"""
CH341 USB-to-SPI/GPIO driver with asynchronous USB transfers
Using ctypes to call libusb directly for async operation
"""

import ctypes
import logging
import threading
import time
from enum import IntEnum
from typing import Optional

logger = logging.getLogger(__name__)


# libusb constants
class LibUSBError(IntEnum):
    SUCCESS = 0
    ERROR_IO = -1
    ERROR_INVALID_PARAM = -2
    ERROR_ACCESS = -3
    ERROR_NO_DEVICE = -4
    ERROR_NOT_FOUND = -5
    ERROR_BUSY = -6
    ERROR_TIMEOUT = -7
    ERROR_OVERFLOW = -8
    ERROR_PIPE = -9
    ERROR_INTERRUPTED = -10
    ERROR_NO_MEM = -11
    ERROR_NOT_SUPPORTED = -12
    ERROR_OTHER = -99


class LibUSBTransferType(IntEnum):
    CONTROL = 0
    ISOCHRONOUS = 1
    BULK = 2
    INTERRUPT = 3


class LibUSBTransferStatus(IntEnum):
    COMPLETED = 0
    ERROR = 1
    TIMED_OUT = 2
    CANCELLED = 3
    STALL = 4
    NO_DEVICE = 5
    OVERFLOW = 6


# Load libusb
try:
    libusb = ctypes.CDLL("libusb-1.0.so.0")
except OSError:
    try:
        libusb = ctypes.CDLL("libusb-1.0.so")
    except OSError:
        raise ImportError("libusb-1.0 not found. Install: sudo apt-get install libusb-1.0-0")


# libusb structures
class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class libusb_transfer(ctypes.Structure):
    pass


# Callback type
TRANSFER_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.POINTER(libusb_transfer))


libusb_transfer._fields_ = [
    ("dev_handle", ctypes.c_void_p),
    ("flags", ctypes.c_uint8),
    ("endpoint", ctypes.c_uint8),
    ("type", ctypes.c_uint8),
    ("timeout", ctypes.c_uint),
    ("status", ctypes.c_int),
    ("length", ctypes.c_int),
    ("actual_length", ctypes.c_int),
    ("callback", TRANSFER_CALLBACK),
    ("user_data", ctypes.c_void_p),
    ("buffer", ctypes.POINTER(ctypes.c_uint8)),
    ("num_iso_packets", ctypes.c_int),
    ("iso_packet_desc", ctypes.c_void_p),
]


# libusb function signatures
libusb.libusb_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
libusb.libusb_init.restype = ctypes.c_int

libusb.libusb_exit.argtypes = [ctypes.c_void_p]
libusb.libusb_exit.restype = None

libusb.libusb_open_device_with_vid_pid.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint16,
    ctypes.c_uint16,
]
libusb.libusb_open_device_with_vid_pid.restype = ctypes.c_void_p

libusb.libusb_close.argtypes = [ctypes.c_void_p]
libusb.libusb_close.restype = None

libusb.libusb_claim_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
libusb.libusb_claim_interface.restype = ctypes.c_int

libusb.libusb_release_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
libusb.libusb_release_interface.restype = ctypes.c_int

libusb.libusb_alloc_transfer.argtypes = [ctypes.c_int]
libusb.libusb_alloc_transfer.restype = ctypes.POINTER(libusb_transfer)

libusb.libusb_free_transfer.argtypes = [ctypes.POINTER(libusb_transfer)]
libusb.libusb_free_transfer.restype = None

libusb.libusb_submit_transfer.argtypes = [ctypes.POINTER(libusb_transfer)]
libusb.libusb_submit_transfer.restype = ctypes.c_int

libusb.libusb_cancel_transfer.argtypes = [ctypes.POINTER(libusb_transfer)]
libusb.libusb_cancel_transfer.restype = ctypes.c_int

libusb.libusb_handle_events_timeout.argtypes = [ctypes.c_void_p, ctypes.POINTER(timeval)]
libusb.libusb_handle_events_timeout.restype = ctypes.c_int

libusb.libusb_kernel_driver_active.argtypes = [ctypes.c_void_p, ctypes.c_int]
libusb.libusb_kernel_driver_active.restype = ctypes.c_int

libusb.libusb_detach_kernel_driver.argtypes = [ctypes.c_void_p, ctypes.c_int]
libusb.libusb_detach_kernel_driver.restype = ctypes.c_int

# Bulk transfer (synchronous). Useful for simple GPIO reads.
libusb.libusb_bulk_transfer.argtypes = [
    ctypes.c_void_p,
    ctypes.c_ubyte,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int),
    ctypes.c_uint,
]
libusb.libusb_bulk_transfer.restype = ctypes.c_int


# Helper function to fill bulk transfer (replaces libusb_fill_bulk_transfer macro)
def fill_bulk_transfer(
    transfer, dev_handle, endpoint, buffer, length, callback, user_data, timeout
):
    """Fill bulk transfer structure (Python implementation of libusb_fill_bulk_transfer)"""
    transfer.contents.dev_handle = dev_handle
    transfer.contents.endpoint = endpoint
    transfer.contents.type = LibUSBTransferType.BULK
    transfer.contents.timeout = timeout
    transfer.contents.buffer = buffer
    transfer.contents.length = length
    transfer.contents.callback = callback
    transfer.contents.user_data = user_data
    transfer.contents.num_iso_packets = 0


class CH341Error(Exception):
    """CH341 device error"""

    pass


class CH341SPIError(CH341Error):
    """CH341 SPI operation error"""

    pass


class TransferState(IntEnum):
    """Transfer state sentinel values.

    IMPORTANT: these must not collide with valid libusb actual_length values
    (which are >= 0). The reference C implementations use negative sentinels.
    """

    IDLE = 0
    ACTIVE = -2
    ERROR = -1


class CH341Async:
    """CH341 USB device with async transfers (singleton pattern)"""

    # Singleton instance
    _instance = None
    _instance_lock = False

    # Device IDs
    DEFAULT_VID = 0x1A86
    DEFAULT_PID = 0x5512

    # Endpoints
    EP_OUT = 0x02
    EP_IN = 0x82

    # Commands
    CMD_SPI_STREAM = 0xA8
    CMD_UIO_STREAM = 0xAB
    CMD_UIO_READ = 0xA0
    CMD_UIO_STM_OUT = 0x80
    CMD_UIO_STM_DIR = 0x40
    CMD_UIO_STM_END = 0x20

    # Packet constraints
    CH341_PACKET_LENGTH = 0x20  # 32 bytes
    MAX_PAYLOAD = 0x1F  # 31 bytes

    # Number of queued IN transfers (like C library)
    USB_IN_TRANSFERS = 16

    # Timeout
    USB_TIMEOUT = 5000  # ms

    def __new__(cls, vid: int = DEFAULT_VID, pid: int = DEFAULT_PID):
        """Singleton pattern - return existing instance if available"""
        if cls._instance is None:
            cls._instance = super(CH341Async, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, vid: int = DEFAULT_VID, pid: int = DEFAULT_PID):
        # Skip if already initialized (singleton)
        if self._initialized:
            return

        self.vid = vid
        self.pid = pid
        self.ctx = None
        self.dev_handle = None
        self.gpio_state = 0x3F  # All HIGH
        self.gpio_dir = 0x3F  # All outputs

        # Transfer state tracking
        self.transfer_out = None
        self.transfer_gpio_out = None
        self.transfer_ins = []
        self.transfer_buffers = []
        self._spi_out_busy = False  # Track if SPI OUT transfer is in use

        # Thread safety for shared USB transfer handles
        self._transfer_lock = threading.Lock()

        # Global operation lock to prevent concurrent USB access
        # This is critical for CH341 which cannot handle simultaneous SPI + GPIO operations
        self._operation_lock = threading.RLock()  # Reentrant for nested calls

        self._open_device()
        self._initialized = True

    @classmethod
    def get_instance(cls, vid: int = DEFAULT_VID, pid: int = DEFAULT_PID):
        """Get or create the singleton instance"""
        if cls._instance is None:
            cls._instance = cls(vid, pid)
        return cls._instance

    @classmethod
    def reset_instance(cls):
        """Reset the singleton instance (useful for testing)"""
        if cls._instance is not None:
            logger.info("Resetting CH341 singleton instance")
            try:
                cls._instance.close()
            except Exception as e:
                logger.warning(f"Error during reset_instance close: {e}")
            cls._instance = None
            # Small delay to let USB subsystem release the device
            time.sleep(0.1)

    def _open_device(self):
        """Initialize libusb and open device"""
        # Initialize libusb context
        self.ctx = ctypes.c_void_p()
        ret = libusb.libusb_init(ctypes.byref(self.ctx))
        if ret < 0:
            raise CH341Error(f"Failed to initialize libusb: {ret}")

        # Open device
        self.dev_handle = libusb.libusb_open_device_with_vid_pid(self.ctx, self.vid, self.pid)
        if not self.dev_handle:
            libusb.libusb_exit(self.ctx)
            raise CH341Error(f"Device not found: VID={self.vid:04x}, PID={self.pid:04x}")

        # Detach kernel driver if active
        if libusb.libusb_kernel_driver_active(self.dev_handle, 0) == 1:
            ret = libusb.libusb_detach_kernel_driver(self.dev_handle, 0)
            if ret < 0:
                logger.warning(f"Could not detach kernel driver: {ret}")

        # Claim interface
        ret = libusb.libusb_claim_interface(self.dev_handle, 0)
        if ret < 0:
            if ret == LibUSBError.ERROR_BUSY:
                logger.error("Device is busy (claimed by another process or driver)")
                logger.error("Try: 1) pkill -9 python3, or 2) unplug/replug device")
            libusb.libusb_close(self.dev_handle)
            libusb.libusb_exit(self.ctx)
            raise CH341Error(f"Failed to claim interface: {ret}")

        # Allocate OUT transfer for SPI
        self.transfer_out = libusb.libusb_alloc_transfer(0)
        if not self.transfer_out:
            raise CH341Error("Failed to allocate SPI OUT transfer")

        # Allocate separate OUT transfer for GPIO (to avoid conflicts)
        self.transfer_gpio_out = libusb.libusb_alloc_transfer(0)
        if not self.transfer_gpio_out:
            raise CH341Error("Failed to allocate GPIO OUT transfer")

        # Allocate IN transfers
        for _ in range(self.USB_IN_TRANSFERS):
            transfer = libusb.libusb_alloc_transfer(0)
            if not transfer:
                raise CH341Error("Failed to allocate IN transfer")
            self.transfer_ins.append(transfer)

        # Initialize GPIO/pinmux (required before SPI transfers)
        # The CH341 SPI engine expects the SPI core pins to be configured:
        #   - SCK  = GPIO 3 (output)
        #   - MOSI = GPIO 5 (output)
        #   - MISO = GPIO 7 (input)
        # And we use GPIO 0 as CS0.
        #
        # If SCK/MOSI are left as inputs, SPI transfers will often return 0xFF bytes
        # (no clock/data driven).
        self.gpio_dir = (1 << 0) | (1 << 3) | (1 << 5)
        self.gpio_state = self.gpio_dir  # deassert CS + idle-high on SCK/MOSI

        # IMPORTANT: Avoid libusb_bulk_transfer here. Some CH341 firmwares/drivers
        # are picky and we already rely on the async submit+event loop path for
        # everything else.
        try:
            self._uio_stream(
                out=self.gpio_state, direction=self.gpio_dir, timeout_ms=self.USB_TIMEOUT
            )
            logger.debug("CH341 GPIO/pinmux initialized")
        except Exception as e:
            logger.warning(f"Failed to send UIO init command: {e}")

        # Drain any stale bytes from EP_IN.
        # If a previous process crashed mid-transfer, the CH341 can have pending bytes,
        # which then causes LIBUSB_TRANSFER_OVERFLOW on the next small IN transfer.
        try:
            for _ in range(32):
                transferred = ctypes.c_int(0)
                buf = (ctypes.c_ubyte * 64)()
                ret = libusb.libusb_bulk_transfer(
                    self.dev_handle,
                    ctypes.c_ubyte(self.EP_IN),
                    ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)),
                    64,
                    ctypes.byref(transferred),
                    ctypes.c_uint(10),  # 10ms
                )
                if ret == LibUSBError.ERROR_TIMEOUT:
                    break
                if ret < 0:
                    break
                if transferred.value <= 0:
                    break
        except Exception:
            pass

        logger.info(f"CH341 opened: VID={self.vid:04x}, PID={self.pid:04x}")

    def close(self):
        """Close device and cleanup"""
        logger.debug("Closing CH341 device...")

        # Cancel any pending transfers first
        if self.transfer_out:
            try:
                libusb.libusb_cancel_transfer(self.transfer_out)
            except Exception:
                pass
            libusb.libusb_free_transfer(self.transfer_out)
            self.transfer_out = None

        for transfer in self.transfer_ins:
            if transfer:
                try:
                    libusb.libusb_cancel_transfer(transfer)
                except Exception:
                    pass
                libusb.libusb_free_transfer(transfer)
        self.transfer_ins.clear()

        if self.dev_handle:
            # Release interface gracefully
            try:
                libusb.libusb_release_interface(self.dev_handle, 0)
            except Exception as e:
                logger.debug(f"Error releasing interface: {e}")

            libusb.libusb_close(self.dev_handle)
            self.dev_handle = None

        if self.ctx:
            libusb.libusb_exit(self.ctx)
            self.ctx = None

        self._initialized = False
        logger.debug("CH341 device closed")

    @staticmethod
    def reverse_byte(b: int) -> int:
        """Reverse bit order in a byte"""
        result = 0
        for i in range(8):
            result = (result << 1) | (b & 1)
            b >>= 1
        return result

    def _bulk_write_all(self, payload: bytes, timeout_ms: Optional[int] = None) -> None:
        """Write the entire payload to EP_OUT, looping until complete."""
        if not self.dev_handle:
            raise CH341Error("Device not open")

        if timeout_ms is None:
            timeout_ms = self.USB_TIMEOUT

        if not payload:
            return

        buf = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
        transferred = ctypes.c_int(0)
        offset = 0

        while offset < len(payload):
            transferred.value = 0
            ptr = ctypes.cast(ctypes.byref(buf, offset), ctypes.POINTER(ctypes.c_ubyte))
            ret = libusb.libusb_bulk_transfer(
                self.dev_handle,
                ctypes.c_ubyte(self.EP_OUT),
                ptr,
                len(payload) - offset,
                ctypes.byref(transferred),
                ctypes.c_uint(timeout_ms),
            )
            if ret < 0:
                raise CH341SPIError(f"SPI OUT bulk transfer failed: {ret}")
            if transferred.value <= 0:
                raise CH341SPIError("SPI OUT bulk transfer short write (0 bytes)")
            offset += transferred.value

    def _bulk_read_exact(self, nbytes: int, timeout_ms: Optional[int] = None) -> bytes:
        """Read exactly nbytes from EP_IN, looping until complete."""
        if not self.dev_handle:
            raise CH341Error("Device not open")

        if timeout_ms is None:
            timeout_ms = self.USB_TIMEOUT

        if nbytes <= 0:
            return b""

        rbuf = (ctypes.c_ubyte * nbytes)()
        transferred = ctypes.c_int(0)
        offset = 0

        while offset < nbytes:
            transferred.value = 0
            ptr = ctypes.cast(ctypes.byref(rbuf, offset), ctypes.POINTER(ctypes.c_ubyte))
            ret = libusb.libusb_bulk_transfer(
                self.dev_handle,
                ctypes.c_ubyte(self.EP_IN),
                ptr,
                nbytes - offset,
                ctypes.byref(transferred),
                ctypes.c_uint(timeout_ms),
            )
            if ret < 0:
                raise CH341SPIError(f"SPI IN bulk transfer failed: {ret}")
            if transferred.value <= 0:
                raise CH341SPIError("SPI IN bulk transfer short read (0 bytes)")
            offset += transferred.value

        return bytes(rbuf)

    def spi_transfer_async(self, data_out: bytes, read_len: int = 0) -> bytes:
        """
        Perform SPI transfer using async libusb transfers

        This matches the C library's usb_transfer() implementation
        """
        import logging

        logger = logging.getLogger(__name__)
        logger.debug(
            f"[SPI] spi_transfer_async called: {len(data_out)} bytes out, {read_len} bytes read"
        )
        with self._operation_lock:
            logger.debug("[SPI] Acquired operation lock")
            with self._transfer_lock:
                logger.debug("[SPI] Acquired transfer lock, calling impl")
                result = self._spi_transfer_async_impl(data_out, read_len)
                logger.debug(f"[SPI] Impl returned {len(result)} bytes")
                return result

    def _spi_transfer_async_impl(self, data_out: bytes, read_len: int = 0) -> bytes:
        """Internal implementation of SPI transfer (called within lock)"""
        import logging

        logger = logging.getLogger(__name__)
        logger.debug(f"[SPI-IMPL] Starting: {len(data_out)} bytes out, {read_len} bytes read")

        try:
            return self._spi_transfer_impl_core(data_out, read_len)
        finally:
            # Always release busy flag, even on error
            self._spi_out_busy = False

    def _spi_transfer_impl_core(self, data_out: bytes, read_len: int = 0) -> bytes:
        """Core SPI transfer implementation.

        NOTE: We intentionally use synchronous bulk transfers here.

        The previous async implementation could produce short/empty reads on some
        CH341 adapters due to buffer offset accounting bugs when actual_length was
        shorter than requested. For SX126x (lots of very small SPI transactions),
        correctness is more important than throughput.
        """
        if not data_out and read_len == 0:
            return b""

        writecnt = len(data_out)
        readcnt = int(read_len)

        write_left = writecnt
        read_left = readcnt
        write_idx = 0

        miso_raw = bytearray()

        # CH341 packets are 32 bytes: 1 command byte + up to 31 payload bytes.
        while write_left > 0 or read_left > 0:
            write_now = min(self.MAX_PAYLOAD, write_left)
            read_now = min(self.MAX_PAYLOAD - write_now, read_left)

            packet = bytearray([self.CMD_SPI_STREAM])

            # Add write data (bit-reversed)
            for i in range(write_now):
                packet.append(self.reverse_byte(data_out[write_idx + i]))

            # Add read padding
            if read_now > 0:
                packet.extend([0xFF] * read_now)

            # OUT then IN (device returns one MISO byte per payload byte)
            self._bulk_write_all(bytes(packet), timeout_ms=self.USB_TIMEOUT)
            miso_raw.extend(
                self._bulk_read_exact(write_now + read_now, timeout_ms=self.USB_TIMEOUT)
            )

            write_idx += write_now
            write_left -= write_now
            read_left -= read_now

        # Convert bit order back
        if readcnt > 0:
            return bytes(self.reverse_byte(b) for b in miso_raw[writecnt : writecnt + readcnt])
        return bytes(self.reverse_byte(b) for b in miso_raw[:writecnt])

    def _submit_gpio_out(self, payload: bytes, timeout_ms: Optional[int] = None) -> int:
        """Submit a GPIO OUT bulk transfer and wait for completion."""
        if not self.transfer_gpio_out or not self.dev_handle:
            raise CH341Error("GPIO OUT transfer not initialized")

        if timeout_ms is None:
            timeout_ms = self.USB_TIMEOUT

        state = ctypes.c_int(TransferState.IDLE)

        @TRANSFER_CALLBACK
        def callback(transfer_ptr):
            if transfer_ptr.contents.status == LibUSBTransferStatus.COMPLETED:
                state.value = transfer_ptr.contents.actual_length
            else:
                state.value = TransferState.ERROR

        cmd_array = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
        fill_bulk_transfer(
            self.transfer_gpio_out,
            self.dev_handle,
            self.EP_OUT,
            cmd_array,
            len(payload),
            callback,
            None,
            timeout_ms,
        )

        state.value = TransferState.ACTIVE
        ret = libusb.libusb_submit_transfer(self.transfer_gpio_out)
        if ret < 0:
            raise CH341Error(f"GPIO write failed: {ret}")

        tv = timeval(0, 100000)  # 100ms
        deadline = time.time() + (timeout_ms / 1000.0) + 1.0
        while state.value == TransferState.ACTIVE:
            libusb.libusb_handle_events_timeout(self.ctx, ctypes.byref(tv))
            if time.time() > deadline:
                try:
                    libusb.libusb_cancel_transfer(self.transfer_gpio_out)
                except Exception:
                    pass
                raise CH341Error("GPIO write timeout")

        if state.value == TransferState.ERROR:
            raise CH341Error("GPIO write transfer failed")

        return int(state.value)

    def _uio_stream(
        self,
        *,
        out: Optional[int] = None,
        direction: Optional[int] = None,
        timeout_ms: Optional[int] = None,
    ) -> None:
        """Send a CH341 UIO_STREAM command.

        We always send the full bitfield(s) when provided (same approach as the
        reference C drivers), not per-pin changes.
        """
        cmd = bytearray([self.CMD_UIO_STREAM])
        if out is not None:
            cmd.append(self.CMD_UIO_STM_OUT | (out & 0xFF))
        if direction is not None:
            cmd.append(self.CMD_UIO_STM_DIR | (direction & 0xFF))
        cmd.append(self.CMD_UIO_STM_END)

        self._submit_gpio_out(bytes(cmd), timeout_ms=timeout_ms)

    def gpio_set(self, pin: int, value: bool):
        """Set GPIO pin."""
        with self._operation_lock:
            with self._transfer_lock:
                return self._gpio_set_impl(pin, value)

    def _gpio_set_impl(self, pin: int, value: bool):
        """Internal GPIO set implementation (called within lock)"""
        if pin < 0 or pin > 5:
            raise ValueError(f"GPIO pin must be 0-5, got {pin}")

        if value:
            self.gpio_state |= 1 << pin
        else:
            self.gpio_state &= ~(1 << pin)

        self._uio_stream(out=self.gpio_state, direction=self.gpio_dir)

    def gpio_set_direction(self, pin: int, is_output: bool):
        """Set GPIO pin direction (input or output)

        Note: Pins 0-5 support both input and output.
              Pins 6-7 are input-only on most CH341 variants.
        """
        with self._operation_lock:  # Prevent concurrent GPIO/SPI operations
            with self._transfer_lock:  # Ensure exclusive access to transfer_out
                return self._gpio_set_direction_impl(pin, is_output)

    def _gpio_set_direction_impl(self, pin: int, is_output: bool):
        """Internal GPIO direction set implementation (called within lock)"""
        if pin < 0 or pin > 7:
            raise ValueError(f"GPIO pin must be 0-7, got {pin}")

        # Pins 6-7 are typically input-only
        if pin > 5 and is_output:
            raise ValueError(f"GPIO pin {pin} only supports input mode (pins 6-7 are input-only)")

        if is_output:
            self.gpio_dir |= 1 << pin  # Set bit to 1 for output
        else:
            self.gpio_dir &= ~(1 << pin)  # Clear bit to 0 for input

        # Send direction update only. Including OUT here can unintentionally toggle
        # other pins when their output state hasn't been set yet.
        self._uio_stream(direction=self.gpio_dir)

    def gpio_get(self, pin: int) -> bool:
        """Read GPIO pin (simplified for async version)"""
        # RLock allows same thread to acquire multiple times (reentrant)
        # Use timeout to prevent blocking from different threads (like GPIO polling)
        acquired = self._operation_lock.acquire(timeout=0.01)  # 10ms timeout
        if not acquired:
            # Lock held by different thread - skip this read
            raise CH341Error("GPIO read IN failed: -6")  # LIBUSB_ERROR_BUSY
        try:
            with self._transfer_lock:
                return self._gpio_get_impl(pin)
        finally:
            self._operation_lock.release()

    def _gpio_get_impl(self, pin: int) -> bool:
        """Internal GPIO get implementation (called within operation lock).

        NOTE: Using synchronous bulk transfers here.

        We found that the async + handle_events loop can stall on some adapters,
        causing multi-second delays between otherwise-fast SPI transactions.
        For GPIO reads, sync bulk is simple and reliable.
        """
        if pin < 0 or pin > 7:
            raise ValueError(f"GPIO pin must be 0-7, got {pin}")

        # CH341 UIO_READ returns a small status blob. Reference implementations
        # typically read 6 bytes and use output[0] as the D0-D7 input bitfield.
        GPIO_READ_BYTES = 6
        GPIO_READ_TIMEOUT_MS = 200  # keep this short; callers often treat failures as "not busy"

        transferred = ctypes.c_int(0)

        # OUT: send UIO_READ command
        cmd = (ctypes.c_ubyte * 1)(self.CMD_UIO_READ)
        ret = libusb.libusb_bulk_transfer(
            self.dev_handle,
            ctypes.c_ubyte(self.EP_OUT),
            ctypes.cast(cmd, ctypes.POINTER(ctypes.c_ubyte)),
            1,
            ctypes.byref(transferred),
            ctypes.c_uint(GPIO_READ_TIMEOUT_MS),
        )
        if ret < 0:
            raise CH341Error(f"GPIO read write failed: {ret}")

        # IN: read back GPIO state blob
        rbuf = (ctypes.c_ubyte * GPIO_READ_BYTES)()
        transferred.value = 0
        ret = libusb.libusb_bulk_transfer(
            self.dev_handle,
            ctypes.c_ubyte(self.EP_IN),
            ctypes.cast(rbuf, ctypes.POINTER(ctypes.c_ubyte)),
            GPIO_READ_BYTES,
            ctypes.byref(transferred),
            ctypes.c_uint(GPIO_READ_TIMEOUT_MS),
        )
        if ret < 0:
            raise CH341Error(f"GPIO read IN failed: {ret}")

        return bool(rbuf[0] & (1 << pin))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
