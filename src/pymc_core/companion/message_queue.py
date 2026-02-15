"""Fixed-size offline message queue for companion radio."""

from collections import deque
from typing import Optional

from .constants import DEFAULT_OFFLINE_QUEUE_SIZE
from .models import QueuedMessage


class MessageQueue:
    """Fixed-size offline message queue (FIFO).

    Stores incoming messages that arrive when no consumer is actively
    reading. Matches the firmware's offline_queue behaviour with a
    configurable maximum size. When full, the oldest messages are
    silently dropped (deque maxlen behaviour).
    """

    def __init__(self, max_size: int = DEFAULT_OFFLINE_QUEUE_SIZE):
        self._queue: deque[QueuedMessage] = deque(maxlen=max_size)
        self._max_size = max_size

    def push(self, msg: QueuedMessage) -> bool:
        """Add a message to the queue. Returns True on success.

        If the queue is at capacity the oldest message is silently dropped.
        """
        self._queue.append(msg)
        return True

    def pop(self) -> Optional[QueuedMessage]:
        """Remove and return the oldest message, or None if empty."""
        if self._queue:
            return self._queue.popleft()
        return None

    def pop_last(self) -> Optional[QueuedMessage]:
        """Remove and return the most recently pushed message, or None if empty."""
        if self._queue:
            return self._queue.pop()
        return None

    def peek(self) -> Optional[QueuedMessage]:
        """Return the oldest message without removing it, or None if empty."""
        if self._queue:
            return self._queue[0]
        return None

    def is_empty(self) -> bool:
        """Check if the queue has no messages."""
        return len(self._queue) == 0

    def is_full(self) -> bool:
        """Check if the queue is at capacity."""
        return len(self._queue) >= self._max_size

    @property
    def count(self) -> int:
        """Return the number of messages in the queue."""
        return len(self._queue)

    def clear(self):
        """Remove all messages from the queue."""
        self._queue.clear()
