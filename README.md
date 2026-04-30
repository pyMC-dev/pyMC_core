# pyMC_Core

[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://pymc-dev.github.io/pyMC_core/)
[![PyPI](https://img.shields.io/pypi/v/pymc-core)](https://pypi.org/project/pymc-core/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**pyMC_Core** is a Python reimplementation of [MeshCore](https://github.com/meshcore-dev/meshcore) — a lightweight, portable C++ library for multi-hop packet routing using LoRa radios. Designed for **Raspberry Pi** and similar hardware, pyMC_Core communicates with LoRa modules over **SPI**.

> pyMC_Core is under active development. It's compatible with the original MeshCore protocol, but not yet as optimized or elegant as its C++ counterpart.

## Documentation

**Complete documentation is available at **[https://rightup.github.io/pyMC_core/](https://pymc-dev.github.io/pyMC_core/)**

### Quick Links
- [Node Usage Guide](https://pymc-dev.github.io/pyMC_core/node/) - Guide for using MeshNode
- [Examples](https://pymc-dev.github.io/pyMC_core/examples/) - Working code examples
- [API Reference](https://pymc-dev.github.io/pyMC_core/api/) - Detailed API documentation

## Quick Start

### Installation

> **Important**: On modern Python installations (Ubuntu 22.04+, Debian 12+), you may encounter `externally-managed-environment` errors when installing packages system-wide. Create a virtual environment first:
>
> ```bash
> # Create virtual environment
> python3 -m venv pymc_env
>
> # Activate virtual environment
> # On Linux/Mac:
> source pymc_env/bin/activate
> # On Windows:
> pymc_env\Scripts\activate
> ```

```bash
# Install from PyPI
pip install pymc-core

# For hardware support (SX1262 radios)
pip install pymc-core[hardware]

# Install all dependencies
pip install pymc-core[all]
```

### Basic Usage

```python
import asyncio
from pymc_core import MeshNode, LocalIdentity
from pymc_core.hardware.sx1262_wrapper import SX1262Radio

async def main():
    # Create radio (Waveshare HAT example)
    radio = SX1262Radio(
        bus_id=0, cs_pin=21, reset_pin=18,
        busy_pin=20, irq_pin=16, txen_pin=6,
        frequency=869525000, tx_power=22
    )
    radio.begin()

    # Create mesh node
    identity = LocalIdentity()
    node = MeshNode(radio=radio, local_identity=identity)
    await node.start()

    print("Mesh node started!")

asyncio.run(main())
```

For examples, see the [documentation](https://pymc-dev.github.io/pyMC_core/examples/).

## Hardware Support

### Supported Radios
- **Waveshare SX1262 LoRaWAN/GNSS HAT** - Popular Raspberry Pi LoRa module
- **HackerGadgets uConsole** - All-in-one extension board with LoRa support
- **FrequencyLabs meshadv-mini** - Raspberry Pi hat with E22-900M22S LoRa module

### Requirements
- Raspberry Pi (or compatible SBC)
- SX1262 LoRa module
- SPI interface enabled
- Python 3.8+

## What is MeshCore?

MeshCore enables **long-range, decentralized communication** using **multi-hop packet routing**. Devices (nodes) forward packets through neighboring nodes to reach distant ones — no central infrastructure required.

It occupies a middle ground between:

| Project | Focus |
|---------|-------|
| [Meshtastic](https://meshtastic.org/) | Casual LoRa messaging |
| [Reticulum](https://reticulum.network/) | Full encrypted networking stack |

### Use Cases
- Off-grid and emergency communication
- Tactical or field mesh deployments
- IoT mesh networks
- Remote monitoring systems

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │    │   MeshNode      │    │   Hardware      │
│                 │    │                 │    │                 │
│ • Text Messages │◄──►│ • Packet Routing│◄──►│ • SX1262 Radio  │
│ • Advertisements│    │ • Identity Mgmt │    │ • SPI Interface │
│ • Telemetry     │    │ • Event Service │    │ • GPIO Control  │
│ • Group Channels│    │ • Repeater Mgmt │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Security

- **Ed25519/X25519 cryptographic identities**
- **End-to-end encryption** for messages
- **CRC validation** for data integrity
- **Secure key exchange** protocols

## Project Structure

```
pyMC_Core/
├── src/pymc_core/          # Main package
│   ├── hardware/           # Radio hardware interfaces
│   ├── node/               # MeshNode implementation
│   ├── protocol/           # Packet protocols
│   └── events/             # Event handling
├── examples/               # Working examples
│   ├── common.py           # Shared utilities
│   ├── send_flood_advert.py
│   ├── send_direct_advert.py
│   └── ...
├── docs/                   # MkDocs documentation
│   ├── docs/               # Documentation source files
│   ├── mkdocs.yml          # MkDocs configuration
│   ├── requirements.txt    # Documentation dependencies
│   └── serve-docs.sh       # Local development script
├── .github/workflows/      # GitHub Actions
│   └── deploy-docs.yml     # Documentation deployment pipeline
└── tests/                  # Unit tests
```

## Contributing

Contributions are welcome! Please see our [contributing guide](https://pymc-dev.github.io/pyMC_core/contributing/) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/rightup/pyMC_Core.git
cd pyMC_Core

# Install development dependencies
pip install -e .[dev]


```



## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Original [MeshCore](https://github.com/meshcore-dev/meshcore) C++ implementation
- Waveshare and HackerGadgets for hardware support

## Support

- [Documentation](https://pymc-dev.github.io/pyMC_core/)
- [Issues](https://github.com/pymc-dev/pyMC_Core/issues)
- [Discussions](https://github.com/pymc-dev/pyMC_Core/discussions)
- [pyMC Discord](https://discord.gg/SMHkUDwf)
- [Meshcore Discord](https://discord.gg/fThwBrRc3Q)

---

*Built with ❤️ for mesh networking enthusiasts*</content>
