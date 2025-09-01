# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Testing
- `make test` - Run fast unit tests only (`pytest -m unit`)
- `make virt` - Run smoke tests against virtual device (`pytest -m smokevirt`)
- `make smoke1` - Run smoke1 test on single USB device (requires factory reset)
- `make slow` - Show slowest unit tests
- `make cov` - Generate coverage report and open in browser
- `make examples` - Run CLI examples tests (`pytest -mexamples`)

### Code Quality
- `make lint` - Lint codebase with pylint (`pylint meshtastic examples`)
- `poetry run mypy meshtastic` - Type checking with mypy

### Build & Installation
- `poetry install` - Install dependencies
- `make install` - Local pip install
- `make docs` - Generate documentation with pdoc3

### Protocol Buffers
- `make protobufs` - Regenerate protobuf files from submodules

## Architecture Overview

### Core Interface Classes
The library provides three primary interfaces for connecting to Meshtastic devices:
- `SerialInterface` - USB/serial connection via `/dev/ttyUSB0` etc.
- `TCPInterface` - TCP connection to device or gateway
- `BLEInterface` - Bluetooth Low Energy connection

All interfaces inherit from `MeshInterface` base class in `meshtastic/mesh_interface.py` which provides:
- Node database (`nodes`, `nodesByNum`) - tracks mesh network participants
- PubSub event system for asynchronous message handling
- Configuration management (`localConfig`, `moduleConfig`, `channels`)

### Key Components
- `meshtastic/node.py` - Represents individual mesh nodes and their properties
- `meshtastic/protobuf/` - Generated protobuf classes from upstream firmware definitions
- `meshtastic/util.py` - Common utilities and helper functions
- `meshtastic/__main__.py` - CLI entry point and command handling

### Message Flow
1. Messages received via interfaces trigger PubSub events
2. Protocol-specific handlers in `protocols` dict decode payloads
3. Node database automatically updates with position/user info
4. Applications subscribe to relevant message topics

### Special Modules
- `meshtastic/tunnel.py` - TAP interface for IP tunneling
- `meshtastic/powermon/` - Power monitoring utilities for device testing
- `meshtastic/analysis/` - Data analysis tools for mesh performance
- `meshtastic/slog/` - Structured logging utilities

## Development Environment

Uses Poetry for dependency management with optional feature groups:
- `[cli]` - Command-line interface extras (QR codes, colors, etc.)
- `[tunnel]` - TAP interface support
- `[analysis]` - Data analysis and visualization tools
- `[powermon]` - Power monitoring hardware support

Testing uses pytest with custom markers for different test categories (unit, integration, smoke tests for various device configurations).

## Important Notes

- Protocol buffer files are auto-generated - modify upstream definitions, not local copies
- Node database is read-only from application perspective
- PubSub model allows multiple subscribers to same message types
- Interfaces automatically handle device discovery when no specific path provided
- CLI supports all firmware features through unified command structure