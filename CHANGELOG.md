# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.2.0] - 2026-02-05

### Added

- Support for draft socket types and options
- OTP 28 added to CI matrix

### Fixed

- Fixed deprecated API usages
- Fixed buffer overrun
- Fixed flaky test
- Improved resource management
- Increased buffer size
- Fixed ZMQ_FD type mismatch on Windows
- Fixed data races
- Avoided accessing NIF env from other threads
- Fixed build on modern macOS

## [4.1.4] - 2024-06-02

### Fixed

- Fixed build on OTP 27

## [4.1.3] - 2022-12-14

### Fixed

- Build on BSD [Dave Cottlehuber](https://github.com/dch)
- Fixed memory leaks
- Unnecessary ZMQ message closes removed
- Deprecated ZMQ API usages migrated to new API

## [4.1.2] - 2022-01-24

### Fixed

- Handling of iolists in send multipart

## [4.1.1] - 2022-01-24

### Fixed

- Specs improved to allow passing iolists

## [4.1.0] - 2020-08-31

### Added

- Send/recive multipart messages in one call [Stefan Kaes](https://github.com/skaes).

## [4.0.0] - 2020-08-26

### Added

- Support for recent libzmq socket flags (up to 4.3.2)
- Support for libzmq context flags (up to 4.3.2)
- Support for zmq CURVE security
- Support for z85 encoding/decoding

### Changed

- Multiple resource leaks fixed plugged
- Uses one thread per socket instead of one thread per context
- Made sure sockets are accessed only from one thread that creatd them
- Uses dirty IO NIF
- Fixes semantics of various libzmq flags with regards to blocking, reliability quaranties, etc.

### Removed

- Active sockets support
