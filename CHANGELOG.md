## 2026-03-01

### Changed

- Update Boost library to 1.87

### Fixed

- Destination TCP retry loop now accepts both stream start and connection start
  messages
- Capped default retry count to 5
- Socket close timing moved to after pending writes complete
- Bus error from boost socket.shutdown on Darwin arm64
- OpenSSL is now truly dynamic or static based on compile flag

### Added

- SSL host verification warning
- Fixes for Windows build support

## 2019-12-07

### Changed

- CMakeLists.txt to always link libatomic, not only whe cross-compiling

## 2019-12-07

### Added

- Predictive region endpoint for cn-north-1 and cn-northwest-1
- Allow settings-json file to create region endpoint overrides as needed
- Destination mode test and more test functionality

### Changed

- Log statement on socket bind failure to include the port

### Fixed

- Behavior for -b/--bind-address CLI argument in destination mode to use random
  port

### Removed

- Most non-helpful comments

## 2019-11-27

### Fixed

- README.md install commands for ProtocolBuffers
