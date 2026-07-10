# Changelog

## [v1.3.0] - 2026-05-02

### Added

- **Modular compile-time feature flags** (`K4MP_ENABLE_*`) for selective inclusion and reduced binary size.
- **`makeJMP()`** now supports **conditions** for both short and relative jumps.
- **Compile-time template functions** for `makeJMP<Condition>`, `makePUSH<Register>`, etc. (zero runtime validation).
- **Pre-write memory safety validation** using `VirtualQuery` (`isWritingSafe`, `isReadingSafe`).
- **Advanced scanning suite**:
  * `findPatterns` (returns all matches, configurable count).
  * `resolveBranch` / `resolveBranches` (reverse-engineers JMP/CALL/LOOP targets).
  * `findBranchTo` / `findBranchesTo` (finds all jumps/calls to target).
  * `findRelativeCall` / `findRelativeCalls` (call-specific scanning).
- **Improved `Range`** with `operator bool()` validation and exclusive-end semantics.
- **Optional instruction cache flushing** (`flushICache` parameter).
- **Optional mutex locking** (`K4MP_NO_MUTEX` for performance-critical code).
- **Enhanced error handling** with `UnsafeMemory` result code.
- **Semantic type aliases** (`Byte`, `Rel8`, `Rel32`, `InstructionCount`, etc.) for stronger typing.

### Changed

- **Complete architectural refactor** into modular headers (`Aliases.hpp`, `Types.hpp`, `Enums.hpp`, internal modules).
- **`makeJMP` / `makeCALL`** now use **compile-time condition selection** and automatic short/relative/absolute fallback.
- **`PageWriteGuard`** enhanced with optional cache flushing and `operator bool()`.
- **Instruction sizes and opcodes** centralized in `Detail::Constants`.
- **Jump opcode maps** (`shortJumpsMap`, `relativeJumpsMap`) now constexpr arrays for O(1) lookup.
- **`findPattern`** signature changed to return `Address` with `ModuleName` support.
- **Memory access functions** now validate safety by default (`validateMemory` parameter).
- **All functions** now use strong types (`Address`, `ByteCount`, etc.) instead of raw `uintptr_t`/`size_t`.
- **Range operations** now exclusive-end (`makeRangedNOP` fills `[start, end)`).
- **Internal helpers** fully templated with `constexpr` where possible.

### Fixed

- **Critical memory safety** - prevents crashes on guard/no-access pages.
- **Register encoding** for 16/32/64-bit registers (REX prefix handling).
- **JECXZ jump** distance validation (no rel32 support).
- **Pattern scanning** edge cases (odd-length, invalid hex, bounds overflow).
- **Relative offset** calculations for 8-bit offset.
- **Conditional jump** opcode mapping (removed unused `NotCarry` duplicate).

### ... Additional changes unlisted

---

## [v1.2.0] - 2026-01-08

### Added

- **Pattern scanning** via `findPattern` (supports wildcard `??`).
- **Module bounds detection** with `Helpers::getModuleBounds`.
- **Extended instruction support**: `PUSH`, `POP`, `INC`, `DEC`, `NEG`, `NOT`, `LOOP` (register-based).
- **Additional opcodes**, **enums** (`JmpCondition`, `Register`) and **utilities** (`swapBytes`, `readRangedBytes`).
- **Thread-safety improvements** and **RAII enhancements**.
- **Register-based** `makePUSH` / `makePOP`.
- **Arithmetic/logic** helpers: `makeINC`, `makeDEC`, `makeNEG`, `makeNOT`, `makeLOOP`.
- **Byte utilities**: `swapBytes`, `swapRangedBytes`, `readRangedBytes`.
- `StablePtr` template for **dynamic pointer resolution**.
- `Range` struct for **range-based operations**.

### Changed

- `makeJMP` / `makeCALL` now support **conditional jumps** and **automatic distance handling**.
- `makeRET` improved behavior for **stack cleanup handling**.
- `getStablePointer` **refactored into `StablePtr` structure**.
- `backupBytes` renamed to **`readBytes`**.
- `compareBytes` extended with **vector comparison overload**.
 **Improved error handling** and **bounds checking across the library**.
- General **performance improvements** and internal cleanup.

### Fixed

- **Improved safety** in memory bounds operations.
- **Better validation** for instruction encoding and decoding.

---

## [v1.1.0] - 2025-11-09

### Added

- `makeRET` overload for **raw RET without stack cleanup**.
- `getStablePointer` for **resolving stable module-based pointers**.
- `backupBytes` for **copying memory into a vector**.
- `backupBytes` overload supporting **length-based** reads.
- `compareBytes` for **byte vector comparison**.
- Implemented **RAII** via `PageWriteGuard`.

### Changed

- Overall code structure **improved** for readability and documentation.
- `makeJMP` and `makeCALL` now support jumps of any distance.
- `makeRET` behavior changed: stack cleanup is now always enforced when specified.

---

## [v1.0.0] - 2025-11-07

### Added

- Initial release.
- Core memory manipulation utilities.
- Basic instruction writing functions (`JMP`, `CALL`, `RET`).
- Primitive byte comparison and memory backup utilities.