# K4MemPatcher
A lightweight Windows memory patching utility in C++

## Overview
K4MemPatcher is a **header-only, Windows-specific** library that performs in-process patching using the `VirtualProtect` API.

It allows you to:
- Write arbitrary bytes or values to memory
- Fill regions with NOPs, INT3, or other instructions
- Create JMP, CALL, RET, PUSH, POP, and register operations
- Backup and compare bytes
- Scan for patterns with wildcards
- Resolve stable pointers and module bounds
- …and additional utilities

This library works on both **32-bit and 64-bit** applications and includes thread-safe operations with instruction cache flushing.

> ⚠️ The caller must ensure that the addresses are valid.

---

## Enums

### Result
Defines the outcome of operations.
```cpp
enum class Result {
    Success,                    // Operation succeeded
    ProtectionChangeFailed,     // VirtualProtect failed
    InvalidRange,               // Invalid address range
    TooFarDistance,             // Jump/call distance too far
    InvalidJump,                // Invalid jump condition
    InvalidRegister,            // Invalid register
    InvalidOperand              // Invalid operand (e.g., for PUSH/RET)
};
```

---

### JmpCondition
Defines jump conditions for `makeJMP`.
```cpp
enum class JmpCondition {
    Unconditional,   // JMP
    Above,           // JA
    AboveOrEqual,    // JAE
    Below,           // JB
    BelowOrEqual,    // JBE
    Carry,           // JC
    Equal,           // JE
    EqualCXZero,     // JECXZ
    Greater,         // JG
    GreaterOrEqual,  // JGE
    Less,            // JL
    LessOrEqual,     // JLE
    NotCarry,        // JNC
    NotEqual,        // JNE
    NotOverflow,     // JNO
    NotParity,       // JNP
    NotSign,         // JNS
    Overflow,        // JO
    Parity,          // JP
    Sign             // JS
};
```

---

### Register
Defines registers for operations like `makePUSH`, `makePOP`, etc.
```cpp
enum class Register {
    AX, CX, DX, BX, SP, BP, SI, DI,  // 16-bit
    EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,  // 32-bit
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,  // 64-bit
    R8, R9, R10, R11, R12, R13, R14, R15  // Extended 64-bit
};
```

---

## Functions

### Core Patching Functions

---

### writeMemory\<T\>()
Function prototype:
```cpp
template<typename T>
inline Result writeMemory(const MemAddr& address, T value) noexcept;
```

Parameters:
- `address`: Address to write to.
- `value`: Value to write (must be a scalar type).

Exit codes:
- `ProtectionChangeFailed`
- `Success`

```cpp
writeMemory<uint32_t>(0xDEADBEEF, 3000); // Writes 3000 to the address
```

---

### readMemory\<T\>()
Function prototype:
```cpp
template<typename T>
inline T readMemory(const MemAddr& address) noexcept;
```

Parameters:
- `address`: Address to read from.

```cpp
float val = readMemory<float>(0xBAADF00D); // Reads a float from the address
```

---

### makeNOP()
Function prototype:
```cpp
inline Result makeNOP(const MemAddr& addressStart, size_t count = 1) noexcept;
```

Parameters:
- `addressStart`: Address to start writing NOPs.
- `count`: Number of NOPs to write.

Exit codes:
- `ProtectionChangeFailed`

```cpp
makeNOP(0xFEEDFACE, 5); // Writes 5 NOPs
```

---

### makeRangedNOP()
Function prototype:
```cpp
inline Result makeRangedNOP(const Range& rangeAddresses) noexcept;
```

Parameters:
- `rangeAddresses`: Range struct defining start and end.

Exit codes:
- `InvalidRange`
- `ProtectionChangeFailed`
- `Success`

```cpp
Range range(0x1000, 0x1005);
makeRangedNOP(range); // NOPs the range
```

---

### makeJMP()
Function prototype:
```cpp
inline Result makeJMP(const MemAddr& addressFrom, const MemAddr& addressTo, JmpCondition jumpCond = JmpCondition::Unconditional, bool nopOutRemainingBytes = false, size_t originalInstructionSize = 0) noexcept;
```

Parameters:
- `addressFrom`: Address to write JMP.
- `addressTo`: Destination address.
- `jumpCond`: Jump condition (default: Unconditional).
- `nopOutRemainingBytes`: Whether to NOP remaining bytes.
- `originalInstructionSize`: Size of original instruction for NOP padding.

Exit codes:
- `InvalidJump`
- `TooFarDistance`
- `Success`

```cpp
makeJMP(0xCAFEBABE, MyDetour1);                                   // Unconditional JMP to MyDetour1
makeJMP(0xFEEDF4DE, MyDetour2, JmpCondition::Greater);            // Conditional   JG  to MyDetour2
makeJMP(0xEDD1EBA3, MyDetour3, JmpCondition::NotEqual, true, 7);  // Conditional   JNE to MyDetour3 with NOP padding
```

---

### makeCALL()
Function prototype:
```cpp
inline Result makeCALL(const MemAddr& addressFrom, const MemAddr& addressTo, bool nopOutRemainingBytes = false, size_t originalInstructionSize = 0) noexcept;
```

Parameters:
- `addressFrom`: Address to write CALL.
- `addressTo`: Function to call.
- `nopOutRemainingBytes`: Whether to NOP remaining bytes.
- `originalInstructionSize`: Size of original instruction for NOP padding.

Exit codes:
- `TooFarDistance`
- `Success`

```cpp
makeCALL(0xBAADC0DE, MyHook1); // CALL to MyHook1
makeCALL(0xAED0B1CE, MyHook2, true 6); // CALL to MyHook2 with NOP padding
```

---

### makeRET() (No Operand)
Function prototype:
```cpp
inline Result makeRET(const MemAddr& address, size_t count = 1) noexcept;
```

Parameters:
- `address`: Address to write RET.
- `count`: Number of RETs.

Exit codes:
- `ProtectionChangeFailed`
- `Success`

```cpp
makeRET(0xDEAD10CC); // Writes RET
```

---

### makeRET() (With Stack Cleanup)
Function prototype:
```cpp
inline Result makeRET(const MemAddr& address, uint16_t stackCleanUpBytes, size_t count = 1) noexcept;
```

Parameters:
- `address`: Address to write RET.
- `stackCleanUpBytes`: Bytes to clean from stack.
- `count`: Number of RETs.

Exit codes:
- `ProtectionChangeFailed`
- `Success`

```cpp
makeRET(0xDEAD10CC, 4); // Writes RET 4
```

---

### makeINT()
Function prototype:
```cpp
inline Result makeINT(const MemAddr& address, uint8_t interrupt, size_t count = 1) noexcept;
```

Parameters:
- `address`: Address to write INT.
- `interrupt`: Interrupt number (e.g., 3 for INT3).
- `count`: Number of INTs.

Exit codes:
- `ProtectionChangeFailed`
- `Success`

```cpp
makeINT(0x00C0FFEE, 3, 4); // Writes 4 INT3s
```

---

### Advanced Instruction Functions

---

### makePUSH() (Immediate)
Function prototype:
```cpp
template<typename T>
inline Result makePUSH(const MemAddr& address, T imm, size_t count = 1) noexcept;
```

Parameters:
- `address`: Address to write PUSH.
- `imm`: Immediate value (integral type).
- `count`: Number of PUSHes.

Exit codes:
- `InvalidOperand`
- `ProtectionChangeFailed`
- `Success`

```cpp
makePUSH(0x12345678, 42); // PUSH 42
```

---

### makePUSH() (Register)
Function prototype:
```cpp
inline Result makePUSH(const MemAddr& address, Register reg, size_t count = 1) noexcept;
```

Parameters:
- `address`: Address to write PUSH.
- `reg`: Register to push.
- `count`: Number of PUSHes.

Exit codes:
- `InvalidRegister`
- `ProtectionChangeFailed`
- `Success`

```cpp
makePUSH(0x12345678, Register::RAX); // PUSH RAX
```

---

### makePOP()
Function prototype:
```cpp
inline Result makePOP(const MemAddr& address, Register reg, size_t count = 1) noexcept;
```

Parameters:
- `address`: Address to write POP.
- `reg`: Register to pop into.
- `count`: Number of POPs.

Exit codes:
- `InvalidRegister`
- `ProtectionChangeFailed`
- `Success`

```cpp
makePOP(0x12345678, Register::RBX); // POP RBX
```

---

### makeINC(), makeDEC(), makeNEG(), makeNOT()
Function prototypes:
```cpp
inline Result makeINC(const MemAddr& address, Register reg, size_t count = 1) noexcept;
inline Result makeDEC(const MemAddr& address, Register reg, size_t count = 1) noexcept;
inline Result makeNEG(const MemAddr& address, Register reg, size_t count = 1) noexcept;
inline Result makeNOT(const MemAddr& address, Register reg, size_t count = 1) noexcept;
```

Parameters:
- `address`: Address to write instruction.
- `reg`: Target register.
- `count`: Number of instructions.

Exit codes:
- `InvalidRegister`
- `ProtectionChangeFailed`
- `Success`

```cpp
makeINC(0x12345678, Register::RCX); // INC RCX
```

---

### makeLOOP()
Function prototype:
```cpp
inline Result makeLOOP(const MemAddr& addressFrom, const MemAddr& addressTo) noexcept;
```

Parameters:
- `addressFrom`: Address to write LOOP.
- `addressTo`: Loop destination.

Exit codes:
- `TooFarDistance`
- `ProtectionChangeFailed`
- `Success`

```cpp
makeLOOP(0x1000, 0x1010); // LOOP to 0x1010
```

---

### Utility Functions

---

### readBytes()
Function prototype:
```cpp
inline std::vector<uint8_t> readBytes(const MemAddr& addressStart, size_t len = 1) noexcept;
```

Parameters:
- `addressStart`: Address to read from.
- `len`: Number of bytes.

```cpp
auto bytes = readBytes(0x1000, 5); // Reads 5 bytes
```

---

### readRangedBytes()
Function prototype:
```cpp
inline std::vector<uint8_t> readRangedBytes(const Range& bytesRange) noexcept;
```

Parameters:
- `bytesRange`: Range to read.

```cpp
Range range(0x1000, 0x1005);
auto bytes = readRangedBytes(range); // Reads range
```

---

### compareBytes() (With Length)
Function prototype:
```cpp
inline bool compareBytes(const std::vector<uint8_t>& bytes1, const std::vector<uint8_t>& bytes2, size_t len) noexcept;
```

Parameters:
- `bytes1`, `bytes2`: Vectors to compare.
- `len`: Number of bytes to compare.

```cpp
bool equal = compareBytes(vec1, vec2, 6); // Compares first 6 bytes
```

---

### compareBytes() (Full Vectors)
Function prototype:
```cpp
inline bool compareBytes(const std::vector<uint8_t>& bytes1, const std::vector<uint8_t>& bytes2) noexcept;
```

Parameters:
- `bytes1`, `bytes2`: Vectors to compare (must be same size).

```cpp
bool equal = compareBytes(vec1, vec2); // Compares all bytes
```

---

### swapBytes()
Function prototype:
```cpp
inline bool swapBytes(const MemAddr& address1, const MemAddr& address2, size_t len) noexcept;
```

Parameters:
- `address1`, `address2`: Addresses to swap.
- `len`: Length to swap.

```cpp
swapBytes(0x1000, 0x2000, 4); // Swaps 4 bytes
```

---

### swapRangedBytes()
Function prototype:
```cpp
inline bool swapRangedBytes(const Range& range1, const Range& range2) noexcept;
```

Parameters:
- `range1`, `range2`: Ranges to swap (must be equal length).

```cpp
Range range1(0x1000, 0x1050);
Range range2(0x1200, 0x1250);
swapRangedBytes(range1, range2); // Swaps ranges
```

---

### findPattern()
Function prototype:
```cpp
inline uintptr_t findPattern(const std::string& pattern, uintptr_t startAddress = 0, uintptr_t endAddress = std::numeric_limits<uintptr_t>::max()) noexcept;
```

Parameters:
- `pattern`: Pattern string (e.g., "8B 0D ?? ?? ?? ?? 29 48 10").
- `startAddress`: Start of scan (default: module base).
- `endAddress`: End of scan (default: module end).

```cpp
uintptr_t addr = findPattern("41 42 ?? 44"); // Scans for pattern
```

---

### Classes and Structs

---

### MemAddr
Wrapper for memory addresses.
```cpp
struct MemAddr {
    MemAddr(uintptr_t address) noexcept;
    MemAddr(void* ptr) noexcept;
    uintptr_t get() const noexcept;
};
```

### Range
Defines a memory range.
```cpp
struct Range {
    Range(const MemAddr& startingPoint, const MemAddr& endingPoint) noexcept;
    uintptr_t startingPoint, endingPoint;
    size_t length;
};
```

### StablePtr
Resolves pointer chains.
```cpp
class StablePtr {
    StablePtr(uintptr_t baseAddress, const std::vector<uintptr_t>& offsets, bool alwaysResolve = true) noexcept;
    StablePtr(HMODULE moduleBase, const std::vector<uintptr_t>& offsets, bool alwaysResolve = true) noexcept;
    uintptr_t Resolve() noexcept;
    bool hasPointerChainFailed() const noexcept;
};
```
```cpp
StablePtr item1Ptr(0x400000, { 0x37FFFF, 0x20, 0x4C });
uintptr_t ptrToItem1 = item1Ptr.Resolve();

StablePtr item2Ptr(GetModuleHandleA(nullptr), { 0x21DDDD, 0x14, 0xC0 });
uintptr_t ptrToItem2 = item2Ptr.Resolve();
```
---

## Changelog

### v1.2.0
- General changes:
  - Added pattern scanning with `findPattern` (supports wildcards like `??`).
  - Introduced module bounds detection with `Helpers::getModuleBounds`.
  - Expanded instruction support (PUSH/POP/INC/DEC/NEG/NOT/LOOP with registers).
  - Improved error handling and bounds checking.
  - Added more opcodes, enums (e.g., `JmpCondition`, `Register`), and utilities (e.g., `swapBytes`, `readRangedBytes`).
  - Thread-safety and RAII improvements.

- Modified function(s):
  - `makeJMP`/`makeCALL`: Now support conditional jumps and automatic distance handling.
  - `makeRET`: Added overload for no-operand RET.
  - `compareBytes`: Added overload for full vector comparison.
  - `getStablePointer` has been reworked to the `StablePtr` struct.

- New feature(s):
  - `findPattern`: Scans for byte patterns with wildcards.
  - `makePUSH`/`makePOP` (register versions).
  - `makeINC`/`makeDEC`/`makeNEG`/`makeNOT`/`makeLOOP`.
  - `swapBytes`/`swapRangedBytes`.
  - `readRangedBytes`.
  - `StablePtr` template for dynamic pointer resolution.
  - `Range` struct for range operations.

### v1.1.0
- General changes:
  - Overall improved structure, readability, and documentation.
  - Implemented **RAII** with `PageWriteGuard` class.
  - `makeJMP` and `makeCALL` can support **any distance**.

- Modified function(s):
  - `makeRET`: The parameter for stack clean-up is not set to 0 by default anymore. This means that it will always clean up the stack given a number of bytes (as long as it's not zero).

- New feature(s):
  - `makeRET` (**overload**): Writes a plain RET with no stack clean-up to an address.
  - `getStablePointer`: Returns a stable pointer given the process' module and offsets.
  - `backupBytes`: Reads bytes from an address to another and stores them in a vector.
  - `backupBytes` (**overload**): Reads a number of bytes starting from an address and stores them in a vector.
  - `compareBytes`: Compares the first 'len' bytes of two vectors. Returns true if they are identical.

### v1.0.0
- Initial release.

## Credits
- **Kevin4e** - Author of the library.
