# K4MemPatcher

A modern Windows memory manipulation toolkit in C++

## Overview

K4MemPatcher is a **header-only**, **Windows-specific** library that performs in-process patching using the `VirtualProtect` API.

It allows you to:
- Write arbitrary bytes or values to memory
- Fill regions with NOPs, INT3, or other instructions
- Create JMP, CALL, RET, PUSH, POP, and register operations
- Backup and compare bytes
- Scan for patterns with wildcards
- Resolve stable pointers and module bounds
- …and additional utilities

This library works on both **32-bit and 64-bit** applications, includes thread-safe operations with instruction cache flushing and memory validation.

---

## Enums

### Result

Defines the outcome of operations.

```cpp
enum class Result : Int8 {
    Success,                    // Operation succeeded
    ProtectionChangeFailed,     // VirtualProtect failed
    InvalidRange,               // Invalid address range
    TooFarDistance,             // Jump/call distance too far
    InvalidJump,                // Invalid jump condition
    InvalidLoop,                // Invalid loop condition
    InvalidRegister,            // Invalid register
    InvalidOperand,             // Invalid operand (e.g. for PUSH/RET)
    UnsafeMemory                // Memory is unsafe for reading/writing
};
```

---

### JmpCondition

Defines jump conditions for `makeJMP`.

```cpp
enum class JmpCondition : Int8 {
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
enum class Register : Int8 {
    AX, CX, DX, BX, SP, BP, SI, DI,          // 16-bit
    EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,  // 32-bit
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,  // 64-bit
    R8, R9, R10, R11, R12, R13, R14, R15     // Extended 64-bit
};
```

---

### Branch

Defines branches for operations like `resolveBranch`, `findBranchTo`, etc.

```cpp
enum class Branch : Int8 {
    Any,
    Jump,
    Call,
    Loop,
};
```

---

### LoopCondition

Defines loop conditions for `makeLOOP`.

```cpp
enum class LoopCondition {
    CX,       // LOOP
    Equal,    // LOOPE
    NotEqual, // LOOPNE
};
```

---

## Classes and Structs

---

### Address

Type-safe wrapper around a raw memory address. It supports construction from raw addresses, pointers, function pointers, and nullptr, as well as address comparison and arithmetic.

```cpp
class Address {
public:
    constexpr Address() noexcept = default;
    constexpr Address(RawAddr address) noexcept;
    Address(void* ptr) noexcept;
    Address(const void* ptr) noexcept;

    template <typename Func>
    Address(Func* funcPtr) noexcept;

    constexpr Address(std::nullptr_t) noexcept;

    template <typename T>
    T as() const noexcept;

    RawAddr get() const noexcept;

    // Comparison operators
    // Arithmetic operators
    // Assignment operators

    explicit constexpr operator bool() const noexcept;
};
```

---

### StablePtr

Resolves pointer chains.

```cpp
class StablePtr {
public:
    StablePtr(Address baseAddress, const std::vector<Distance>& offsets, bool alwaysResolve = true);

    StablePtr(ModuleName moduleName,
              const std::vector<Distance>& offsets,
              bool alwaysResolve = true);

    StablePtr(const std::vector<Distance>& offsets,
              bool alwaysResolve = true);

    Address Resolve() noexcept;

    explicit operator bool() const noexcept;
};
```

```cpp
StablePtr item1Ptr(0x400000, { 0x37FFFF, 0x20, 0x4C });
uintptr_t ptrToItem1 = item1Ptr.Resolve();

StablePtr item2Ptr(GetModuleHandleA(nullptr), { 0x21DDDD, 0x14, 0xC0 });
uintptr_t ptrToItem2 = item2Ptr.Resolve();
```

---

### Range

Defines an **end-exclusive** memory range (`[start, end)`).

```cpp
struct Range {
    Address start{};
    Address end{};

    constexpr Range() noexcept = default;
    constexpr Range(Address start, Address end) noexcept;

    explicit constexpr operator bool() const noexcept;

    constexpr Size size() const noexcept;

    constexpr bool operator==(const Range& other) const noexcept;
};
```

---

### BranchInfo

Wrapper made of address target and branch's type

```cpp
struct BranchInfo {
    Address target{};
    Branch type{ Branch::Any };

    constexpr BranchInfo() noexcept = default;
    constexpr BranchInfo(Address target) noexcept;
    constexpr BranchInfo(Address target, Branch type) noexcept;
};
```

---

## Functions

### Core Patching Functions | `K4MP_ENABLE_CORE`

---

### writeMemory\<T\>()

Function declaration:
```cpp
template <typename T>
inline Result writeMemory(Address address, T value, bool validateMemory, bool flushICache) noexcept;
```

Parameters:
- `address`: Address to write to.
- `value`: Value to write (must be a scalar type).
- `validateMemory`: Whether memory has to be validated before writing (`true` by default).
- `flushICache`: Whether the instruction cache has to be flushed (`true` by default).

Possible exit codes:
- `UnsafeMemory`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
writeMemory<uint32_t>(0xDEADBEEF, 3000, false, false); // Writes 3000 (no memory validation nor I-cache flushing)
writeMemory<uint8_t>(0xE004D3D3, 0x9C, false, true); // Writes 0x9C (PUSHFQ) with I-cache flushing (no memory validation)

if (writeMemory<uint32_t>(0xB40DI000, 1500, true, false) != Result::Success) { // Writes 1500 with memory validation (no I-cache flushing)
	/* ... */
}

if (writeMemory<float>(0xC4D0AB12, 10.0, true, true) != Result::Success) { // Writes 1500 with memory validation and I-cache flushing
	/* ... */
}
```

---

### readMemory\<T\>()

Function declaration:
```cpp
template <typename T>
inline T readMemory(Address address, bool validateMemory) noexcept;
```

Parameters:
- `address`: Address to read from.
- `validateMemory`: Whether memory has to be validated before reading.

Example usage:
```cpp
float val1 = readMemory<float>(0xBAADF00D, false); // Reads a float from the address (no memory validation)
float val2 = readMemory<float>(0xC4C4EDA1, true); // Reads a float from the address with memory validation
```

---

### Common Instruction Functions | `K4MP_ENABLE_BASIC_ASM`

---

### makeNOP()

Function declaration:
```cpp
inline Result makeNOP(Address start, InstructionCount count, bool validateMemory) noexcept;
```

Parameters:
- `start`: Address to start writing NOPs.
- `count`: Number of NOPs to write (`1` by default).
- `validateMemory`: Whether memory has to be validated before writing (`true` by default).

Possible exit codes:
- `UnsafeMemory`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
makeNOP(0xFEEDFACE, 1, false); // Writes 1 NOP (no memory validation)
makeNOP(0xF33DF4C3, 5, false); // Writes 5 NOPs (no memory validation)

if (makeNOP(0xFE3DFAC3, 3, true) != Result::Success) { // Writes 3 NOPs with memory validation
	/* ... */
}
```

---

### makeRangedNOP()

Function declaration:
```cpp
inline Result makeRangedNOP(const Range& range, bool validateMemory) noexcept;
```

Parameters:
- `range`: Range to NOP out.
- `validateMemory`: Whether memory has to be validated before writing (`true` by default).

Possible exit codes:
- `InvalidRange`
- `UnsafeMemory`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
Range range1(0x1000, 0x1005);
makeRangedNOP(range1, false); // NOPs out the range (no memory validation)

Range range2(0x1400, 0x1410);
if (makeRangedNOP(range2, true) != Result::Success) { // NOPs out the range with memory validation
	/* ... */
}
```

---

### makeJMP\<JmpCondition\>()

Function declaration:
```cpp
template <JmpCondition jumpCond>
inline Result makeJMP(Address from, Address to, bool validateMemory) noexcept;
```

Parameters:
- `jumpCond`: Jump condition (compile-time, `JmpCondition::Unconditional` by default).
- `from`: Address to write JMP.
- `to`: Destination address.
- `validateMemory`: Whether memory has to be validated before writing (`true` by default).

Possible exit codes:
- `UnsafeMemory`
- `InvalidJump`
- `TooFarDistance`
- `Success`

Example usage:
```cpp
makeJMP<JmpCondition::Unconditional>(0xCAFEBABE, MyDetour1, false);  // Unconditional JMP to MyDetour1 (no memory validation)
makeJMP<JmpCondition::Greater>(0xFEEDF4DE, MyDetour2, false);        // Conditional JG to MyDetour2 (no memory validation)

if (makeJMP<JmpCondition::NotEqual>(0xEDD1EBA3, MyDetour3, true) != Result::Success) // Conditional JNE to MyDetour3 with memory validation
	/* ... */
}     
```

---

### makeCALL()

Function declaration:
```cpp
inline Result makeCALL(Address from, Address to, bool validateMemory) noexcept;
```

Parameters:
- `from`: Address to write CALL.
- `to`: Function to call.
- `validateMemory`: Whether memory has to be validated before writing (`true` by default).

Possible exit codes:
- `UnsafeMemory`
- `TooFarDistance`
- `Success`

Example usage:
```cpp
makeCALL(0xBAADC0DE, MyHook1, false); // CALL to MyHook1() (no memory validation)

if (makeCALL(0xAED0B1CE, MyHook2, true)) { // CALL to MyHook2() with memory validation
    /* ... */
}
```

---

### Occasional Instruction Functions | `K4MP_ENABLE_ADVANCED_ASM`

---

### makeRET()

Function declaration:
```cpp
inline Result makeRET(Address start, InstructionCount count, bool validateMemory) noexcept;
```

Parameters:
- `start`: Address to write RET.
- `count`: Number of RETs to write (`1` by default).
- `validateMemory`: Whether memory has to be validated before writing (`true` by default).

Possible exit codes:
- `UnsafeMemory`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
makeRET(0xDEAD10CC, 1, false); // Writes 1 RET (no memory validation)
makeRET(0x0DE4D444, 4, false); // Writes 4 RETs (no memory validation)

if (makeRET(0xEDD1EB01, 3, true) != Result::Success) { // Writes 3 RETs with memory validation
    /* ... */
}
```

---

### makeRETimm()

Function declaration:
```cpp
inline Result makeRETimm(Address start, StackAdjustment cleanup, InstructionCount count, bool validateMemory) noexcept;
```

Parameters:
- `start`: Address to write RET.
- `cleanup`: Bytes to clean from stack.
- `count`: Number of RETs to write (`1` by default).
- `validateMemory`: Whether memory has to be validated before writing (`true` by default).

Possible exit codes:
- `UnsafeMemory`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
makeRETimm(0xDEAD10CC, 4, 1, false); // Writes 1 RET 4 (no memory validation)
makeRETimm(0xE4DAA522, 2, 5, false); // Writes 5 RET 2 (no memory validation)

if (makeRETimm(0xD33DB0D1, 1, 3, true) != Result::Success) { // Writes 3 RET 1 with memory validation
    /* ... */
}
```

---

### makeINT()

Function declaration:
```cpp
inline Result makeINT(Address start, Interrupt interrupt, InstructionCount count, bool validateMemory) noexcept;
```

Parameters:
- `start`: Address to write INT.
- `interrupt`: Interrupt number (e.g. 3 for INT3).
- `count`: Number of INTs to write(`1` by default).
- `validateMemory`: Whether memory has to be validated before writing (`true` by default)

Possible exit codes:
- `UnsafeMemory`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
makeINT(0x00C0FFEE, 3, 1, false);  // Writes 1 INT3 (no memory validation)
makeINT(0xEEFF0C00, 10, 6, false); // Writes 6 INT 10 (no memory validation)

if (makeINT(0x0E0ECF0F, 5, 3, true) != Result::Success) { // Writes 3 INT 5 with memory validation
    /* ... */
}
```

---

### makePUSH\<T\>()

Function declaration:
```cpp
template <typename T>
inline Result makePUSH(Address start, T imm, InstructionCount count, bool validateMemory) noexcept;
```

Parameters:
- `start`: Address to write PUSH.
- `imm`: Immediate value (integral type).
- `count`: Number of PUSHes to write (`1` by default).
- `validateMemory`: Whether memory has to be validated before writing (`true` by default).

Possible exit codes:
- `InvalidOperand`
- `UnsafeMemory`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
makePUSH(0x12345678, 42, 1, false); // Writes 1 PUSH 42 (no memory validation)
makePUSH(0x87654321, 61, 4, false); // Writes 4 PUSH 61 (no memory validation)

if (makePUSH(0x18273645, 5, 3, true) != Result::Success) { // Writes 3 PUSH 5 with memory validation
    /* ... */
}
```

---

### makePUSH\<Register\>()

Function declaration:
```cpp
template <Register reg>
inline Result makePUSH(Address start, InstructionCount count, bool validateMemory) noexcept;
```

Parameters:
- `reg`: Register to push (compile-time).
- `start`: Address to write PUSH.
- `count`: Number of PUSHes to write (`1` by default).
- `validateMemory`: Whether memory has to be validated before writing (`true` by default).

Possible exit codes:
- `UnsafeMemory`
- `InvalidRegister`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
makePUSH<Register::RAX>(0x12345678, 1, false); // Writes 1 PUSH RAX (no memory validation)
makePUSH<Register::ECX>(0x87654321, 3, false); // Writes 3 PUSH ECX (no memory validation)

if (makePUSH<Register::BX>(0x18273645, 2, true) != Result::Success) { // Writes 2 PUSH BX with memory validation
	/* ... */
}
```

---

### makePOP\<Register\>()

Function declaration:
```cpp
template <Register reg>
inline Result makePOP(Address start, InstructionCount count, bool validateMemory) noexcept;
```

Parameters:
- `reg`: Register to pop into (compile-time).
- `start`: Address to write POP.
- `count`: Number of POPs to write (`1` by default).
- `validateMemory`: Whether memory has to be validated before writing (`true` by default).

Possible exit codes:
- `UnsafeMemory`
- `InvalidRegister`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
makePOP<Register::RBX>(0x12345678, 1, false); // Writes 1 POP RBX (no memory validation)
makePOP<Register::EAX>(0x1444910D, 4, false); // Writes 4 POP EAX (no memory validation)

if (makePOP<Register::EAX>(0xD38A1BB0, 3, true) != Result::Success) { // Writes 3 POP EAX with memory validation
	/* ... */
}
```

---

### makeINC\<Register\>()

Function declaration:
```cpp
template <Register reg>
inline Result makeINC(Address address, InstructionCount count, bool validateMemory) noexcept;
```

Parameters:
- `reg`: Register to increment (compile-time).
- `address`: Address to write INC.
- `count`: Number of INCs to write (`1` by default).
- `validateMemory`: Whether memory has to be validate before writing (`true` by default).

Possible exit codes:
- `UnsafeMemory`
- `InvalidRegister`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
makeINC<Register::AX>(0xD3D3D4D4, 3, false); // Writes 3 INC AX (no memory validation)
makeINC<Register::DX>(0x04B01111, 2, false); // Writes 2 INC DX (no memory validation)

if (makeINC<Register::EBX>(0x444A444A, 4, true) != Result::Success) { // Writes 4 INC EBX with memory validation
	/* ... */
}
```

---

### makeDEC\<Register\>()

Function declaration:
```cpp
template <Register reg>
inline Result makeDEC(Address address, InstructionCount count, bool validateMemory) noexcept;
```

Parameters:
- `reg`: Register to decrement (compile-time).
- `address`: Address to write DEC.
- `count`: Number of DECs to write (`1` by default).
- `validateMemory`: Whether memory has to be validate before writing (`true` by default).

Possible exit codes:
- `UnsafeMemory`
- `InvalidRegister`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
makeDEC<Register::CX>(0x8DD1E47B, 1, false); // Writes 1 DEC CX (no memory validation)
makeDEC<Register::EDX>(0x9A38BCE1, 3, false); // Writes 3 DEC EDX (no memory validation)

if (makeDEC<Register::EAX>(0x8CD10A5B, 2, true) != Result::Success) { // Writes 2 DEC EAX with memory validation
	/* ... */
}
```

---

### makeNEG\<Register\>()

Function declaration:
```cpp
template <Register reg>
inline Result makeNEG(Address address, InstructionCount count, bool validateMemory) noexcept;
```

Parameters:
- `reg`: Register to invert the sign (compile-time).
- `address`: Address to write NEG.
- `count`: Number of NEGs to write (`1` by default).
- `validateMemory`: Whether memory has to be validate before writing (`true` by default).

Possible exit codes:
- `UnsafeMemory`
- `InvalidRegister`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
makeNEG<Register::DX>(0x9A4DE38C, 1, false); // Writes 1 NEG DX (no memory validation)
makeNEG<Register::SI>(0x7D3811D0, 2, false); // Writes 2 NEG SI (no memory validation)

if (makeINC<Register::RBX>(0x2A49CD1E, 3, true) != Result::Success) { // Writes 3 NEG RBX with memory validation
	/* ... */
}
```

---

### makeNOT\<Register\>()

Function declaration:
```cpp
template <Register reg>
inline Result makeNOT(Address address, InstructionCount count, bool validateMemory) noexcept;
```

Parameters:
- `reg`: Register to flip bits (compile-time).
- `address`: Address to write NOT.
- `count`: Number of NOTs of write (`1` by default).
- `validateMemory`: Whether memory has to be validate before writing (`true` by default).

Possible exit codes:
- `UnsafeMemory`
- `InvalidRegister`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
makeNOT<Register::ECX>(0xAD7B1C8E); // Writes 1 NOT ECX (no memory validation)
makeNOT<Register::DX>(0x04B01111, 4, false); // Writes 4 NOT DX (no memory validation)

if (makeNOT<Register::SI>(0x444A444A, 2, true) != Result::Success) { // Writes 2 NOT SI with memory validation
	/* ... */
}
```

---

### makeLOOP\<LoopCondition\>()

Function declaration:
```cpp
template <LoopCondition loopCond>
inline Result makeLOOP(Address from, Address to, bool validateMemory) noexcept;
```

Parameters:
- `loopCond`: Loop condition (compile-time, `LoopCondition::CX` by default).
- `from`: Address to write LOOP.
- `to`: Loop destination.
- `validateMemory`: Whether memory has to be validated before writing (`true` by default).

Possible exit codes:
- `InvalidLoop`
- `UnsafeMemory`
- `TooFarDistance`
- `ProtectionChangeFailed`
- `Success`

Example usage:
```cpp
makeLOOP<LoopCondition::CX>(0x1000, 0x1010, false); // LOOP to 0x1010 

if (makeLOOP<LoopCondition::NotEqaual>(0x2000, 0x3000, true) != Result::Success) { // LOOPNE to 0x3000 with memory validation
	/* ... */
}
```

---

### Utility Functions | `K4MP_ENABLE_BYTES_UTILS`

---

### readBytes()

Function declaration:
```cpp
inline ByteBuffer readBytes(Address start, ByteCount len, bool validateMemory) noexcept;
```

Parameters:
- `start`: Address to read from.
- `len`: Number of bytes to read (`1` by default).
- `validateMemory`: Whether memory has to be validated before reading (`true` by default).

Example usage:
```cpp
ByteBuffer bytes1 = readBytes(0x1000, 5, false); // Reads 5 bytes (no memory validation)

ByteBuffer bytes2 = readBytes(0x1500, 10, true); // Reads 10 bytes with memory validation

if (bytes2.empty()) {
	/* ... */
}
```

---

### readRangedBytes()

Function declaration:
```cpp
inline ByteBuffer readRangedBytes(const Range& range, bool validateMemory) noexcept;
```

Parameters:
- `range`: Range to read.
- `validateMemory`: Whether memory has to be validated before reading (`true` by default).

Example usage:
```cpp
Range r1(0x1000, 0x1005);
ByteBuffer bytes1 = readRangedBytes(r1, false); // Reads range (no memory validation)

Range r2(0x1400, 0x1410);
ByteBuffer bytes2 = readRangedBytes(r2, true); // Reads range with memory validation

if (bytes2.empty()) {
	/* ... */
}
```

---

### compareBytes() (With Length)

Function declaration:
```cpp
inline bool compareBytes(const ByteBuffer& bytes1, const ByteBuffer& bytes2, ByteCount len) noexcept;
```

Parameters:
- `bytes1`, `bytes2`: Vectors to compare.
- `len`: Number of bytes to compare.

Example usage:
```cpp
ByteBuffer bytes1 = readBytes(0x00600000, 30);
ByteBuffer bytes2 = readBytes(0x00700500, 45);

bool equal = compareBytes(bytes1, bytes2, 15); // Compares first 6 bytes
```

---

### compareBytes() (Full Vectors)

Function declaration:
```cpp
inline bool compareBytes(const ByteBuffer& bytes1, const ByteBuffer& bytes2) noexcept;
```

Parameters:
- `bytes1`, `bytes2`: Vectors to compare (must be same size).

Example usage:
```cpp
ByteBuffer bytes1 = readBytes(0x00550000, 15);
ByteBuffer bytes2 = readBytes(0x00780500, 15);

bool equal = compareBytes(bytes1, bytes2); // Compares all bytes
```

---

### swapBytes()

Function declaration:
```cpp
inline bool swapBytes(Address first, Address second, ByteCount len, bool validateMemory) noexcept;
```

Parameters:
- `first`, `second`: Addresses to swap.
- `len`: Length to swap.
- `validateMemory`: Whether memory has to be validated before reading/writing (`true` by default).

Example usage:
```cpp
swapBytes(0x00500000, 0x00950000, 10, false); // Swaps 10 bytes (no memory validation)

if (swapBytes(0x00380000, 0x00850000, 15, true)) { // Swaps 15 bytes with memory validation
	/* ... */
}
```

---

### swapRangedBytes()

Function declaration:
```cpp
inline bool swapRangedBytes(const Range& firstRange, const Range& secondRange, bool validateMemory) noexcept;
```

Parameters:
- `firstRange`, `secondRange`: Ranges to swap (must be equal length).
- `validateMemory`: Whether memory has to be validated before reading/writing (`true` by default).

Example usage:
```cpp
Range range1(0x00100000, 0x00100050);
Range range2(0x00100200, 0x00100250);

swapRangedBytes(range1, range2, false); // Swaps ranges (no memory validation)

Range range3(0x00200000
```

---

### Scanning functions | `K4MP_ENABLE_SCAN`

---

### findPattern()

Function declaration:
```cpp
inline Address findPattern(const std::string& pattern, ModuleName moduleName);
```

Parameters:
- `pattern`: Pattern string (e.g., "8B 0D ?? ?? ?? ?? 29 48 10").
- `moduleName`: Name of the module in which to search for the pattern (`nullptr` by default).

Example usage:
```cpp
Address patternAddress = findPattern("41 42 ?? 44"); // Searches for pattern

if (!patternAddress) { // No pattern was found
	/* ... */
}
```

---

### findPatterns()

Function declaration:
```cpp
inline Addresses findPatterns(const std::string& pattern, ModuleName moduleName, Size firstNPatterns);
```

Parameters:
- `pattern`: Pattern string (e.g., "8B 0D ?? ?? ?? ?? 29 48 10").
- `moduleName`: Name of the module in which to search for the pattern (`nullptr` by default).
- `firstNPatterns`: Maximum number of matching pattern addresses to return (`Limit::max<Size>` by default).

Example usage:
```cpp
Addresses patternAddresses = findPatterns("A0 4C 1E ?? ?? 8F");

if (patternAddresses.empty()) { // No pattern was found
	/* ... */
}
```

---

### resolveBranch()

Function declaration:
```cpp
inline BranchInfo resolveBranch(Address address) noexcept;
```

Parameters:
- `address`: Address containing the branch to solve.

Example usage:
```cpp
BranchInfo branch = resolveBranch(0x8AAD1E0C);

if (!branch.target || branch.type == Branch::Any) { // Branch couldn't be resolved
	/* ... */
}
```

---

### resolveBranches()

Function declaration:
```cpp
inline std::vector<BranchInfo> resolveBranches(const Addresses& addresses);
```

Parameters:
- `addresses`: Addresses containing the branches to solve.

Example usage:
```cpp
Addresses addresses = { 0x3ACD71B0, 0xAB3D91CE, 0x021DBA14 };
std::vector<BranchInfo> branches = resolveBranches(addresses);

if (std::any_of(branches.begin(), branches.end(), [](const BranchInfo& branch)
	{ return !branch.target || branch.type == Branch::Any; })) // At least one of the branches couldn't be resolved
{
	/* ... */
}
```

---

### findBranchTo()

Function declaration:
```cpp
inline Address findBranchTo(const BranchInfo& branchInfo, ModuleName moduleName);
```

Parameters:
- `branchInfo`: Branch to search for.
- `moduleName`: Name of the module in which to search for the branch (`nullptr` by default).

Example usage:
```cpp
BranchInfo branch(0x8EEDA19C, Branch::Jmp);

// We're looking for an address where any type of jump to 0x8EEDA19C is performed
Address branchAddress = findBranchTo(branch);

if (!branchAddress) { // No branch was found
	/* ... */
}
```

---

### findBranchesTo()

Function declaration:
```cpp
inline Addresses findBranchesTo(const BranchInfo& branchInfo, ModuleName moduleName, Size firstNBranches);
```

Parameters:
- `branchInfo`: Branch to search for.
- `moduleName`: Name of the module in which to search for the branch (`nullptr` by default).
- `firstNBranches`: Maximum number of matching branch addresses to return (`Limit::max<Size>` by default).

Example usage:
```cpp
BranchInfo branch(0x3DAB169D, Branch::Call);

// We're looking for all the addresses where a relative CALL to 0x8EEDA19C is performed
Addresses branchAddresses = findBranchesTo(branch);

if (branchAddresses.empty()) { // Branch was not found
	/* ... */
}
```

---

### findRelativeCall()

Function declaration:
```cpp
inline Address findRelativeCall(Address target, ModuleName moduleName) noexcept;
```

Parameters:
- `target`: The called address to find.
- `moduleName`: Name of the module in which to search for the CALL (`nullptr` by default).

Example usage:
```cpp
Address target = 0xD34DF00D;

Address callToTarget = findRelativeCall(target);

if (!callToTarget) { // No call was found
	/* ... */
}
```

---

### findRelativeCalls()

Function declaration:
```cpp
inline Addresses findRelativeCalls(Address target, ModuleName moduleName, Size firstNCalls) {
```

Parameters:
- `target`: The called address to find.
- `moduleName`: Name of the module in which to search for the CALL (`nullptr` by default).
- `firstNCalls`: Maximum number of matching CALL addresses to return (`Limit::max<Size>` by default).

Example usage:
```cpp
Address target = 0xF00DD34D;

Addresses callsToTarget = findRelativeCalls(target);

if (callsToTarget.empty()) { // No call was found
	/* ... */
}
```

---

### findRetFunction()

Function declaration:
```cpp
inline Address findRetFunction(ModuleName moduleName) noexcept;
```

Parameters:
- `moduleName`: Name of the module in which to search for the RET (`nullptr` by default).

Example usage:
```cpp
Address retFunction = findRetFunction();

if (!retFunction) { // No ret function was found
	/* ... */
}
```

---

### findRetFunctions()

Function declaration:
```cpp
inline Addresses findRetFunctions(ModuleName moduleName, bool sort, Size firstNFunctions) noexcept;
```

Parameters:
- `moduleName`: Name of the module in which to search for the RET (`nullptr` by default).
- `sort`: Whether the addresses found have to be sorted after the scan (`false` by default).
- `firstNFunction`: Maximum number of matching RET addresses to return (`Limit::max<Size>` by default).

---

Example usage:
```cpp
Addresses retFuncs1 = findRetFunctions(nullptr, false); // Looks for all the ret functions (no sorting)

if (retFuncs1.empty()) { // No ret function was found
	/* ... */
}

Addresses retFuncs2 = findRetFunctions(nullptr, true); Looks for all the ret functions with sorting

if (retFuncs2.empty()) { // No ret function was found
	/* ... */
}

Addresses retFuncs3 = findRetFunctions(nullptr, false, 15); Looks for the first 15 ret functions (no sorting)

if (retFuncs3.empty()) { // No ret function was found
	/* ... */
}
```

---

## License

- See [LICENSE](LICENSE)

## Credits

- **Kevin4e** - Author of the library.