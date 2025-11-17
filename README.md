# K4MemPatcher
A lightweight Windows memory patching utility in C++

## Overview
K4MemPatcher is a **header-only, Windows-specific** library that performs in-process patching using the `VirtualProtect` API.

It allows you to:
- Write arbitrary bytes to memory
- Fill regions with NOPs or INT3 instructions
- Create relative JMP and CALL instructions
- Safely modify memory protections with `VirtualProtect`

This library works on both **32-bit and 64-bit** applications.

> ⚠️ The caller must ensure that the addresses are valid.

## Functions

### writeMemory\<T\>()
Function prototype:
```cpp
template<typename T>
inline Result writeMemory(const MemAddr& address, T value); noexcept
```
Parameters:
- `address`: address to write at.
- `value`: value to write at `address`.
```cpp
writeMemory<uint32_t>(0xDEADBEEF, 3000); // Writes 3000 (wrapped to uint32_t) to the given address
```

---

### readMemory\<T>\()
Function prototype
```cpp
template<typename T>
inline T readMemory(const MemAddr& address); noexcept
```
Parameters:
- `address`: address to read bytes from.
```cpp
readMemory<float>(0xBAADF00D); // Reads the value at the given address and returns a float
```

---

### makeNOP()
Function prototype:
```cpp
inline Result makeNOP(const MemAddr& addressStart, size_t count = 1) noexcept
```
Parameters:
- `addressStart`: address to start writing **NOP**s from.
- `count`: number of **NOP**s to write starting from `addressStart`.
```cpp
makeNOP(0xFEEDFACE, 5); // Writes 5 NOPs at the given address
```

---

### makeJMP()
Function prototype:
```cpp
inline Result makeJMP(const MemAddr& addressFrom, const MemAddr& addressTo); noexcept
```
Parameters:
- `addressFrom`: address to write **JMP** at.
- `addressTo`: jump's address destination.
```cpp
makeJMP(0xCAFEBABE, MyDetour); // Creates a jump at the given address to 'MyDetour' (function)
```

---

### makeCALL()
Function prototype:
```cpp
inline Result makeCALL(const MemAddr& addressFrom, const MemAddr& addressTo); noexcept
```
Parameters:
- `addressFrom`: address to write **CALL** at.
- `addressTo`: function to call.
```cpp
makeCALL(0xBAADC0DE, MyHook); // Creates a call at the given address to 'MyHook' (function)
```

---

### makeRET()
Function prototype:
```cpp
inline Result makeRET(const MemAddr& address); noexcept
```
Parameters:
- `address`: address to write **RET** at.
```cpp
makeRET(0xDEAD10CC); // Writes 'ret' at the given addres
```

---

### makeRET() (overload)
Function prototype:
```cpp
inline Result makeRET(const MemAddr& address, uint16_t stackCleanUpBytes); noexcept
```
Parameters:
- `address`: address to write **RET** at.
- `stackCleanUpBytes`: number of bytes to clean up the stack.
```cpp
makeRET(0xDEAD10CC, 4); // Writes 'ret 4' at the given addres
```

---

### makeINT3()
Function prototype:
```cpp
inline Result makeINT3(const MemAddr& address, size_t count = 1); noexcept
```
Parameters:
- `address`: address to start writing **INT 3**s from.
- `count`: number of **INT 3**s to write starting from `address`.
```cpp
makeINT3(0x00C0FFEE, 4); // Writes 4 'INT 3' at the given addres
```

---

### fillNOPs()
Function prototype:
```cpp
inline Result fillNOPs(const MemAddr& addressStart, const MemAddr& addressEnd, bool inclusive = true); noexcept
```
Parameters:
- `addressStart`: address to start writing **NOP**s from.
- `addressEnd`: last address to write **NOP**s to.
- `inclusive`: whether **NOP** should be written at `addressEnd` or not.
```cpp
fillNOPs(0xCAFED00D, 0xDEADBABE); // Fills the memory region between two addresses with NOP instructions
```

---

### getStablePointer()
Function prototype:
```cpp
inline uintptr_t getStablePointer(HMODULE moduleBase, const std::vector<uintptr_t>& offsets, bool checkIfInvalid = false); noexcept
```
Parameters:
- `moduleBase`: module of the process from which the stable pointer is obtained.
- `offsets`: vector containing the the stable pointer's offsets.
- `checkIfInvalid`: whether to check if a pointer is invalid before reading it or not.
```cpp
getStablePointer(GetModuleHandleA(nullptr), offsets, false); // Gets the stable pointer given the process' module and offsets without checking pointer's validity
```

---

### backupBytes() (overload)
Function prototype:
```cpp
inline std::vector<uint8_t> backupBytes(const MemAddr& addressStart, const MemAddr& addressEnd, bool inclusive = true); noexcept
```
Parameters:
- `addressStart`: address to start saving bytes from.
- `addressEnd`: last address to save bytes to.
- `inclusive`: whether to include the byte at `addressEnd`.
```cpp
backupBytes(0xF4CEB00C, 0xBAC3FEED, true) // Saves the bytes between 0xF4CEB00C and 0xBAC3FEED inclusive
```

---

### backupBytes() (overload)
Function prototype:
```cpp
inline std::vector<uint8_t> backupBytes(const MemAddr& addressStart, size_t len = 1); noexcept
```
Parameters:
- `addressStart`: address to start saving bytes from.
- `len`: number of bytes to save starting from `addressStart`.
```cpp
backupBytes(0xF4CEB00C, 5) // Saves 5 bytes starting from 0xF4CEB00C
```

---

### compareBytes()
Function prototype:
```cpp
inline bool compareBytes(const std::vector<uint8_t>& patch1, const std::vector<uint8_t>& patch2, size_t len); noexcept
```
Parameters:
- `patch1`: first vector.
- `patch2`: second vector.
- `len`: number of bytes to compare between `patch1` and `patch2`.

Example usage:
```cpp
compareBytes(firstPatch, secondPatch, 6) // Compares the first 6 bytes of the two vectors
```

---

## Changelog
### v1.1.0
- General changes:
  * Overall improved structure, readability, and documentation.
  * Implemented **RAII** with `PageWriteGuard` class.
  * `makeJMP` and `makeCALL` can support **any distance**.

- Modified function(s):
  * `makeRET`: the parameter of the stack clean-up is not set to 0 by default anymore. This means that it will always clean up the stack given a number of bytes (as long as it's not zero).

- New feature(s):
  * `makeRET` (**overload**): writes a plain ret with no stack clean-up to an address.
  * `getStablePointer` : returns a stable pointer given the process' module and offsets.
  * `backupBytes` : reads the bytes from an address to another one and stores it in a vector.
  * `backupBytes`  (**overload**): reads a number of bytes starting from an address and stores it in a vector.
  * `compareBytes` : compares the first 'len' bytes of two vectors. Returns true if they are identical.

---

### v1.0.0
- Initial release.

---

## Credits
- **Kevin4e** - Author of the library.
