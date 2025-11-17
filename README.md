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

> ⚠️ **Important:** All functions are **NOT thread-safe**. Ensure no other thread is using these memory regions simultaneously.  
> The caller must ensure that the addresses are valid.

## Usage

```cpp
writeMemory<uint32_t>(0xDEADBEEF, 3000); // Writes 3000 (wrapped to uint32_t) to the given address
```
```cpp
readMemory<float>(0xBAADF00D); // Reads the value at the given address and returns a float
```
```cpp
makeNOP(0xFEEDFACE, 5); // Writes 5 NOPs at the given address
```
```cpp
makeJMP(0xCAFEBABE, MyDetour); // Creates a jump at the given address to 'MyDetour' (function)
```
```cpp
makeCALL(0xBAADC0DE, MyHook); // Creates a call at the given address to 'MyHook' (function)
```
```cpp
makeRET(0xDEAD10CC, 4); // Writes 'ret 4' at the given addres
```
```cpp
makeINT3(0x00C0FFEE, 4); // Writes 4 'INT 3' at the given addres
```
```cpp
fillNOPs(0xCAFED00D, 0xDEADBABE); // Fills the memory region between two addresses with NOP instructions
```
## Credits
- **Kevin4e** - Author of the library.
