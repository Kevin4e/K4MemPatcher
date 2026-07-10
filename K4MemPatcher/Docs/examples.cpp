/*
 *  K4MemPatcher — Usage Examples Source
 *  File: examples.cpp
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

#define K4MP_ENABLE_CORE
#define K4MP_ENABLE_BASIC_ASM
#define K4MP_ENABLE_ADVANCED_ASM
#define K4MP_ENABLE_BYTES_UTILS
#define K4MP_ENABLE_SCAN

#include "../K4MemPatcher.hpp"
#include "../../../K4IniReader/K4IniReader.hpp"
#include "../../../NFSVersionManager/NFSVersionManager.hpp"
#include <iostream>

using namespace K4MemPatcher;

// Game module name
constexpr const char* GAME_EXE = "game.exe";

// Some example addresses (these are placeholders - replace with actual addresses)
namespace GameOffsets {
    constexpr uintptr_t PLAYER_SPEED = 0x00567890;        // Player speed value
    constexpr uintptr_t MONEY_ADDR = 0x0056ABC0;          // Money address
    constexpr uintptr_t NITRO_ADDR = 0x0056DEF0;          // Nitro boost address
    constexpr uintptr_t FUNC_GET_SPEED = 0x00401000;      // Function that gets speed
    constexpr uintptr_t FUNC_SET_SPEED = 0x00402000;      // Function that sets speed
    constexpr uintptr_t LANDING_DETECTED = 0x00403000;    // Jump land detection
    constexpr uintptr_t SPEEDOMETER_DRAW = 0x00404000;    // Speedometer draw function
}


// ============================================================================
// EXAMPLE 1: BASIC MEMORY READ/WRITE
// ============================================================================

void Example_BasicReadWrite()
{
    std::cout << "=== Example 1: Basic Read/Write ===\n";

    // Write a simple value
    float speed = 200.0f;
    Result res = writeMemory(MemAddr(GameOffsets::PLAYER_SPEED), speed);

    if (res == Result::Success) {
        std::cout << "[+] Speed written: " << speed << "\n";
    }
    else {
        std::cout << "[-] Failed to write speed\n";
    }

    // Read it back
    float readSpeed = readMemory<float>(GameOffsets::PLAYER_SPEED);
    std::cout << "[*] Speed read: " << readSpeed << "\n";

    // Write multiple values
    int money = 100000;
    writeMemory(GameOffsets::MONEY_ADDR, money);

    int nitro = 100;
    writeMemory(GameOffsets::NITRO_ADDR, nitro);

    std::cout << "[*] Money: " << readMemory<int>(GameOffsets::MONEY_ADDR) << "\n";
    std::cout << "[*] Nitro: " << readMemory<int>(GameOffsets::NITRO_ADDR) << "\n\n";
}


// ============================================================================
// EXAMPLE 2: MEMADDR OPERATORS AND ARITHMETIC
// ============================================================================

void Example_MemAddrOperators()
{
    std::cout << "=== Example 2: MemAddr Operators ===\n";

    MemAddr baseAddr = GameOffsets::PLAYER_SPEED;

    // Addition/subtraction
    MemAddr speedPlus4 = baseAddr + 4;
    MemAddr speedMinus4 = baseAddr - 4;

    std::cout << "Base:      0x" << std::hex << baseAddr << "\n";
    std::cout << "Base + 4:  0x" << speedPlus4 << "\n";
    std::cout << "Base - 4:  0x" << speedMinus4 << "\n";

    // Increment
    MemAddr addr = baseAddr;
    ++addr;  // Now points to base + 1

    std::cout << "++addr:    0x" << addr << "\n";

    // Compound assignment
    addr += 0x10;  // Now points to base + 0x11
    std::cout << "addr+=0x10: 0x" << addr << "\n";

    // Comparison
    if (baseAddr < speedPlus4) {
        std::cout << "[*] baseAddr < speedPlus4 is TRUE\n";
    }

    std::cout << "\n";
}


// ============================================================================
// EXAMPLE 3: STABLEPTR FOR POINTER CHAINS
// ============================================================================

void Example_StablePtr()
{
    std::cout << "=== Example 3: StablePtr (Pointer Chains) ===\n";

    // Example: Navigate through a structure
    // Let's say: BaseAddress -> +0x10 -> read pointer -> +0x4C -> final address

    // Option 1: Resolve every time (alwaysResolve = true)
    StablePtr dynamicPtr(GAME_EXE, { 0x1000, 0x10, 0x4C }, true);
    MemAddr resolvedAddr = dynamicPtr.Resolve();
    std::cout << "[*] Dynamic resolved: 0x" << std::hex << resolvedAddr << "\n";

    // Option 2: Cache after first resolve (alwaysResolve = false)
    StablePtr cachedPtr(GAME_EXE, { 0x2000, 0x20 }, false);
    MemAddr cachedAddr = cachedPtr.Resolve();
    std::cout << "[*] Cached resolved: 0x" << std::hex << cachedAddr << "\n";

    // Read value through pointer chain
    // If you have: Game.exe + 0x1234 = pointer to player data
    //              player data + 0x50 = pointer to speed
    StablePtr speedPtr(GAME_EXE, { 0x1234, 0x50 });

    // Note: Resolve() returns the final address, then you can read from it
    // This is useful for data structures that change during runtime

    std::cout << "\n";
}


// ============================================================================
// EXAMPLE 4: MAKING NOP INSTRUCTIONS
// ============================================================================

void Example_MakeNOP()
{
    std::cout << "=== Example 4: Make NOP ===\n";

    // NOP a single byte
    Result res = makeNOP(GameOffsets::LANDING_DETECTED);
    std::cout << "[*] Single NOP: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    // NOP multiple bytes (e.g., disable a function)
    // Let's say we want to NOP 6 bytes
    res = makeNOP(GameOffsets::SPEEDOMETER_DRAW, 6);
    std::cout << "[*] 6-byte NOP: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    // NOP a range of addresses
    Range range{ GameOffsets::SPEEDOMETER_DRAW, GameOffsets::SPEEDOMETER_DRAW + 20 };
    res = makeRangedNOP(range);
    std::cout << "[*] Range NOP: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    std::cout << "\n";
}


// ============================================================================
// EXAMPLE 5: MAKING JMP INSTRUCTIONS
// ============================================================================

void Example_MakeJMP()
{
    std::cout << "=== Example 5: Make JMP ===\n";

    // Create a JMP from one location to another
    // Example: Redirect a function call to our custom function

    MemAddr fromAddr = GameOffsets::LANDING_DETECTED;
    MemAddr toAddr = 0x00410000;  // Our custom function address

    // Create unconditional JMP
    // K4MemPatcher automatically chooses between short, relative, or absolute
    Result res = makeJMP(fromAddr, toAddr, JmpCondition::Unconditional);

    if (res == Result::Success) {
        std::cout << "[+] JMP created successfully\n";
    }
    else {
        std::cout << "[-] Failed to create JMP: " << static_cast<int>(res) << "\n";
    }

    // Create conditional JMP (e.g., jump if above)
    res = makeJMP(fromAddr + 10, toAddr + 100, JmpCondition::Above);
    std::cout << "[*] Conditional JMP: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    // With NOP padding to preserve instruction alignment
    // Original instruction was 6 bytes, we write 5-byte JMP, so 1 byte gets NOP'd
    res = makeJMP(fromAddr + 20, toAddr + 200, JmpCondition::Unconditional, true);  // nopPadding = true

    std::cout << "\n";
}


// ============================================================================
// EXAMPLE 6: MAKING CALL INSTRUCTIONS
// ============================================================================

void Example_MakeCALL()
{
    std::cout << "=== Example 6: Make CALL ===\n";

    // Create a CALL instruction
    MemAddr fromAddr = GameOffsets::FUNC_GET_SPEED;
    MemAddr toAddr = 0x00420000;  // Our custom function

    Result res = makeCALL(fromAddr, toAddr);
    std::cout << "[*] CALL created: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    // With NOP padding
    res = makeCALL(fromAddr + 5, toAddr, true);
    std::cout << "[*] CALL with padding: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    std::cout << "\n";
}


// ============================================================================
// EXAMPLE 7: ADVANCED ASM INSTRUCTIONS
// ============================================================================

void Example_AdvancedASM()
{
    std::cout << "=== Example 7: Advanced ASM ===\n";

    MemAddr addr = GameOffsets::NITRO_ADDR;

    // Make RET instruction
    Result res = makeRET(addr);
    std::cout << "[*] RET: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    // Make RET with stack cleanup (pop 4 bytes)
    res = makeRETimm(addr, 4);
    std::cout << "[*] RET imm16: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    // Make PUSH immediate value
    res = makePUSH(addr, static_cast<uint32_t>(100));
    std::cout << "[*] PUSH imm32: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    // Make PUSH register
    res = makePUSH(addr, Register::EAX);
    std::cout << "[*] PUSH reg: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    // Make POP register
    res = makePOP(addr, Register::ECX);
    std::cout << "[*] POP reg: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    // Make INC/DEC
    res = makeINC(addr, Register::EAX);
    std::cout << "[*] INC reg: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    res = makeDEC(addr, Register::EBX);
    std::cout << "[*] DEC reg: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    // Make NEG/NOT
    res = makeNEG(addr, Register::EAX);
    std::cout << "[*] NEG reg: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    res = makeNOT(addr, Register::EAX);
    std::cout << "[*] NOT reg: " << (res == Result::Success ? "OK" : "FAILED") << "\n";

    std::cout << "\n";
}


// ============================================================================
// EXAMPLE 8: BYTE READING AND WRITING
// ============================================================================

void Example_ByteOperations()
{
    std::cout << "=== Example 8: Byte Operations ===\n";

    // Read bytes from memory
    std::vector<uint8_t> bytes = readBytes(GameOffsets::PLAYER_SPEED, 16);
    std::cout << "[*] Read " << bytes.size() << " bytes\n";

    // Print hex dump
    std::cout << "Hex: ";
    for (uint8_t b : bytes) {
        std::cout << std::hex << static_cast<int>(b) << " ";
    }
    std::cout << "\n";

    // Read range of bytes
    Range r{ GameOffsets::MONEY_ADDR, GameOffsets::MONEY_ADDR + 10 };
    std::vector<uint8_t> rangedBytes = readRangedBytes(r);
    std::cout << "[*] Read ranged: " << rangedBytes.size() << " bytes\n";

    // Compare bytes
    std::vector<uint8_t> original = { 0x90, 0x90, 0x90, 0x90, 0x90 };
    std::vector<uint8_t> nops = { 0x90, 0x90, 0x90, 0x90, 0x90 };

    if (compareBytes(original, nops)) {
        std::cout << "[*] Bytes match!\n";
    }

    // Swap bytes between two addresses
    bool swapped = swapBytes(GameOffsets::PLAYER_SPEED, GameOffsets::MONEY_ADDR, 4);
    std::cout << "[*] Swap bytes: " << (swapped ? "OK" : "FAILED") << "\n";

    std::cout << "\n";
}


// ============================================================================
// EXAMPLE 9: PATTERN SCANNING
// ============================================================================

void Example_PatternScanning()
{
    std::cout << "=== Example 9: Pattern Scanning ===\n";

    // Pattern format: "8B 0D ?? ?? ?? ?? 29 48 10"
    // ?? = wildcard (matches any byte)

    // Find first occurrence
    std::string pattern = "8B 0D ?? ?? ?? ?? 29 48 10";
    MemAddr foundAddr = findPattern(pattern, GAME_EXE);

    if (foundAddr) {
        std::cout << "[+] Pattern found at: 0x" << std::hex << foundAddr << "\n";
    }
    else {
        std::cout << "[-] Pattern not found\n";
    }

    // Find all occurrences
    std::vector<MemAddr> allAddresses = findPatterns(pattern, GAME_EXE);
    std::cout << "[*] Found " << allAddresses.size() << " occurrences\n";

    for (size_t i = 0; i < allAddresses.size(); ++i) {
        std::cout << "  [" << i << "] 0x" << std::hex << allAddresses[i] << "\n";
    }

    // Find first N patterns
    std::vector<MemAddr> firstThree = findPatterns(pattern, GAME_EXE, 3);
    std::cout << "[*] First 3: " << firstThree.size() << "\n";

    std::cout << "\n";
}


// ============================================================================
// EXAMPLE 10: BRANCH RESOLUTION
// ============================================================================

void Example_BranchResolution()
{
    std::cout << "=== Example 10: Branch Resolution ===\n";

    // Get information about a branch instruction (JMP/CALL)
    MemAddr jmpAddr{ GameOffsets::LANDING_DETECTED };

    BranchInfo info = resolveBranch(jmpAddr);

    if (info.target) {
        std::cout << "[*] Branch type: " << static_cast<int>(info.type) << "\n";
        std::cout << "[*] Target address: 0x" << std::hex << info.target << "\n";
    }

    // Find all JMPs that lead to a specific address
    MemAddr targetAddr = 0x00410000;
    std::vector<MemAddr> branches = findBranchesTo({ targetAddr, Branch::Jump }, GAME_EXE);

    std::cout << "[*] Found " << branches.size() << " branches to target\n";

    // Find all CALLs to a function
    std::vector<MemAddr> calls = findRelativeCalls(targetAddr, GAME_EXE);
    std::cout << "[*] Found " << calls.size() << " calls to target\n";

    // Resolve multiple branches
    std::vector<MemAddr> branchAddrs = {
        GameOffsets::FUNC_GET_SPEED,
        GameOffsets::FUNC_SET_SPEED
    };
    std::vector<BranchInfo> infos = resolveBranches(branchAddrs);

    for (const auto& bi : infos) {
        if (bi.target) {
            std::cout << "[*] Resolved: 0x" << std::hex << bi.target << "\n";
        }
    }

    std::cout << "\n";
}