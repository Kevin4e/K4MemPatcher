#pragma once

/*
 *  K4MemPatcher — Lightweight Windows memory patching utility
 *  Version v1.2.0
 *  GitHub page: https://github.com/Kevin4e/K4MemPatcher
 *  Author: Kevin4e
 *  
 *  Modifies memory protections with VirtualProtect, restoring them afterwards.
 *  
 *  All functions guarantee 32-bit and 64-bit compatibility.
 *  
 *  Target: C++17+
 * 
 *  Notes:
 *    - The caller must ensure the addresses passed to these functions are valid.
 *    - Function templates work only if T is a scalar/singular data type (not a collection).
 *    - All functions are thread-safe.
 *    - Instruction cache is automatically flushed after each write.
 */

/*
 *  MIT License
 *  Copyright (c) 2025-2026 Kevin4e
 * 
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
 *  and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */ 

#include <windows.h>
#include <cstring>
#include <cstdint>
#include <vector>
#include <mutex>
#include <array>
#include <Psapi.h>
#include <limits>
#include <cctype>
#include <string>
#include <algorithm>
#include <charconv>

namespace K4MemPatcher {
    namespace Opcodes {
        constexpr uint8_t NOP_OPCODE = 0x90;
        //constexpr uint8_t SHORT_JMP_OPCODE = 0xEB;
        //constexpr uint8_t RELATIVE_JMP_OPCODE = 0xE9;
        constexpr uint8_t JUMP_TO_RAX_MOD_RM_OPCODE = 0xE0;
        constexpr uint8_t RELATIVE_CALL_OPCODE = 0xE8;
        constexpr uint8_t RET_OPCODE = 0xC3;
        constexpr uint8_t RET_OPCODE_IMM16 = 0xC2;
        constexpr uint8_t INT3_OPCODE = 0xCC;
        constexpr uint8_t INT_OPCODE = 0xCD;
        constexpr uint8_t REXB_OPCODE = 0x41;
        constexpr uint8_t REXW_OPCODE = 0x48;
        constexpr uint8_t REXWB_OPCODE = 0x49;
        constexpr uint8_t MOV_RAX_IMM64_OPCODE = 0xB8;
        constexpr uint8_t INDIRECT_JMP_CALL_OPCODE = 0xFF;
        constexpr uint8_t CALL_TO_RAX_MOD_RM_OPCODE = 0xD0;
        constexpr uint8_t PUSH_IMM8_OPCODE = 0x6A;
        constexpr uint8_t PUSH_IMM32_OPCODE = 0x68;
        constexpr uint8_t PUSH_REG_OPCODE = 0x50;
        constexpr uint8_t POP_REG_OPCODE = 0x58;
        constexpr uint8_t LOOP_OPCODE = 0xE2;
        constexpr uint8_t INC_REG_OPCODE = 0xC0;
        constexpr uint8_t DEC_REG_OPCODE = 0xC8;
        constexpr uint8_t NOT_REG_OPCODE = 0xD0;
        constexpr uint8_t NEG_REG_OPCODE = 0xD8;
    }

    namespace InstructionsSize {
        constexpr size_t SHORT_JMP_SIZE = 2;
        constexpr size_t RELATIVE_JMP_SIZE = 5;
        constexpr size_t ABS_JMP_SIZE = 12;
        constexpr size_t RELATIVE_CALL_SIZE = 5;
        constexpr size_t ABS_CALL_SIZE = 12;
        constexpr size_t RET_IMM16_SIZE = 3;
        constexpr size_t LOOP_SIZE = 2;
    }

    inline std::mutex& getMutex() {
        static std::mutex mtx;
        return mtx;
    }

    class PageWriteGuard {
    private:
        uintptr_t address_;
        size_t len_;
        DWORD oldProtection_;
        bool protectionChangeSucceeded = true;

    public:
        // Changes the protection of the page.
        // By default, the new protection is set to make the page writeable (PAGE_EXECUTE_READWRITE)
        PageWriteGuard(uintptr_t address, size_t len, DWORD newProtection = PAGE_EXECUTE_READWRITE) noexcept : address_(address), len_(len) {
            if (!VirtualProtect(reinterpret_cast<void*>(address_), len_, newProtection, &oldProtection_))
                protectionChangeSucceeded = false;
        }

        // Flushes instruction cache and restores original protection when the guard goes out of scope
        ~PageWriteGuard() noexcept {
            if (protectionChangeSucceeded) {
                // Flush instruction cache to ensure CPU fetches the updated instructions, recommended after writing new bytes into code memory
                FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address_), len_);

                // Restore original protection
                VirtualProtect(reinterpret_cast<void*>(address_), len_, oldProtection_, nullptr);
            }
        }

        bool hasSucceeded() const noexcept {
            return protectionChangeSucceeded;
        }
    };

    struct MemAddr {
    private:
        uintptr_t address;

    public:
        MemAddr(uintptr_t address) noexcept : address(address) {}
        MemAddr(void* ptr) noexcept : address(reinterpret_cast<uintptr_t>(ptr)) {}

        uintptr_t get() const noexcept {
            return address;
        }
    };

    enum class Result {
        Success,
		ProtectionChangeFailed,
        InvalidRange,
        TooFarDistance,
        InvalidJump,
        InvalidRegister,
        InvalidOperand
    };

    class StablePtr {
    private:
        std::vector<uintptr_t> offsets;
        bool alwaysResolve;
        uintptr_t baseAddress;

        bool isResolved = false;
        uintptr_t stablePtr;

        size_t nOffsetsRequired;

    public:
        StablePtr(uintptr_t baseAddress, const std::vector<uintptr_t>& offsets, bool alwaysResolve = true) noexcept :
            offsets(offsets),
            alwaysResolve(alwaysResolve),
            baseAddress(baseAddress),
            nOffsetsRequired(offsets.size() == 0 ? 0 : offsets.size() - 1)
        {}

        StablePtr(HMODULE moduleBase, const std::vector<uintptr_t>& offsets, bool alwaysResolve = true) noexcept :
            StablePtr(reinterpret_cast<uintptr_t>(moduleBase), offsets, alwaysResolve)
        {}

        uintptr_t Resolve() noexcept {
            if (nOffsetsRequired == 0)
                return baseAddress;

            if (!alwaysResolve && isResolved)
                return stablePtr; // Return cached pointer if it was already resolved and it doesn't have to resolved every time

            stablePtr = baseAddress; // Start from the base address

            for (size_t i = 0; i < nOffsetsRequired; ++i) {
                uintptr_t valueRead = readMemory<uintptr_t>(stablePtr + offsets[i]);

                if (!valueRead)
                    return {};

                stablePtr = valueRead;
            }

            stablePtr += offsets.back();

            isResolved = true;

            return stablePtr;
        }

        bool hasPointerChainFailed() const noexcept {
            return !isResolved;
        }
    };

    enum class JmpCondition {
        Unconditional,  // JMP

        Above,          // JA  = JNBE (NotBelowOrEqual)
        AboveOrEqual,   // JAE = JNB  (NotBelow)
        Below,          // JB  = JNAE (NotAboveOrEqual)
        BelowOrEqual,   // JBE = JNA  (NotAbove)
        Carry,          // JC
        Equal,          // JE  = JZ   (Zero)
        EqualCXZero,    // JECXZ
        Greater,        // JG  = JNLE (NotLessOrEqual)
        GreaterOrEqual, // JGE = JNL  (NotLess)
        Less,           // JL  = JNGE (NotGreaterOrEqual)
        LessOrEqual,    // JLE = JNG  (NotGreater)
        NotCarry,       // JNC
        NotEqual,       // JNE = JNZ  (NotZero)        
        NotOverflow,    // JNO
        NotParity,      // JNP = JPO  (ParityOdd)
        NotSign,        // JNS
        Overflow,       // JO
        Parity,         // JP  = JPE  (ParityEven)
        Sign,           // JS

        Count           // Number of jumps
    };

    inline constexpr size_t JMP_COND_SIZE = static_cast<size_t>(JmpCondition::Count);

    enum class Register {
        AX, CX, DX, BX, SP, BP, SI, DI, // 16-bit
        
        EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, // 32-bit

        RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, // 64-bit

        R8, R9, R10, R11,
        R12, R13, R14, R15,

        Count // Number of registers
    };

    inline constexpr size_t REG_SIZE = static_cast<size_t>(Register::Count);

    // Opcodes for all jumps (rel8)
    inline constexpr std::array<uint8_t, JMP_COND_SIZE> shortJumpsMap = {
        0xEB,  /*  Unconditional  (JMP)    */
        0x77,  /*  Above          (JA)     */
        0x73,  /*  AboveOrEqual   (JAE)    */
        0x72,  /*  Below          (JB)     */
        0x76,  /*  BelowOrEqual   (JBE)    */
        0x72,  /*  Carry          (JC)     */
        0x74,  /*  Equal          (JE)     */
        0xE3,  /*  EqualCXZero    (JECXZ)  */
        0x7F,  /*  Greater        (JG)     */
        0x7D,  /*  GreaterOrEqual (JGE)    */
        0x7C,  /*  Less           (JL)     */
        0x7E,  /*  LessOrEqual    (JLE)    */
        0x73,  /*  NotCarry       (JNC)    */
        0x75,  /*  NotEqual       (JNE)    */
        0x71,  /*  NotOverflow    (JNO)    */
        0x7B,  /*  NotParity      (JNP)    */
        0x79,  /*  NotSign        (JNS)    */
        0x70,  /*  Overflow       (JO)     */
        0x7A,  /*  Parity         (JP)     */
        0x78   /*  Sign           (JS)     */
    };

    // Opcodes for all jumps (rel32)
    inline constexpr std::array<std::array<uint8_t, 2>, JMP_COND_SIZE> relativeJumpsMap = { {
        {0xE9, 0x00},  /*  Unconditional  (JMP)  */
        {0x0F, 0x87},  /*  Above          (JA)   */
        {0x0F, 0x83},  /*  AboveOrEqual   (JAE)  */
        {0x0F, 0x82},  /*  Below          (JB)   */
        {0x0F, 0x86},  /*  BelowOrEqual   (JBE)  */
        {0x0F, 0x82},  /*  Carry          (JC)   */
        {0x0F, 0x84},  /*  Equal          (JE)   */
        {0x0F, 0x8F},  /*  Greater        (JG)   */
        {0x0F, 0x8D},  /*  GreaterOrEqual (JGE)  */
        {0x0F, 0x8C},  /*  Less           (JL)   */
        {0x0F, 0x8E},  /*  LessOrEqual    (JLE)  */
        {0x0F, 0x83},  /*  NotCarry       (JNC)  */
        {0x0F, 0x85},  /*  NotEqual       (JNE)  */
        {0x0F, 0x81},  /*  NotOverflow    (JNO)  */
        {0x0F, 0x8B},  /*  NotParity      (JNP)  */
        {0x0F, 0x89},  /*  NotSign        (JNS)  */
        {0x0F, 0x80},  /*  Overflow       (JO)   */
        {0x0F, 0x8A},  /*  Parity         (JP)   */
        {0x0F, 0x88}   /*  Sign           (JS)   */
    } };

    struct Range {
    public:
        uintptr_t startingPoint;
        uintptr_t endingPoint;
        size_t length;

        Range(const MemAddr& startingPoint, const MemAddr& endingPoint) noexcept : startingPoint(startingPoint.get()), endingPoint(endingPoint.get()) {
            length = (this->startingPoint > this->endingPoint) ? 0 : (this->endingPoint - this->startingPoint) + 1;
        }
    };

    namespace Helpers {
        // Calculates the relative offset between two memory addresses, adjusted by the size of the instruction.
        // Used for creating JMP or CALL patches.
        inline int32_t getRelativeOffset(uintptr_t addressFrom, uintptr_t addressTo, size_t instructionSize, bool checkDistance, Result* outResult = nullptr) noexcept {
            const int64_t distance = addressTo - addressFrom - instructionSize;

            if (checkDistance && (distance < INT32_MIN || distance > INT32_MAX)) {
                if (outResult) *outResult = Result::TooFarDistance;
                return int32_t{};
            }

            if (outResult) *outResult = Result::Success;

            const int32_t relativeOffset = static_cast<int32_t>(distance);

            return relativeOffset;
        }

        // Builds a short instruction patch (JMP) that transfers execution from an address to another one
        inline Result buildShortPatch(uintptr_t addressFrom, uintptr_t addressTo, uint8_t opcode, std::vector<uint8_t>& patchBytes, bool checkDistance) noexcept {
            patchBytes[0] = opcode;

            const size_t patchLen = patchBytes.size();

            Result outResult;
            const int32_t relativeOffset = getRelativeOffset(addressFrom, addressTo, patchLen, checkDistance, &outResult);

            if (outResult != Result::Success)
                return outResult;

            patchBytes[1] = static_cast<uint8_t>(relativeOffset);

            return Result::Success;
        }

        // Builds a relative instruction patch (JMP or CALL) that transfers execution from an address to another one
        inline Result buildRelativePatch(uintptr_t addressFrom, uintptr_t addressTo, std::array<uint8_t, 2> opcodes, std::vector<uint8_t>& patchBytes, bool checkDistance) noexcept {
            uint8_t firstOpcode = opcodes[0];

            patchBytes[0] = firstOpcode;

            size_t indexMin = 1;

            if (firstOpcode == 0x0F) {
                patchBytes[1] = opcodes[1];
                indexMin = 2;
            }

            const size_t patchLen = patchBytes.size();

            Result outResult;
            const int32_t relativeOffset = getRelativeOffset(addressFrom, addressTo, patchLen, checkDistance, &outResult);

            if (outResult != Result::Success)
                return outResult;

            // Fills the empty part of the array 'patch' with the value of the relative offset
            std::memcpy(&patchBytes[indexMin], &relativeOffset, sizeof(relativeOffset));

            return Result::Success;
        }

        // Builds an absolute instruction patch (JMP or CALL) that transfers execution from an address to another one
        inline Result buildAbsolutePatch(uintptr_t addressTo, uint8_t opcode, std::vector<uint8_t>& patchBytes) noexcept {
            patchBytes[0] = Opcodes::REXW_OPCODE;
            patchBytes[1] = Opcodes::MOV_RAX_IMM64_OPCODE;

            std::memcpy(&patchBytes[2], &addressTo, 8);

            patchBytes[10] = Opcodes::INDIRECT_JMP_CALL_OPCODE;
            patchBytes[11] = opcode;
            
            return Result::Success;
        }

        // Validates two ranges:
        // - Ensures each range's start address is not greater than its end address.
        // - Checks that the ranges do not overlap.
        inline bool areRangesValid(const Range& range1, const Range& range2) noexcept {
            if (range1.startingPoint > range1.endingPoint || range2.startingPoint > range2.endingPoint)
                return false; // Starting points are greater than the ending ones

            if (range1.startingPoint <= range2.endingPoint && range2.startingPoint <= range1.endingPoint)
                return false; // Ranges overlap

            return true;
        }

        // Adds NOP opcodes to a patch if the original instruction is longer
        inline void addEventualNOPs(std::vector<uint8_t>& patch, size_t jmpOrCallSize, size_t originalInstructionSize) noexcept {
            if (originalInstructionSize < jmpOrCallSize)
                return;

            const size_t numberOfNOPToWrite = originalInstructionSize - jmpOrCallSize;

            for (size_t i = 0; i < numberOfNOPToWrite; ++i)
                patch.emplace_back(Opcodes::NOP_OPCODE);
        }

        // Computes the absolute distance between two addresses
        inline size_t getDistance(uintptr_t a, uintptr_t b) {
            return (a > b) ? (a - b) : (b - a);
        }

        // Computes the module base and module end of the executable
        inline bool getModuleBounds(uintptr_t& moduleBase, uintptr_t& moduleEnd) {
            HMODULE hModule = GetModuleHandleA(nullptr);

            if (!hModule)
                return false;  // Failed to get module handle

            moduleBase = reinterpret_cast<uintptr_t>(hModule);

            MODULEINFO moduleInfo;

            if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(MODULEINFO)))
                return false;  // Failed to get module info

            // Calculate the end address: base + size - 1
            moduleEnd = moduleBase + moduleInfo.SizeOfImage - 1;

            return true;
        }
    }

    // Use the functions inside of this namespace if you're sure of what you're doing ('makeJMP' and 'makeCALL' already handle distances and use the appropriate function).
    namespace Raw {
        // Writes a sequence of raw bytes to a memory address, repeated 'count' times consecutively.
        inline Result writeBytes(const MemAddr& address, const std::vector<uint8_t>& bytes, size_t count = 1) noexcept {
            std::lock_guard<std::mutex> lock(getMutex());

            uintptr_t addressCasted = address.get();

            const size_t bytesLen = bytes.size();

            const PageWriteGuard guard(addressCasted, bytesLen * count);

            if (!guard.hasSucceeded()) return Result::ProtectionChangeFailed;

            if (bytesLen == 1)
                std::memset(reinterpret_cast<void*>(addressCasted), bytes[0], count);
            else {
                for (size_t i = 0; i < count; ++i) {
                    std::memcpy(reinterpret_cast<void*>(addressCasted), bytes.data(), bytesLen); // Patches
                    addressCasted += bytesLen; // Shift 
                }
            }

            return Result::Success;
        }

        // Writes a single byte to a memory address, repeated 'count' times consecutively.
        inline Result writeByte(const MemAddr& address, uint8_t byte, size_t count = 1) noexcept {
            return writeBytes(address, { byte }, count);
        }

        // Creates a short jump from an address to another one.
        // The distance between the two addresses must be within +/- 128 bytes.
        inline Result makeShortJMP(const MemAddr& addressFrom, const MemAddr& addressTo, JmpCondition jumpCond, bool checkDistance = true, bool nopOutRemainingBytes = false, size_t originalInstructionSize = 0) {
            const size_t jmpSize = InstructionsSize::SHORT_JMP_SIZE;

            std::vector<uint8_t> patch(jmpSize);

            size_t jumpCondIndex = static_cast<uint8_t>(jumpCond);

            if (jumpCondIndex >= JMP_COND_SIZE) return Result::InvalidJump;

            const Result r = Helpers::buildShortPatch(addressFrom.get(), addressTo.get(), shortJumpsMap[jumpCondIndex], patch, checkDistance);

            if (r != Result::Success) return r;

            if (nopOutRemainingBytes)
                Helpers::addEventualNOPs(patch, jmpSize, originalInstructionSize);

            return writeBytes(addressFrom.get(), patch);
        }

        // Creates a relative jump from an address to another one.
	    // The distance between the two addresses must be within +/- 2GiB (≈ 2GB).
        inline Result makeRelativeJMP(const MemAddr& addressFrom, const MemAddr& addressTo, JmpCondition jumpCond, bool checkDistance = true, bool nopOutRemainingBytes = false, size_t originalInstructionSize = 0) noexcept {
            const size_t jmpSize = (jumpCond == JmpCondition::Unconditional) ? 5 : 6; // unconditional rel32 jump size = 5; conditional rel32 jump size = 6

            std::vector<uint8_t> patch(jmpSize);

            size_t jumpCondIndex = static_cast<uint8_t>(jumpCond);

            if (jumpCondIndex >= JMP_COND_SIZE) return Result::InvalidJump;

            const Result r = Helpers::buildRelativePatch(addressFrom.get(), addressTo.get(), relativeJumpsMap[jumpCondIndex], patch, checkDistance);

            if (r != Result::Success) return r;

            if (nopOutRemainingBytes)
                Helpers::addEventualNOPs(patch, jmpSize, originalInstructionSize);

            return writeBytes(addressFrom.get(), patch);
        }

        // Creates an absolute jump from an address to another one using the RAX register.
        // The distance between the two addresses is irrelevant.
        inline Result makeAbsoluteJMP(const MemAddr& addressFrom, const MemAddr& addressTo, bool nopOutRemainingBytes = false, size_t originalInstructionSize = 0) {
            const size_t jmpSize = InstructionsSize::ABS_JMP_SIZE;

            std::vector<uint8_t> patch(jmpSize);

            const Result r = Helpers::buildAbsolutePatch(addressTo.get(), Opcodes::JUMP_TO_RAX_MOD_RM_OPCODE, patch);
            if (r != Result::Success) return r;

            if (nopOutRemainingBytes)
                Helpers::addEventualNOPs(patch, jmpSize, originalInstructionSize);

            return writeBytes(addressFrom.get(), patch);
        }

        // Writes a relative call from an address to another one.
        // The distance between the two addresses must be within +/- 2GiB (≈ 2GB).
        inline Result makeRelativeCALL(const MemAddr& addressFrom, const MemAddr& addressTo, bool checkDistance = true, bool nopOutRemainingBytes = false, size_t originalInstructionSize = 0) noexcept {
            const size_t callSize = InstructionsSize::RELATIVE_CALL_SIZE;

            std::vector<uint8_t> patch(callSize);

            const Result r = Helpers::buildRelativePatch(addressFrom.get(), addressTo.get(), { Opcodes::RELATIVE_CALL_OPCODE, 0x00 }, patch, checkDistance);
            if (r != Result::Success) return r;

            if (nopOutRemainingBytes)
                Helpers::addEventualNOPs(patch, callSize, originalInstructionSize);

            return writeBytes(addressFrom.get(), patch);
        }

        // Writes an absolute call from an address to another one using the RAX register.
        // The distance between the two addresses is irrelevant.
        inline Result makeAbsoluteCALL(const MemAddr& addressFrom, const MemAddr& addressTo, bool nopOutRemainingBytes = false, size_t originalInstructionSize = 0) {
            const size_t callSize = InstructionsSize::ABS_CALL_SIZE;

            std::vector<uint8_t> patch(callSize);

            const Result r = Helpers::buildAbsolutePatch(addressTo.get(), Opcodes::CALL_TO_RAX_MOD_RM_OPCODE, patch);
            if (r != Result::Success) return r;

            if (nopOutRemainingBytes)
                Helpers::addEventualNOPs(patch, callSize, originalInstructionSize);

            return writeBytes(addressFrom.get(), patch);
        }

        inline Result makeRegInstruction(const MemAddr& address, uint8_t baseOpcode, Register reg, size_t count = 1) {
            const size_t regIndex = static_cast<size_t>(reg);

            if (regIndex >= REG_SIZE)
                return Result::InvalidRegister;

            std::vector<uint8_t> finalPatch;

            const uint8_t opcode = baseOpcode + (regIndex % 8);

            if (regIndex < 8) { // AX-DI
                if (baseOpcode == Opcodes::PUSH_REG_OPCODE || baseOpcode == Opcodes::POP_REG_OPCODE) // If we're making a PUSH/POP instruction
                    finalPatch.insert(finalPatch.end(), { 0x66, opcode });

                else if (baseOpcode == Opcodes::NEG_REG_OPCODE || baseOpcode == Opcodes::NOT_REG_OPCODE) // If we're making a NEG/NOT instruction
                    finalPatch.insert(finalPatch.end(), { 0x66, 0xF7, opcode });

                else
                    finalPatch.insert(finalPatch.end(), { 0x66, 0xFF, opcode });
            }

            else if (regIndex < 16) { // EAX-EDI
                if (baseOpcode == Opcodes::PUSH_REG_OPCODE || baseOpcode == Opcodes::POP_REG_OPCODE) // If we're making a PUSH/POP instruction
                    finalPatch.insert(finalPatch.end(), { opcode });

                else if (baseOpcode == Opcodes::NEG_REG_OPCODE || baseOpcode == Opcodes::NOT_REG_OPCODE) // If we're making a NEG/NOT instruction
                    finalPatch.insert(finalPatch.end(), { 0xF7, opcode });

                else
                    finalPatch.insert(finalPatch.end(), { 0xFF, opcode });
            }

            else if (regIndex < 24) { // RAX-RDI
                if (baseOpcode == Opcodes::PUSH_REG_OPCODE || baseOpcode == Opcodes::POP_REG_OPCODE) // If we're making a PUSH/POP instruction
                    finalPatch.insert(finalPatch.end(), { opcode });

                else if (baseOpcode == Opcodes::NEG_REG_OPCODE || baseOpcode == Opcodes::NOT_REG_OPCODE) // If we're making a NEG/NOT instruction
                    finalPatch.insert(finalPatch.end(), { Opcodes::REXW_OPCODE, 0xF7, opcode });

                else
                    finalPatch.insert(finalPatch.end(), { Opcodes::REXW_OPCODE, 0xFF, opcode });
            }

            else { // R8-R15
                if (baseOpcode == Opcodes::PUSH_REG_OPCODE || baseOpcode == Opcodes::POP_REG_OPCODE) // If we're making a PUSH/POP instruction
                    finalPatch.insert(finalPatch.end(), { Opcodes::REXB_OPCODE, opcode });

                else if (baseOpcode == Opcodes::NEG_REG_OPCODE || baseOpcode == Opcodes::NOT_REG_OPCODE) // If we're making a NEG/NOT instruction
                    finalPatch.insert(finalPatch.end(), { Opcodes::REXW_OPCODE, 0xF7, opcode });

                else
                    finalPatch.insert(finalPatch.end(), { Opcodes::REXWB_OPCODE, 0xFF, opcode });
            }
            
            return Raw::writeBytes(address.get(), finalPatch, count);
        }
    }
    
    // Writes a value of type T to the specified memory address.
    template <typename T>
    inline Result writeMemory(const MemAddr& address, T value) noexcept {
        std::lock_guard<std::mutex> lock(getMutex());

        const size_t len = sizeof(T);
        const uintptr_t addressCasted = address.get();

        const PageWriteGuard guard(addressCasted, len);

        if (!guard.hasSucceeded()) return Result::ProtectionChangeFailed;

        // Write the value directly
        std::memcpy(reinterpret_cast<void*>(addressCasted), &value, len);

        return Result::Success;
    }

    // Reads a value of type T from the specified memory address.
    template <typename T>
    inline T readMemory(const MemAddr& address) noexcept {
        std::lock_guard<std::mutex> lock(getMutex());

        T value{};
        std::memcpy(&value, reinterpret_cast<void*>(address.get()), sizeof(T)); // Copies 'sizeof(T)' bytes from the address into 'value'
        return value;
    }

    // Writes a number of NOP instructions to the specified memory address.
    inline Result makeNOP(const MemAddr& addressStart, size_t count = 1) noexcept {
        return Raw::writeByte(addressStart.get(), Opcodes::NOP_OPCODE, count);
    }

    // Fills a memory region with NOP instructions from an address to another one (inclusive).
    inline Result makeRangedNOP(const Range& rangeAddresses) noexcept {
        const uintptr_t addressStart = rangeAddresses.startingPoint;
        const uintptr_t addressEnd = rangeAddresses.endingPoint;

        if (addressEnd < addressStart)
            return Result::InvalidRange;

        const size_t totalBytes = addressEnd - addressStart + 1;

        return makeNOP(addressStart, totalBytes);
    }

    // Writes a JMP instruction from an address to another one.
    // NOTE: For jumps beyond +/- 2GB, a register (RAX) is used to hold the destination address and the jump is performed indirectly via that register.
    inline Result makeJMP(const MemAddr& addressFrom, const MemAddr& addressTo, JmpCondition jumpCond, bool nopOutRemainingBytes = false, size_t originalInstructionSizeLength = 0) noexcept {
        const int64_t distance = static_cast<int64_t>(addressTo.get() - addressFrom.get());

        const int64_t validDistanceForShort = distance - InstructionsSize::SHORT_JMP_SIZE;

        // If the distance is in range for a short jump, uses it; otherwise, try the relative one
        if (validDistanceForShort >= INT8_MIN && validDistanceForShort <= INT8_MAX)
            return Raw::makeShortJMP(addressFrom, addressTo, jumpCond, false, nopOutRemainingBytes, originalInstructionSizeLength);

        const int64_t validDistanceForRelative = distance - InstructionsSize::RELATIVE_JMP_SIZE;

        // If the distance is in range for a relative jump, and is not a JECXZ, uses it; otherwise, try the absolute one
        if (jumpCond != JmpCondition::EqualCXZero && validDistanceForRelative >= INT32_MIN && validDistanceForRelative <= INT32_MAX) 
            return Raw::makeRelativeJMP(addressFrom, addressTo, jumpCond, false, nopOutRemainingBytes, originalInstructionSizeLength);

        // Use the absolute one only if the jump is unconditional (JMP)
        return jumpCond == JmpCondition::Unconditional ? Raw::makeAbsoluteJMP(addressFrom, addressTo, nopOutRemainingBytes, originalInstructionSizeLength) : Result::TooFarDistance;
    }

    // Writes a CALL instruction from an address to another one.
    // NOTE: For jumps beyond +/- 2GB, a register (RAX) is used to hold the destination address and the jump is performed indirectly via that register.
    inline Result makeCALL(const MemAddr& addressFrom, const MemAddr& addressTo, bool nopOutRemainingBytes = false, size_t originalInstructionSizeLength = 0) noexcept {
        const int64_t distance = static_cast<int64_t>(addressTo.get() - addressFrom.get());

        const int64_t validDistanceForRelative = distance - InstructionsSize::RELATIVE_CALL_SIZE;

        // If the distance is in range for a relative call, uses it, otherwise, uses the absolute one
        if (validDistanceForRelative >= INT32_MIN && validDistanceForRelative <= INT32_MAX)
            return Raw::makeRelativeCALL(addressFrom, addressTo, false, nopOutRemainingBytes, originalInstructionSizeLength);

        return Raw::makeAbsoluteCALL(addressFrom, addressTo, nopOutRemainingBytes, originalInstructionSizeLength);
    }

    // Writes a number of RET (no operand) instructions to the specified memory address.
    inline Result makeRET(const MemAddr& address, size_t count = 1) noexcept {
        return Raw::writeByte(address.get(), Opcodes::RET_OPCODE, count);
    }

    // Writes a number of RET IMM16 (stack cleanup) instructions to the specified memory address.
    inline Result makeRET(const MemAddr& address, uint16_t stackCleanUpBytes, size_t count = 1) noexcept {
        std::vector<uint8_t> patch(InstructionsSize::RET_IMM16_SIZE);

        patch[0] = Opcodes::RET_OPCODE_IMM16;
        
        // Fills the empty part of the array 'patch' with the value of the stack cleanup
        std::memcpy(&patch[1], &stackCleanUpBytes, 2);

        return Raw::writeBytes(address.get(), patch, count);
    }

    // Writes a number of INT imm8 instructions to the specified memory address.
    // If imm8 is 3, the INT3 opcode is used (1 byte). For all the others, 2 bytes are used.
    inline Result makeINT(const MemAddr& address, uint8_t interrupt, size_t count = 1) noexcept {
        if (interrupt == 3)
            return Raw::writeByte(address.get(), Opcodes::INT3_OPCODE, count);

        return Raw::writeBytes(address.get(), { Opcodes::INT_OPCODE, interrupt }, count);
    }

    // Writes a number of PUSH imm8/imm32 instructions to the specified memory address.
    template <typename T>
    inline Result makePUSH(const MemAddr& address, T imm, size_t count = 1) noexcept {
        static_assert(std::is_integral_v<T>, "T must be an integral type");

        const size_t immSize = sizeof(imm);

        std::vector<uint8_t> opcodes;

        switch (immSize) {
            case 1: // imm8
                opcodes.push_back(Opcodes::PUSH_IMM8_OPCODE);
                break;

            case 4: // imm32
                opcodes.push_back(Opcodes::PUSH_IMM32_OPCODE);
                break;

            default:
                return Result::InvalidOperand;
        }

        const size_t opcodeSize = opcodes.size();

        opcodes.resize(opcodeSize + immSize);

        std::memcpy(opcodes.data() + opcodeSize, &imm, immSize);

        return Raw::writeBytes(address, opcodes, count);
    }

    // Writes a number of PUSH reg instructions to the specified memory address.  
    inline Result makePUSH(const MemAddr& address, Register reg, size_t count = 1) noexcept {
        return Raw::makeRegInstruction(address.get(), Opcodes::PUSH_REG_OPCODE, reg, count);
    }

    // Writes a number of POP reg instructions to the specified memory address. 
    inline Result makePOP(const MemAddr& address, Register reg, size_t count = 1) noexcept {
        return Raw::makeRegInstruction(address.get(), Opcodes::POP_REG_OPCODE, reg, count);
    }

    // Writes a number of INC reg instructions to the specified memory address. 
    inline Result makeINC(const MemAddr& address, Register reg, size_t count = 1) noexcept {
        return Raw::makeRegInstruction(address.get(), Opcodes::INC_REG_OPCODE, reg, count);
    }

    // Writes a number of DEC reg instructions to the specified memory address. 
    inline Result makeDEC(const MemAddr& address, Register reg, size_t count = 1) noexcept {
        return Raw::makeRegInstruction(address.get(), Opcodes::DEC_REG_OPCODE, reg, count);
    }

    // Writes a number of NEG reg instructions to the specified memory address. 
    inline Result makeNEG(const MemAddr& address, Register reg, size_t count = 1) noexcept {
        return Raw::makeRegInstruction(address.get(), Opcodes::NEG_REG_OPCODE, reg, count);
    }

    // Writes a number of NOT reg instructions to the specified memory address. 
    inline Result makeNOT(const MemAddr& address, Register reg, size_t count = 1) noexcept {
        return Raw::makeRegInstruction(address.get(), Opcodes::NOT_REG_OPCODE, reg, count);
    }

    // Writes a LOOP instruction from an address to another one.
    inline Result makeLOOP(const MemAddr& addressFrom, const MemAddr& addressTo) noexcept {
        Result outResult;

        const int32_t relOffset = Helpers::getRelativeOffset(addressFrom.get(), addressTo.get(), InstructionsSize::LOOP_SIZE, true, &outResult);

        if (outResult != Result::Success)
            return outResult;

        return Raw::writeBytes(addressFrom.get(), { Opcodes::LOOP_OPCODE, static_cast<uint8_t>(relOffset) });
    }

    // Reads a number of bytes starting from the specified address.
    inline std::vector<uint8_t> readBytes(const MemAddr& addressStart, size_t len = 1) noexcept {
        std::lock_guard<std::mutex> lock(getMutex());

        std::vector<uint8_t> patch(len);

        // Copy the first 'len' bytes starting from an address into the vector
        std::memcpy(patch.data(), reinterpret_cast<void*>(addressStart.get()), len);

        return patch;
    }

    // Reads the bytes from an address to another one (inclusive) and stores it in a dynamic vector.
    inline std::vector<uint8_t> readRangedBytes(const Range& bytesRange) noexcept {
        const uintptr_t addressStart = bytesRange.startingPoint;
        const uintptr_t addressEnd = bytesRange.endingPoint;

        // If the end address comes before the start one, return an empty collection
        if (addressStart > addressEnd)
            return {};

        const size_t nBytes = addressEnd - addressStart + 1;

        return readBytes(addressStart, nBytes);
    }

    // Compares the first 'len' bytes of two vectors and returns true if they are identical.
    // If 'len' goes beyond one of the vector's size, it returns false.
    inline bool compareBytes(const std::vector<uint8_t>& bytes1, const std::vector<uint8_t>& bytes2, size_t len) noexcept {

        // Return false if 'len' exceeds the size of either vector
        if (bytes1.size() < len || bytes2.size() < len)
            return false;

        // Compares the first 'len' bytes of both vectors
        return std::memcmp(bytes1.data(), bytes2.data(), len) == 0;
    }

    // Compares all the bytes of two vectors and returns true if they are identical.
    // The two vectors' length must be the same.
    inline bool compareBytes(const std::vector<uint8_t>& bytes1, const std::vector<uint8_t>& bytes2) noexcept {

        // Return false if the two vectors don't have equal size
        if (bytes1.size() != bytes2.size())
            return false;

        return compareBytes(bytes1, bytes2, bytes1.size());
    }
    
    // Swaps a number of bytes starting from two addresses.
    // Returns true if the swap was successful, false if not.
    inline bool swapBytes(const MemAddr& address1, const MemAddr& address2, size_t len) noexcept {
        uintptr_t address1Casted = address1.get();
        uintptr_t address2Casted = address2.get();

        const size_t distance = Helpers::getDistance(address1Casted, address2Casted);

        if (len > distance)
            return false;

        // Reading bytes
        std::vector<uint8_t>bytes1 = readBytes(address1, len);
        std::vector<uint8_t>bytes2 = readBytes(address2, len);

        Raw::writeBytes(address1Casted, bytes2);
        Raw::writeBytes(address2Casted, bytes1);

        return true;
    }

    // Swaps two ranged bytes, each starting from an address to another one (equal length is required).
    // Returns true if the swap was successful, false if not.
    inline bool swapRangedBytes(const Range& range1, const Range& range2) noexcept {
        const size_t lenRange1 = range1.length;

        if (!Helpers::areRangesValid(range1, range2) || lenRange1 != range2.length)
            return false;

        return swapBytes(range1.startingPoint, range2.startingPoint, lenRange1);
    }

    // Returns the starting address of a bytes pattern.
    // Pattern format example: 8B 0D ?? ?? ?? ?? 29 48 10
    inline uintptr_t findPattern(const std::string& pattern, uintptr_t startAddress = 0, uintptr_t endAddress = std::numeric_limits<uintptr_t>::max()) noexcept {
        if (startAddress > endAddress)
            return{};

        uintptr_t moduleBase;
        uintptr_t moduleEnd;

        if (!Helpers::getModuleBounds(moduleBase, moduleEnd))
            return {};

        // Clamp limits if exceeded
        if (startAddress < moduleBase) startAddress = moduleBase;
        if (endAddress > moduleEnd) endAddress = moduleEnd;

        std::string patternCpy = pattern;

        patternCpy.erase(std::remove_if(patternCpy.begin(), patternCpy.end(),
            [](unsigned char c) { return std::isspace(c); }),
            patternCpy.end());

        const size_t patternSize = patternCpy.size();

        if (patternSize % 2 != 0) 
            return {}; // Odd-length pattern

        const size_t nBytes = patternSize / 2;

        std::vector<uint8_t> bytesPattern(nBytes);
        std::vector<bool> wildcard(nBytes);

        for (size_t i = 0; i < nBytes; ++i) {
            size_t idx = i * 2;

            if (patternCpy[idx] == '?' && patternCpy[idx + 1] == '?') {
                wildcard[i] = true;
            }
            else {
                wildcard[i] = false;

                // Converts a hex byte from its string format to the numeric one (casted to uint8_t)
                auto result = std::from_chars(patternCpy.data() + idx, patternCpy.data() + idx + 2, bytesPattern[i], 16);

                if (result.ec != std::errc{})
                    return {}; // Conversion failed
            }
        }

        uint8_t* scanStart = reinterpret_cast<uint8_t*>(startAddress);
        uint8_t* scanEnd = reinterpret_cast<uint8_t*>(endAddress);

        for (uint8_t* current = scanStart; current <= scanEnd - nBytes; ++current) {
            bool isEqual = true;

            for (size_t i = 0; i < nBytes; ++i) {
                if (!wildcard[i] && bytesPattern[i] != current[i]) { // If not a wildcard and unequal
                    isEqual = false;
                    break;
                }
            }

            if (!isEqual)
                continue;

            return reinterpret_cast<uintptr_t>(current);
        }

        return {};
    }
}