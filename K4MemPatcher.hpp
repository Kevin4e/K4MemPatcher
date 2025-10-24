#pragma once

/*
 *  K4MemPatcher — Lightweight Windows memory patching utility
 *  Author: Kevin4e
 * 
 *  Modifies memory protections with VirtualProtect, restoring them afterwards.
 *  
 *  All functions guarantee 32-bit and 64-bit compatibility.
 * 
 *  Notes:
 *    - The caller must ensure the addresses passed to these functions are valid.
 *    - Function templates work only if T is a scalar/singular data type (not a collection).
 *    - All functions are NOT thread-safe; ensure no other thread is using these functions simultaneously.
 *    - Instruction cache is automatically flushed after each write.
 */

/*
 *  MIT License
 *  Copyright (c) 2025 Kevin4e
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
#include <variant>
#include <iterator>

namespace K4MemPatcher {
    struct MemAddr {
    private:
        uintptr_t addr;

    public:
        inline MemAddr(uintptr_t address) noexcept : addr(address) {}
        inline MemAddr(void* ptr) noexcept : addr(reinterpret_cast<uintptr_t>(ptr)) {}

        inline uintptr_t get() const noexcept {
            return addr;
        }
    };

    enum Result {
        Success,
		ProtectionChangeFailed,
		ReadFailed,
        InvalidRange,
        TooFarDistance
    };

    namespace Helpers {
        inline BOOL makePageWritable(uintptr_t address, size_t len, DWORD* originalP) noexcept {
            return VirtualProtect(reinterpret_cast<void*>(address), len, PAGE_EXECUTE_READWRITE, originalP);
        }
        inline BOOL flushAndRestoreProtection(uintptr_t address, size_t len, DWORD originalP) noexcept {
            // Flush instruction cache to ensure CPU fetches the updated instructions, recommended after writing new bytes into code memory
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), len);

            DWORD temp;
            return VirtualProtect(reinterpret_cast<void*>(address), len, originalP, &temp);
        }

        // Calculates the 32-bit relative offset between two memory addresses, adjusted by the size of the instruction.
        // Used for creating relative JMP or CALL patches.
        inline int32_t getRelativeOffset(uintptr_t addressFrom, uintptr_t addressTo, size_t instructionSize, Result* outResult = nullptr) noexcept {
            int64_t distance = addressTo - addressFrom - instructionSize;

            if (distance < INT32_MIN || distance > INT32_MAX) {
                if (outResult) *outResult = TooFarDistance;
                return int32_t{};
            }

            if (outResult) *outResult = Success;

            int32_t relativeOffset = static_cast<int32_t>(distance);

            return relativeOffset;
        }

        // Fill a block of memory with a single repeated byte
        inline Result fillRegion(uintptr_t address, uint8_t byte, size_t count) noexcept {
            DWORD originalProtect;

            if (!makePageWritable(address, count, &originalProtect)) // Make the page writable by changing its protection
                return ProtectionChangeFailed; // Couldn't change protection

            // Fill memory region with the given byte
            std::memset(reinterpret_cast<void*>(address), byte, count);

            flushAndRestoreProtection(address, count, originalProtect); // Flush instruction cache and restore original protection

            return Success;
        }

        // Write a sequence of raw bytes to a given memory address.
        template <size_t N>
        inline Result patchBytes(uintptr_t address, uint8_t(&bytes)[N]) noexcept {
            size_t len = N;

            DWORD originalProtect;

            if (!makePageWritable(address, len, &originalProtect)) // Make the page writable by changing its protection
                return ProtectionChangeFailed; // Couldn't change protection

            std::memcpy(reinterpret_cast<void*>(address), bytes, len); // Patches

            flushAndRestoreProtection(address, len, originalProtect); // Flush instruction cache and restore original protection

            return Success;
        }

        // Builds a relative instruction patch (JMP or CALL) that transfers execution from an address to another one
        template <size_t N>
        inline Result buildPatch(uintptr_t addressFrom, uintptr_t addressTo, uint8_t opcode, uint8_t(&patchytes)[N]) noexcept {
            size_t patchLen = N;
            patch[0] = opcode;

            Result outResult;
            int32_t relativeOffset = getRelativeOffset(addressFrom, addressTo, patchLen, &outResult);

            if (outResult != Success)
                return outResult;

            // Fills the empty part of the array 'patch' with the value of the relative offset
            std::memcpy(&patch[1], &relativeOffset, sizeof(relativeOffset));

            return Success;
        }
    }

    namespace Opcodes {
        constexpr uint8_t NOP_OPCODE = 0x90;
        constexpr uint8_t JMP_OPCODE = 0xE9;
		constexpr uint8_t CALL_OPCODE = 0xE8;
		constexpr uint8_t RET_OPCODE = 0xC3;
        constexpr uint8_t RET_OPCODE_IMM16 = 0xC2;
        constexpr uint8_t INT3_OPCODE = 0xCC;
    }

    namespace InstructionsSize {
        constexpr size_t JMP_SIZE = 5;
        constexpr size_t CALL_SIZE = 5;
		constexpr size_t RET_SIZE_MAX = 3;
    }

    using namespace Helpers;
    using namespace Opcodes;
    using namespace InstructionsSize;

    // Writes a value of type T to the specified memory address.
    template<typename T>
    inline Result writeMemory(const MemAddr& address, T value) noexcept {
        const size_t len = sizeof(T);
        uintptr_t addressCasted = address.get();

        DWORD originalProtect;

		if (!makePageWritable(addressCasted, len, &originalProtect)) // Make the page writable by changing its protection
            return ProtectionChangeFailed; // Couldn't change protection

        // Write the value directly
        *reinterpret_cast<T*>(addressCasted) = value;

        flushAndRestoreProtection(addressCasted, len, originalProtect); // Flush instruction cache and restore original protection

        return Success;
    }

    // Reads a value of type T from the specified memory address
    template<typename T>
    inline T readMemory(const MemAddr& address, Result* result = nullptr) noexcept {
        uintptr_t addressCasted = address.get();

        __try {
            if (result) *result = Success;
            return *reinterpret_cast<T*>(addressCasted); // Read the value directly and return it
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            if (result) *result = ReadFailed;
            return T{};
        }
    }

    // Writes a number of NOP instructions to an address
    inline Result makeNOP(const MemAddr& address, size_t count = 1) noexcept {
        return fillRegion(address.get(), NOP_OPCODE, count);
    }

    // Creates a relative jump from an address to another one
	// The distance between the two addresses must be within +/- 2GB
    inline Result makeJMP(const MemAddr& addressAt, const MemAddr& addressDest) noexcept {
        uint8_t patch[JMP_SIZE];
        Result r = buildPatch(addressAt.get(), addressDest.get(), JMP_OPCODE, patch);
        if (r != Success) return r;

        return patchBytes(addressAt.get(), patch);
    }

    // Creates a relative call from an address to another one
    // The distance between the two addresses must be within +/- 2GB
    inline Result makeCALL(const MemAddr& addressAt, const MemAddr& addressDest) noexcept {
        uint8_t patch[CALL_SIZE];
        Result r = buildPatch(addressAt.get(), addressDest.get(), CALL_OPCODE, patch);
        if (r != Success) return r;

        return patchBytes(addressAt.get(), patch);
    }

    // Creates a ret to an address
    inline Result makeRET(const MemAddr& addressAt, uint16_t stackCleanUpBytes = 0) noexcept {
        if (stackCleanUpBytes == 0)
            return writeMemory<uint8_t>(addressAt.get(), RET_OPCODE);

        uint8_t patch[RET_SIZE_MAX];
        patch[0] = RET_OPCODE_IMM16;
        
        // Fills the empty part of the array 'patch' with the value of the stack clean-up
        std::memcpy(&patch[1], &stackCleanUpBytes, 2);

        return patchBytes(addressAt.get(), patch);
    }

    // Writes a number of INT 3 instructions to an address
    inline Result makeINT3(const MemAddr& address, size_t count = 1) noexcept {
        return fillRegion(address.get(), INT3_OPCODE, count);
    }

    // Fills a memory region with NOP instructions from an address to another one (inclusive)
    // By default, the end address is included; set inclusive = false to exclude it.
    inline Result fillNOPs(const MemAddr& addressStart, const MemAddr& addressEnd, bool inclusive = true) noexcept {
        uintptr_t addressStartCasted = addressStart.get();
        uintptr_t addressEndCasted = addressEnd.get();

        if (addressEndCasted < addressStartCasted)
            return InvalidRange; // Invalid range

        size_t totalBytes = addressEndCasted - addressStartCasted;
        if (inclusive) ++totalBytes;

        return makeNOP(addressStart, totalBytes);
    }
}