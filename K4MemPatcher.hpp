#pragma once

/*
 *  K4MemPatcher — Lightweight Windows memory patching utility
 *  Version v1.1.0
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
#include <vector>
#include <mutex>

namespace {
    namespace Opcodes {
        constexpr uint8_t NOP_OPCODE = 0x90;
        constexpr uint8_t SHORT_JMP_OPCODE = 0xEB;
        constexpr uint8_t RELATIVE_JMP_OPCODE = 0xE9;
        constexpr uint8_t JUMP_TO_RAX_OPCODE = 0xE0;
        constexpr uint8_t RELATIVE_CALL_OPCODE = 0xE8;
        constexpr uint8_t RET_OPCODE = 0xC3;
        constexpr uint8_t RET_OPCODE_IMM16 = 0xC2;
        constexpr uint8_t INT3_OPCODE = 0xCC;
        constexpr uint8_t REXW_OPCODE = 0x48;
        constexpr uint8_t MOV_RAX_IMM64_OPCODE = 0xB8;
        constexpr uint8_t INDIRECT_JMP_CALL_OPCODE = 0xFF;
        constexpr uint8_t CALL_TO_RAX_OPCODE = 0xD0;
    }

    namespace InstructionsSize {
        constexpr size_t SHORT_JMP_SIZE = 2;
        constexpr size_t RELATIVE_JMP_SIZE = 5;
        constexpr size_t ABS_JMP_SIZE = 12;
        constexpr size_t RELATIVE_CALL_SIZE = 5;
        constexpr size_t ABS_CALL_SIZE = 12;
        constexpr size_t RET_SIZE_MAX = 3;
    }
}

namespace K4MemPatcher {
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
        uintptr_t addr;

    public:
        MemAddr(uintptr_t address) noexcept : addr(address) {}
        MemAddr(void* ptr) noexcept : addr(reinterpret_cast<uintptr_t>(ptr)) {}

        constexpr uintptr_t get() const noexcept {
            return addr;
        }
    };

    enum class Result {
        Success,
		ProtectionChangeFailed,
        InvalidRange,
        TooFarDistance,
        InvalidPtr,
        InvalidOperand
    };

    namespace Helpers {
        // Calculates the relative offset between two memory addresses, adjusted by the size of the instruction.
        // Used for creating JMP or CALL patches.
        constexpr inline int32_t getRelativeOffset(uintptr_t addressFrom, uintptr_t addressTo, size_t instructionSize, bool checkDistance, Result* outResult = nullptr) noexcept {
            const int64_t distance = addressTo - addressFrom - instructionSize;

            if (checkDistance && (distance < INT32_MIN || distance > INT32_MAX)) {
                if (outResult) *outResult = Result::TooFarDistance;
                return int32_t{};
            }

            if (outResult) *outResult = Result::Success;

            const int32_t relativeOffset = static_cast<int32_t>(distance);

            return relativeOffset;
        }

        // Fills a block of memory with a single repeated byte
        inline Result fillRegion(uintptr_t address, uint8_t byte, size_t count) noexcept {
            std::lock_guard<std::mutex> lock(getMutex());

            const PageWriteGuard guard(address, count);

            if (!guard.hasSucceeded()) return Result::ProtectionChangeFailed;

            std::memset(reinterpret_cast<void*>(address), byte, count);

            return Result::Success;
        }

        // Writes a sequence of raw bytes to a given memory address.
        template <size_t N>
        inline Result patchBytes(uintptr_t address, uint8_t(&bytes)[N]) noexcept {
            std::lock_guard<std::mutex> lock(getMutex());

            const PageWriteGuard guard(address, N);

            if (!guard.hasSucceeded()) return Result::ProtectionChangeFailed;

            std::memcpy(reinterpret_cast<void*>(address), bytes, N); // Patches

            return Result::Success;
        }

        // Builds a relative instruction patch (JMP or CALL) that transfers execution from an address to another one
        template <size_t N>
        constexpr inline Result buildRelativePatch(uintptr_t addressFrom, uintptr_t addressTo, uint8_t opcode, uint8_t(&patchBytes)[N], bool checkDistance) noexcept {
            patchBytes[0] = opcode;

            Result outResult;
            const int32_t relativeOffset = getRelativeOffset(addressFrom, addressTo, N, checkDistance, &outResult);

            if (outResult != Result::Success)
                return outResult;

            // Fills the empty part of the array 'patch' with the value of the relative offset
            std::memcpy(&patchBytes[1], &relativeOffset, sizeof(relativeOffset));

            return Result::Success;
        }

        // Builds an absolute instruction patch (JMP or CALL) that transfers execution from an address to another one
        inline Result buildAbsolutePatch(uintptr_t addressFrom, uintptr_t addressTo, uint8_t opcode, uint8_t patchBytes[]) noexcept {
            patchBytes[0] = Opcodes::REXW_OPCODE;
            patchBytes[1] = Opcodes::MOV_RAX_IMM64_OPCODE;

            std::memcpy(&patchBytes[2], &addressTo, 8);

            patchBytes[10] = Opcodes::INDIRECT_JMP_CALL_OPCODE;
            patchBytes[11] = opcode;
            
            return Result::Success;
        }
    }

    // Use the functions inside of this namespace if you're sure of what you're doing. 'makeJMP' and 'makeCALL' already handle distances, and use the appropriate function.
    namespace Raw {
        // Creates a short jump from an address to another one
        // The distance between the two addresses must be within +/- 128 bytes
        inline Result makeShortJMP(const MemAddr& addressFrom, const MemAddr& addressTo, bool checkDistance = true) {
            const int64_t distance = addressTo.get() - addressFrom.get() - InstructionsSize::SHORT_JMP_SIZE;

            if (checkDistance && (distance < INT8_MIN || distance > INT8_MAX))
                return Result::TooFarDistance;

            uint8_t patch[InstructionsSize::SHORT_JMP_SIZE];
            patch[0] = Opcodes::SHORT_JMP_OPCODE;

            const int8_t relativeOffset = static_cast<int8_t>(distance);

            std::memcpy(&patch[1], &relativeOffset, 1);

            return Helpers::patchBytes(addressFrom.get(), patch);
        }

        // Creates a relative jump from an address to another one
	    // The distance between the two addresses must be within +/- 2GiB (≈ 2GB)
        inline Result makeRelativeJMP(const MemAddr& addressFrom, const MemAddr& addressTo, bool checkDistance = true) noexcept {
            uint8_t patch[InstructionsSize::RELATIVE_JMP_SIZE];

            const Result r = Helpers::buildRelativePatch(addressFrom.get(), addressTo.get(), Opcodes::RELATIVE_JMP_OPCODE, patch, checkDistance);
            if (r != Result::Success) return r;

            return Helpers::patchBytes(addressFrom.get(), patch);
        }

        // Creates an absolute jump from an address to another one
        // The distance between the two addresses is irrelevant
        inline Result makeAbsoluteJMP(const MemAddr& addressFrom, const MemAddr& addressTo) {
            uint8_t patch[InstructionsSize::ABS_JMP_SIZE];

            const Result r = Helpers::buildAbsolutePatch(addressFrom.get(), addressTo.get(), Opcodes::JUMP_TO_RAX_OPCODE, patch);
            if (r != Result::Success) return r;

            return Helpers::patchBytes(addressFrom.get(), patch);
        }

        // Creates a relative call from an address to another one
        // The distance between the two addresses must be within +/- 2GiB (≈ 2GB)
        inline Result makeRelativeCALL(const MemAddr& addressFrom, const MemAddr& addressTo, bool checkDistance = true) noexcept {
            uint8_t patch[InstructionsSize::RELATIVE_CALL_SIZE];

            const Result r = Helpers::buildRelativePatch(addressFrom.get(), addressTo.get(), Opcodes::RELATIVE_CALL_OPCODE, patch, checkDistance);
            if (r != Result::Success) return r;

            return Helpers::patchBytes(addressFrom.get(), patch);
        }

        // Creates an absolute call from an address to another one
        // The distance between the two addresses is irrelevant
        inline Result makeAbsoluteCALL(const MemAddr& addressFrom, const MemAddr& addressTo) {
            uint8_t patch[InstructionsSize::ABS_CALL_SIZE];

            const Result r = Helpers::buildAbsolutePatch(addressFrom.get(), addressTo.get(), Opcodes::CALL_TO_RAX_OPCODE, patch);
            if (r != Result::Success) return r;

            return Helpers::patchBytes(addressFrom.get(), patch);
        }
    }
    
    // Writes a value of type T to the specified memory address.
    template<typename T>
    inline Result writeMemory(const MemAddr& address, T value) noexcept {
        std::lock_guard<std::mutex> lock(getMutex());

        const size_t len = sizeof(T);
        const uintptr_t addressCasted = address.get();

        const PageWriteGuard guard(addressCasted, len);

        if (!guard.hasSucceeded()) return Result::ProtectionChangeFailed;

        // Write the value directly
        *reinterpret_cast<T*>(addressCasted) = value;

        return Result::Success;
    }

    // Reads a value of type T from the specified memory address
    template<typename T>
    inline T readMemory(const MemAddr& address) noexcept {
        std::lock_guard<std::mutex> lock(getMutex());

        T value{};
        std::memcpy(&value, reinterpret_cast<void*>(address.get()), sizeof(T)); // Copies 'sizeof(T)' bytes from the address into 'value'
        return value;
    }

    // Writes a number of 'nop' instructions to an address
    inline Result makeNOP(const MemAddr& addressStart, size_t count = 1) noexcept {
        return Helpers::fillRegion(addressStart.get(), Opcodes::NOP_OPCODE, count); // Writes the 'nop' opcode at the address
    }

    // Creates a jmp instruction from an address to another one.
    // Any distance is valid
    inline Result makeJMP(const MemAddr& addressFrom, const MemAddr& addressTo) noexcept {
        const int64_t distance = static_cast<int64_t>(addressTo.get() - addressFrom.get());

        const int64_t validDistanceForShort = distance - InstructionsSize::SHORT_JMP_SIZE;

        // If the distance is in range for a short jump, uses it; otherwise, try the relative one
        if (validDistanceForShort >= INT8_MIN && validDistanceForShort <= INT8_MAX)
            return Raw::makeShortJMP(addressFrom, addressTo, false);

        const int64_t validDistanceForRelative = distance - InstructionsSize::RELATIVE_JMP_SIZE;

        // If the distance is in range for a relative jump, uses it; otherwise, use the absolute one
        if (validDistanceForRelative >= INT32_MIN && validDistanceForRelative <= INT32_MAX) 
            return Raw::makeRelativeJMP(addressFrom, addressTo, false);

        return Raw::makeAbsoluteJMP(addressFrom, addressTo);
    }

    // Creates a call instruction from an address to another one.
    // Any distance is valid
    inline Result makeCALL(const MemAddr& addressFrom, const MemAddr& addressTo) noexcept {
        const int64_t distance = static_cast<int64_t>(addressTo.get() - addressFrom.get());

        const int64_t validDistanceForRelative = distance - InstructionsSize::RELATIVE_CALL_SIZE;

        // If the distance is in range for a relative call, uses it, otherwise, uses the absolute one
        if (validDistanceForRelative >= INT32_MIN && validDistanceForRelative <= INT32_MAX)
            return Raw::makeRelativeCALL(addressFrom, addressTo, false);

        return Raw::makeAbsoluteCALL(addressFrom, addressTo);
    }

    // Creates a 'ret' (no operand) to an address
    inline Result makeRET(const MemAddr& address) noexcept {
        return writeMemory<uint8_t>(address, Opcodes::RET_OPCODE); // Writes the 'ret' opcode at the address
    }

    // Creates a 'ret imm16' (stack cleanup) to an address
    inline Result makeRET(const MemAddr& address, uint16_t stackCleanUpBytes) noexcept {
        if (stackCleanUpBytes > 0xFFFF) // Operand is 16-bit; values above 65535 are invalid
            return Result::InvalidOperand;

        uint8_t patch[InstructionsSize::RET_SIZE_MAX];
        patch[0] = Opcodes::RET_OPCODE_IMM16;
        
        // Fills the empty part of the array 'patch' with the value of the stack clean-up
        std::memcpy(&patch[1], &stackCleanUpBytes, 2);

        return Helpers::patchBytes(address.get(), patch);
    }

    // Writes a number of INT 3 instructions to an address
    inline Result makeINT3(const MemAddr& address, size_t count = 1) noexcept {
        return Helpers::fillRegion(address.get(), Opcodes::INT3_OPCODE, count);
    }

    // Fills a memory region with NOP instructions from an address to another one (inclusive)
    // By default, the end address is included; set inclusive = false to exclude it.
    inline Result fillNOPs(const MemAddr& addressStart, const MemAddr& addressEnd, bool inclusive = true) noexcept {
        uintptr_t addressStartCasted = addressStart.get();
        uintptr_t addressEndCasted = addressEnd.get();

        if (addressEndCasted < addressStartCasted)
            return Result::InvalidRange; // Invalid range

        size_t totalBytes = addressEndCasted - addressStartCasted;
        if (inclusive) ++totalBytes;

        return makeNOP(addressStart, totalBytes);
    }

    // Get stable pointer given the process module and an array of offsets
    inline uintptr_t getStablePointer(HMODULE moduleBase, const std::vector<uintptr_t>& offsets, bool checkIfInvalid = false) noexcept {
        std::lock_guard<std::mutex> lock(getMutex());

        uintptr_t finalPointer = reinterpret_cast<uintptr_t>(moduleBase); // Start from the base address

        const size_t nOffsets = offsets.size();

        if (nOffsets == 0)
            return finalPointer;

        if (checkIfInvalid) {
            for (size_t i = 0; i < nOffsets - 1; ++i) {
                if (!finalPointer)
                    return 0; // Return 0 if pointer is invalid

                finalPointer = *reinterpret_cast<uintptr_t*>(finalPointer + offsets[i]); // Read the offset
            }
        }
        else
            for (size_t i = 0; i < nOffsets - 1; ++i)
                finalPointer = *reinterpret_cast<uintptr_t*>(finalPointer + offsets[i]); // Read the offset

        return finalPointer + offsets.back();
    }

    // Reads the bytes from an address to another one and stores it in a dynamic vector
    // By default, the end address is included; set inclusive = false to exclude it.
    inline std::vector<uint8_t> backupBytes(const MemAddr& addressStart, const MemAddr& addressEnd, bool inclusive = true) noexcept {
        std::lock_guard<std::mutex> lock(getMutex());

        uintptr_t addressStartCasted = addressStart.get();
        uintptr_t addressEndCasted = addressEnd.get();

        // If the end address comes before the start one, return an empty collection
        if (addressStartCasted > addressEndCasted)
            return {};

        size_t len = addressEndCasted - addressStartCasted;
        if (inclusive) ++len;

        std::vector<uint8_t> patch(len);

        // Copy the first 'len' bytes starting from an address into the vector
        std::memcpy(patch.data(), reinterpret_cast<void*>(addressStartCasted), len);

        return patch;
    }

    // Reads a number of bytes starting from an address
    inline std::vector<uint8_t> backupBytes(const MemAddr& addressStart, size_t len = 1) noexcept {
        std::lock_guard<std::mutex> lock(getMutex());

        std::vector<uint8_t> patch(len);

        // Copy the first 'len' bytes starting from an address into the vector
        std::memcpy(patch.data(), reinterpret_cast<void*>(addressStart.get()), len);

        return patch;
    }

    // Compares the first 'len' bytes of two vectors and returns true if they are identical
    // If 'len' goes beyond one of the vector's size, it returns false
    inline bool compareBytes(const std::vector<uint8_t>& patch1, const std::vector<uint8_t>& patch2, size_t len) noexcept {

        // Return false if 'len' exceeds the size of either vector
        if (patch1.size() < len || patch2.size() < len)
            return false;

        // Compares the first 'len' bytes of both vectors
        return std::memcmp(patch1.data(), patch2.data(), len) == 0;
    }
}