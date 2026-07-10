#pragma once

/*
 *  K4MemPatcher — Modern Windows Memory Manipulation Toolkit
 *  Version v1.3.0
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

/*
 *  K4MemPatcher — Library Base Header
 *  File: K4MemPatcher.hpp
 * 
 *  Description: Defines the functions available to the public.
 */

#if !defined(K4MP_ENABLE_CORE) && \
    !defined(K4MP_ENABLE_BASIC_ASM) && \
    !defined(K4MP_ENABLE_ADVANCED_ASM) && \
    !defined(K4MP_ENABLE_BYTES_UTILS) && \
    !defined(K4MP_ENABLE_SCAN)

#define K4MP_ENABLE_CORE
#define K4MP_ENABLE_BASIC_ASM
#define K4MP_ENABLE_ADVANCED_ASM
#define K4MP_ENABLE_BYTES_UTILS
#define K4MP_ENABLE_SCAN

#endif

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>
#include <type_traits>
#include <unordered_set>

#ifndef K4MP_NO_MUTEX
#include <mutex>
#endif

#include "Aliases.hpp"
#include "Enums.hpp"
#include "Types.hpp"

#include "Internal/Constants.hpp"
#include "Internal/Helpers.hpp"
#include "Internal/Maps.hpp"
#include "Internal/Misc.hpp"
#include "Internal/Raw.hpp"
#include "Internal/Utils.hpp"

using namespace K4MemPatcher::Detail;

namespace K4MemPatcher {
    #ifdef K4MP_ENABLE_CORE

    // Writes a value of type T to the specified memory address.
    template <typename T>
    inline Result writeMemory(Address address, T value, bool validateMemory = true, bool flushICache = true) noexcept {
        static_assert(std::is_trivially_copyable_v<T>,
            "T must be trivially copyable");

        #ifndef K4MP_NO_MUTEX
            std::lock_guard<std::mutex> lock(getMutex());
        #endif

        if (validateMemory && !Helpers::isWritingSafe(address, sizeof(T)))
            return Result::UnsafeMemory;

        const PageWriteGuard guard{ address, sizeof(T), flushICache };

        if (!guard) return Result::ProtectionChangeFailed;

        Utils::addBytesToAddressFromValue(address, value);

        return Result::Success;
    }

    // Reads a value of type T from the specified memory address.
    template <typename T>
    [[nodiscard]]
    inline T readMemory(Address address, bool validateMemory = true) noexcept {
        if (validateMemory && !Helpers::isReadingSafe(address, sizeof(T)))
            return T{};

        return Raw::readFromAddress<T>(address);
    }

    #endif // K4MP_ENABLE_CORE

    #ifdef K4MP_ENABLE_BASIC_ASM

    // Writes a number of NOP instructions to the specified memory address.
    inline Result makeNOP(Address start, InstructionCount count = 1, bool validateMemory = true) noexcept {
        if (validateMemory && !Helpers::isWritingSafe(start, count))
            return Result::UnsafeMemory;

        return Raw::writeByte(start, Opcode::NOP, count);
    }

    // Fills a memory region with NOP instructions from an address to another one (exclusive).
    inline Result makeRangedNOP(const Range& range, bool validateMemory = true) noexcept {
        if (!range)
            return Result::InvalidRange;

        return makeNOP(range.start, range.size());
    }

    // Writes a JMP instruction from an address to another one.
    // NOTE: For jumps beyond +/- 2GB, a register (RAX) is used to hold the destination address and the jump is performed indirectly via that register.
    template <JmpCondition jumpCond = JmpCondition::Unconditional>
    inline Result makeJMP(
        Address from,
        Address to,
        bool    validateMemory = true
    ) noexcept
    {
        const Distance distance{ to - from };

        const Distance validDistanceForShort{ distance - InstructionSize::JMP_REL8 };

        // If the distance is in range for a short jump, uses it; otherwise, tries the relative one
        if (Utils::isInRange<Rel8>(validDistanceForShort))
            return Raw::makeShortJMP<jumpCond>(from, to, validateMemory, false);

        constexpr Size jmpRelSize{ Utils::getRelativeJmpSize<jumpCond>() };

        const Distance validDistanceForRelative{ distance - jmpRelSize };

        // If the distance is in range for a relative jump, and is not a JECXZ, uses it; otherwise, tries the absolute one
        if (Utils::isInRange<Rel32>(validDistanceForRelative)) 
            return Raw::makeRelativeJMP<jumpCond>(from, to, validateMemory, false);

        // Use the absolute one only if the jump is unconditional (JMP)
        if constexpr (jumpCond == JmpCondition::Unconditional)
            return Raw::makeAbsoluteJMP(from, to, validateMemory);

        return Result::TooFarDistance;
    }

    // Writes a CALL instruction from an address to another one.
    // NOTE: For jumps beyond +/- 2GB, a register (RAX) is used to hold the destination address and the jump is performed indirectly via that register.
    inline Result makeCALL(
        Address from,
        Address to,
        bool    validateMemory = true
    ) noexcept
    {
        const Distance validDistanceForRelative{ to - from - InstructionSize::CALL_REL32 };

        // If the distance is in range for a relative call, uses it, otherwise, uses the absolute one
        if (Utils::isInRange<Rel32>(validDistanceForRelative))
            return Raw::makeRelativeCALL(from, to, validateMemory, false);

        return Raw::makeAbsoluteCALL(from, to, validateMemory);
    }

    #endif // K4MP_ENABLE_BASIC_ASM

    #ifdef K4MP_ENABLE_ADVANCED_ASM

    // Writes a number of RET (no operand) instructions to the specified memory address.
    inline Result makeRET(Address start, InstructionCount count = 1, bool validateMemory = true) noexcept {
        if (validateMemory && !Helpers::isWritingSafe(start, count))
            return Result::UnsafeMemory;

        return Raw::writeByte(start, Opcode::RET_NEAR, count);
    }

    // Writes a number of RET IMM16 (stack cleanup) instructions to the specified memory address.
    inline Result makeRETimm(Address start, StackAdjustment cleanup, InstructionCount count = 1, bool validateMemory = true) noexcept {
        if (validateMemory && !Helpers::isWritingSafe(start, count))
            return Result::UnsafeMemory;

        ByteArray<InstructionSize::RET_IMM16> patch = { Opcode::RET_IMM16 };

        // Fills the empty part of the array 'patch' with the value of the stack cleanup
        Utils::addBytesToArrayFromValue(patch, 1, cleanup);

        return Raw::writeByteArray(start, patch, count);
    }

    // Writes a number of INT imm8 instructions to the specified memory address.
    // If imm8 is 3, the INT3 opcode is used (1 byte). For all the others, 2 bytes are used.
    inline Result makeINT(Address start, Interrupt interrupt, InstructionCount count = 1, bool validateMemory = true) noexcept {
        if (validateMemory && !Helpers::isWritingSafe(start, count))
            return Result::UnsafeMemory;

        if (interrupt == 3)
            return Raw::writeByte(start, Opcode::INT3, count);

        return Raw::writeByteArray<InstructionSize::INT_IMM8>(start, { Opcode::INT_IMM8, interrupt }, count);
    }

    // Writes a number of PUSH imm8/imm32 instructions to the specified memory address.
    template <typename T>
    inline Result makePUSH(Address start, T imm, InstructionCount count = 1, bool validateMemory = true) {
        static_assert(std::is_integral_v<T>, "T must be an integral type");

        constexpr Size immSize{ sizeof(T) };

        if constexpr (immSize != 1 && immSize != 4)
            return Result::InvalidOperand;

        if (validateMemory && !Helpers::isWritingSafe(start, count))
            return Result::UnsafeMemory;

        ByteArray<1 + immSize> patch{};

        if constexpr (immSize == 1)
            patch[0] = Opcode::PUSH_IMM8;
        else 
            patch[0] = Opcode::PUSH_IMM32;

        Utils::addBytesToArrayFromValue(patch, 1, imm);

        return Raw::writeByteArray(start, patch, count);
    }

    // Writes a number of PUSH reg instructions to the specified memory address.
    template <Register reg>
    inline Result makePUSH(Address start, InstructionCount count = 1, bool validateMemory = true) {
        if (validateMemory && !Helpers::isWritingSafe(start, count))
            return Result::UnsafeMemory;

        return Raw::makeRegInstruction<reg>(start, Opcode::PUSH_REG, count);
    }

    // Writes a number of POP reg instructions to the specified memory address.
    template <Register reg>
    inline Result makePOP(Address start, InstructionCount count = 1, bool validateMemory = true) {
        if (validateMemory && !Helpers::isWritingSafe(start, count))
            return Result::UnsafeMemory;

        return Raw::makeRegInstruction<reg>(start, Opcode::POP_REG, count);
    }

    // Writes a number of INC reg instructions to the specified memory address.
    template <Register reg>
    inline Result makeINC(Address start, InstructionCount count = 1, bool validateMemory = true) {
        if (validateMemory && !Helpers::isWritingSafe(start, count))
            return Result::UnsafeMemory;

        return Raw::makeRegInstruction<reg>(start, Opcode::MODRM_INC_REG_BASE, count);
    }

    // Writes a number of DEC reg instructions to the specified memory address.
    template <Register reg>
    inline Result makeDEC(Address start, InstructionCount count = 1, bool validateMemory = true) {
        if (validateMemory && !Helpers::isWritingSafe(start, count))
            return Result::UnsafeMemory;

        return Raw::makeRegInstruction<reg>(start, Opcode::MODRM_DEC_REG_BASE, count);
    }

    // Writes a number of NEG reg instructions to the specified memory address.
    template <Register reg>
    inline Result makeNEG(Address start, InstructionCount count = 1, bool validateMemory = true) {
        if (validateMemory && !Helpers::isWritingSafe(start, count))
            return Result::UnsafeMemory;

        return Raw::makeRegInstruction<reg>(start, Opcode::MODRM_NEG_REG_BASE, count);
    }

    // Writes a number of NOT reg instructions to the specified memory address.
    template <Register reg>
    inline Result makeNOT(Address start, InstructionCount count = 1, bool validateMemory = true) {
        if (validateMemory && !Helpers::isWritingSafe(start, count))
            return Result::UnsafeMemory;

        return Raw::makeRegInstruction<reg>(start, Opcode::MODRM_NOT_REG_BASE, count);
    }

    // Writes a LOOP instruction from an address to another one.
    template <LoopCondition loopCond = LoopCondition::CX>
    inline Result makeLOOP(Address from, Address to, bool validateMemory = true) noexcept {
        constexpr Size loopIndex{ Utils::toIndex(loopCond) };

        if constexpr (loopIndex >= LOOP_COND_ENUM_SIZE)
            return Result::InvalidLoop;

        constexpr Size loopSize{ InstructionSize::LOOP };

        if (validateMemory && !Helpers::isWritingSafe(from, loopSize))
            return Result::UnsafeMemory;

        const OffsetResult<Rel8> relOffset{ Helpers::getRelativeOffset<Rel8>(from, to, loopSize, true) };

        if (relOffset.result != Result::Success)
            return relOffset.result;

        return Raw::writeByteArray<loopSize>(from, { LOOPsMap[loopIndex], static_cast<UInt8>(relOffset.offset)}, 1);
    }

    #endif // K4MP_ENABLE_ADVANCED_ASM

    #ifdef K4MP_ENABLE_BYTES_UTILS

    // Reads a number of bytes starting from the specified address.
    [[nodiscard]]
    inline ByteBuffer readBytes(Address start, ByteCount len = 1, bool validateMemory = true) {
        if (validateMemory && !Helpers::isReadingSafe(start, len))
            return {};

        #ifndef K4MP_NO_MUTEX
            std::lock_guard<std::mutex> lock(getMutex());
        #endif

        ByteBuffer patch;
        patch.reserve(len);

        // Copy the first 'len' bytes starting from an address into the vector
        Utils::addBytesToBufferFromAddress(patch, start, len);

        return patch;
    }

    // Reads the bytes from an address to another one (exclusive) and stores it in a dynamic vector.
    [[nodiscard]]
    inline ByteBuffer readRangedBytes(const Range& range, bool validateMemory = true) {
        if (!range)
            return{}; // Invalid range

        if (validateMemory && !Helpers::isReadingSafeRanged(range))
            return {};

        return readBytes(range.start, range.size(), false);
    }

    // Compares the first 'len' bytes of two vectors and returns true if they are identical.
    // If 'len' goes beyond one of the vector's size, it returns false.
    [[nodiscard]]
    inline bool compareBytes(const ByteBuffer& bytes1, const ByteBuffer& bytes2, ByteCount len) noexcept {
        if (bytes1.size() < len || bytes2.size() < len)
            return false; // 'len' exceeds the size of either vector

        // Compares the first 'len' bytes of both vectors
        return std::memcmp(bytes1.data(), bytes2.data(), len) == 0;
    }

    // Compares all the bytes of two vectors and returns true if they are identical.
    // The two vectors' length must be the same.
    [[nodiscard]]
    inline bool compareBytes(const ByteBuffer& bytes1, const ByteBuffer& bytes2) noexcept {
        if (bytes1.size() != bytes2.size())
            return false; // The two vectors don't have equal size

        return compareBytes(bytes1, bytes2, bytes1.size());
    }
    
    // Swaps a number of bytes starting from two addresses.
    // Returns true if the swap was successful, false if not.
    inline bool swapBytes(Address first, Address second, ByteCount len, bool validateMemory = true) {
        if (len == 0)
            return true;

        if (validateMemory)
            if (!Helpers::isReadingSafe(first, len) || !Helpers::isReadingSafe(second, len) ||
                !Helpers::isWritingSafe(first, len) || !Helpers::isWritingSafe(second, len))
                return false;

        const Distance distance{ Utils::getDistance(first, second) };

        if (len > distance)
            return false;

        // Reading bytes
        const ByteBuffer firstBuffer(readBytes(first, len, false));
        const ByteBuffer secondBuffer(readBytes(second, len, false));

        Raw::writeByteBuffer(first, secondBuffer);
        Raw::writeByteBuffer(second, firstBuffer);

        return true;
    }

    // Swaps two ranged bytes, each starting from an address to another one (equal length is required).
    // Returns true if the swap was successful, false if not.
    inline bool swapRangedBytes(const Range& firstRange, const Range& secondRange, bool validateMemory = true) {
        if (!Utils::areRangesValid(firstRange, secondRange) || firstRange.size() != secondRange.size())
            return false;

        return swapBytes(firstRange.start, secondRange.start, firstRange.size(), validateMemory);
    }

    #endif // K4MP_ENABLE_BYTES_UTILS

    #ifdef K4MP_ENABLE_SCAN

    // Returns the first occurrence of the starting address of a bytes pattern.
    // Pattern format example: 8B 0D ?? ?? ?? ?? 29 48 10
    [[nodiscard]]
    inline Address findPattern(const std::string& pattern, ModuleName moduleName = nullptr) {
        const PatternParsingResult ppr{ Helpers::parsePattern(pattern) };

        if (!ppr)
            return {}; // Failed to parse pattern

        const ModuleBounds mb{ Helpers::getModuleBounds(moduleName) };

        if (!mb)
            return {}; // Failed to get module bounds
        
        const Size patternSize{ ppr.bytes.size() };

        const ScanWindow window{ mb.base, mb.end, patternSize - 1 };

        for (const Byte* current{ window.start }; current < window.end; ++current) {
            const Address address{ Raw::findPatternAt(current, ppr.bytes, ppr.wildcard) };

            if (address)
                return address;
        }
        
        return {};
    }

    // Returns all the occurrences of the starting addresses of a bytes pattern.
    // Pattern format example: 8B 0D ?? ?? ?? ?? 29 48 10
    [[nodiscard]]
    inline Addresses findPatterns(const std::string& pattern, ModuleName moduleName = nullptr, Size firstNPatterns = Limit::max<Size>) {
        if (firstNPatterns == 0)
            return {};

        if (firstNPatterns == 1)
            return { findPattern(pattern, moduleName) };

        const PatternParsingResult ppr{ Helpers::parsePattern(pattern) };

        if (!ppr)
            return {}; // Failed to parse the pattern

        const ModuleBounds mb{ Helpers::getModuleBounds(moduleName) };

        if (!mb)
            return {}; // Failed to get module bounds

        const ByteCount patternSize{ ppr.bytes.size() };

        if (patternSize > mb.size())
            return {}; // Module's size is less than the bytes of the pattern

        const Size toReserve{ firstNPatterns == Limit::max<Size> ?
            8 :             // Reserve 8 if default
            firstNPatterns // Else, reserve the number of calls to track
        };

        Addresses found;
        found.reserve(toReserve);

        const ScanWindow window{ mb.base, mb.end, patternSize - 1 };

        for (const Byte* current{ window.start }; current < window.end && found.size() < firstNPatterns; ++current) {
            const Address address{ Raw::findPatternAt(current, ppr.bytes, ppr.wildcard) };

            if (address)
                found.push_back(address);
        }

        return found;
    }

    // Returns the destination branch and its type of an instruction at the specified address.
    // Indirect branches are not supported.
    [[nodiscard]]
    inline BranchInfo resolveBranch(Address address) noexcept {
        if (!Helpers::isReadingSafe(address, 2))
            return {};

        Address target{};
        Branch type{};

        const Byte* const bytes = address.as<const Byte*>();
        const Byte firstByte{ bytes[0] };

        // Short jump (any condition)
        if (Utils::isByteShortJump(firstByte)) {
            type = Branch::Jump;
            const Rel8 relOffset{ Raw::readFromAddress<Rel8>(bytes + 1) };
            target = address + relOffset + InstructionSize::JMP_REL8;
        }

        // Relative call
        else if (firstByte == Opcode::CALL_REL32) {
            if (!Helpers::isReadingSafe(address + 2, 3)) return {};
            type = Branch::Call;
            const Rel32 relOffset{ Raw::readFromAddress<Rel32>(bytes + 1) };
            target = address + relOffset + InstructionSize::CALL_REL32;
        }

        // Loop (any condition)
        else if (Utils::isByteLoop(firstByte)) {
            type = Branch::Loop;
            const Rel8 relOffset{ Raw::readFromAddress<Rel8>(bytes + 1) };
            target = address + relOffset + InstructionSize::LOOP;
        }

        // Relative jump (unconditional)
        else if (firstByte == Opcode::JMP_REL32) {
            if (!Helpers::isReadingSafe(address + 2, 3)) return {};
            type = Branch::Jump;
            const Rel32 relOffset{ Raw::readFromAddress<Rel32>(bytes + 1) };
            target = address + relOffset + InstructionSize::JMP_REL32;
        }
        else {
            const Byte secondByte{ bytes[1] };

            // Relative jump (conditional)
            if (Utils::areBytesRelativeConditionalJump(firstByte, secondByte)) {
                if (!Helpers::isReadingSafe(address + 2, 4)) return {};
                type = Branch::Jump;
                const Int32 relOffset{ Raw::readFromAddress<Int32>(bytes + 2) };
                target = address + relOffset + InstructionSize::JCC_REL32;
            }
        }
        
        return { target, type };
    }

    // Returns the destination branches and their type of an instruction at multiple addresses.
    // Indirect branches are not supported.
    [[nodiscard]]
    inline std::vector<BranchInfo> resolveBranches(const Addresses& addresses) {
        std::vector<BranchInfo> branchesInfo;
        branchesInfo.reserve(addresses.size());

        for (const auto addr : addresses)
            branchesInfo.push_back(resolveBranch(addr));

        return branchesInfo;
    }

    // Finds the first address in which the execution is redirected to the specified address.
    // Indirect jumps/calls are not supported.
    [[nodiscard]]
    inline Address findBranchTo(const BranchInfo& branchInfo, ModuleName moduleName = nullptr) noexcept {
        if (Utils::toIndex(branchInfo.type) >= BRANCH_ENUM_SIZE)
            return {}; // Invalid branch

        const ModuleBounds mb{ Helpers::getModuleBounds(moduleName) };

        if (!mb)
            return {};

        const ScanWindow window{ mb.base, mb.end };

        const Byte* addr{ window.start };

        while (addr < window.end) {
            const Address address{ Raw::findBranchAt(addr, branchInfo, window.end) };

            if (address)
                return address;
        }
        
        return {};
    }

    // Finds all the addresses in which the execution is redirected to the specified address.
    // Indirect jumps/calls are not supported.
    [[nodiscard]]
    inline Addresses findBranchesTo(const BranchInfo& branchInfo, ModuleName moduleName = nullptr, Size firstNBranches = Limit::max<Size>) {
        if (firstNBranches == 0)
            return {}; // No branches to find

        if (firstNBranches == 1)
            return { findBranchTo(branchInfo, moduleName) }; // Just find the first occurrence

        if (Utils::toIndex(branchInfo.type) >= BRANCH_ENUM_SIZE)
            return {}; // Invalid branch

        const ModuleBounds mb{ Helpers::getModuleBounds(moduleName) };

        if (!mb)
            return {};

        const Size toReserve
        {
            firstNBranches == Limit::max<Size> ?

            8 :            // Reserve 8 if default
            firstNBranches // Else, reserve the number of calls to track
        };

        Addresses found;
        found.reserve(toReserve);
        
        const ScanWindow window{ mb.base, mb.end };

        const Byte* addr{ window.start };

        while (addr < window.end && found.size() < firstNBranches) {
            const Address address{ Raw::findBranchAt(addr, branchInfo, window.end) };

            if (address)
                found.push_back(address);
        }

        return found;
    }

    // Finds the first occurrence of a relative CALL that targets the given address.
    // Indirect calls are not detected.
    [[nodiscard]]
    inline Address findRelativeCall(Address target, ModuleName moduleName = nullptr) noexcept {
        return findBranchTo({ target, Branch::Call }, moduleName);
    }

    // Finds a number of direct relative CALLs that target the given address.
    // Indirect calls are not detected.
    [[nodiscard]]
    inline Addresses findRelativeCalls(Address target, ModuleName moduleName = nullptr, Size firstNCalls = Limit::max<Size>) {
        return findBranchesTo({ target, Branch::Call }, moduleName, firstNCalls);
    }

    // Finds the address of the first function that consists of a single RET instruction.
    [[nodiscard]]
    inline Address findRetFunction(ModuleName moduleName = nullptr) noexcept {
        const ModuleBounds mb{ Helpers::getModuleBounds(moduleName) };

        if (!mb)
            return {}; // Failed to get module bounds

        constexpr Size callSize{ InstructionSize::CALL_REL32 };

        const ScanWindow window{ mb.base, mb.end, callSize - 1 };

        for (const Byte* current{ window.start }; current < window.end; ++current) {
            const Address address{ Raw::findRetFunctionAt(current, mb) };

            if (address)
                return address;
        }

        return {};
    }

    // Finds addresses of functions that consist of a single RET instruction.
    // Results are returned in memory scan order unless 'sort' is enabled.
    [[nodiscard]]
    inline Addresses findRetFunctions(ModuleName moduleName = nullptr, bool sort = false, Size firstNFunctions = Limit::max<Size>) noexcept {
        if (firstNFunctions == 0)
            return {}; // No functions to find

        if (firstNFunctions == 1)
            return { findRetFunction(moduleName) }; // Just find the first occurrence

        const ModuleBounds mb{ Helpers::getModuleBounds(moduleName) };

        if (!mb)
            return {}; // Failed to get module bounds

        constexpr Size callSize{ InstructionSize::CALL_REL32 };

        const Size toReserve
        {
            firstNFunctions == Limit::max<Size> ?

            8 :         // Reserve 8 if default
            firstNFunctions // Else, reserve the number of calls to track
        };

        Addresses found{};
        found.reserve(toReserve);

        const ScanWindow window{ mb.base, mb.end, callSize - 1 };

        for (const Byte* current{ window.start }; current < window.end && found.size() < firstNFunctions; ++current) {
            const Address address{ Raw::findRetFunctionAt(current, mb) };

            if (address)
                found.push_back(address);
        }

        Utils::removeDuplicates(found);

        if (sort)
            Utils::sortVector(found);

        return found;
    }

    #endif // K4MP_ENABLE_SCAN
}