#pragma once

/*
 *  K4MemPatcher — Helpers Header
 *  File: Helpers.hpp
 *
 *  Visibility: internal
 *
 *  Description: Defines functions heavily used throughout the library.
 */

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <system_error>

#include <Psapi.h>
#include <Windows.h>

#include "../Aliases.hpp"
#include "../Types.hpp"

#include "Constants.hpp"
#include "Misc.hpp"
#include "Utils.hpp"

namespace K4MemPatcher::Detail::Helpers {
    // Calculates the relative offset between two memory addresses, adjusted by the size of the instruction.
    // Used for creating JMP, CALL and LOOP patches.
    template <typename OffsetT>
    [[nodiscard]]
    constexpr inline OffsetResult<OffsetT> getRelativeOffset(
        Address from,
        Address to,
        Size    instructionSize,
        bool    checkDistance
    ) noexcept
    {
        const Distance distance{ to - from - instructionSize };

        if (checkDistance && !Utils::isInRange<OffsetT>(distance))
            return OffsetResult<OffsetT>{ OffsetT{}, Result::TooFarDistance };

        const OffsetT relativeOffset = static_cast<OffsetT>(distance);

        return OffsetResult<OffsetT>{ relativeOffset, Result::Success };
    }

    // Builds a short instruction patch (JMP) that transfers execution from an address to another one
    inline Result buildShortPatch(
        Address     from,
        Address     to,
        Byte        opcode,
        ByteArray<InstructionSize::JMP_REL8>& patch,
        bool        checkDistance
    ) noexcept
    {
        constexpr Size patchLen{ InstructionSize::JMP_REL8 };

        const OffsetResult<Rel8> relativeOffset{ getRelativeOffset<Rel8>(from, to, patchLen, checkDistance) };

        if (relativeOffset.result != Result::Success)
            return relativeOffset.result; // Failed to get relative offset

        Utils::addElementsToArray(patch, 0, opcode, relativeOffset.offset);

        return Result::Success;
    }

    // Builds a relative instruction patch (JMP or CALL) that transfers execution from an address to another one
    template <Size N>
    inline Result buildRelativePatch(
        Address       from,
        Address       to,
        ByteArray<2>  opcode,
        ByteArray<N>& patch,
        bool          checkDistance
    ) noexcept
    {
        constexpr Size patchLen{ N };

        const OffsetResult<Rel32> relativeOffset{ getRelativeOffset<Rel32>(from, to, patchLen, checkDistance) };

        if (relativeOffset.result != Result::Success)
            return relativeOffset.result; // Failed to get relative offset

        Size startIndex{0};

        patch[startIndex++] = opcode[0];

        if (patchLen == 6) // Conditional JMP
            patch[startIndex++] = opcode[1];

        // Fills the empty part of the array 'patch' with the value of the relative offset
        Utils::addBytesToArrayFromValue(patch, startIndex, relativeOffset.offset);

        return Result::Success;
    }

    // Builds an absolute instruction patch (JMP or CALL) that transfers execution from an address to another one
    inline void buildAbsolutePatch(
        Address to,
        Byte opcode,
        ByteArray<InstructionSize::JMP_ABS>& patch
    ) noexcept
    {
        Utils::addElementsToArray(patch, Opcode::REX_W, Opcode::MOV_RAX_IMM64);
        Utils::addBytesToArrayFromValue(patch, 2, to);
        Utils::addElementsToArray(patch, 10, Opcode::INDIRECT_JMP_CALL, opcode);
    }

    // Parses a bytes pattern and stores the bytes in the first vector and wildcards in the second one.
    // Returns true if the parsing succeeded.
    [[nodiscard]]
    inline PatternParsingResult parsePattern(const std::string& pattern) {
        std::string patternCpy{ pattern };

        // Remove whitespaces
        patternCpy.erase(std::remove_if(patternCpy.begin(), patternCpy.end(),
            [](unsigned char c) { return std::isspace(c); }),
            patternCpy.end());

        const Size patternSize{ patternCpy.size() };

        if (patternSize % 2 != 0 || patternSize == 0)
            return {}; // Odd-length pattern or zero

        const ByteCount nBytes{ patternSize / 2 };

        ByteBuffer bytesPattern;
        WildcardMask wildcard;

        bytesPattern.reserve(nBytes);
        wildcard.reserve(nBytes);

        for (Size i{0}; i < nBytes; ++i) {
            const Size idx{ i * 2 };

            if (patternCpy[idx] == '?' && patternCpy[idx + 1] == '?') { // If it's a wildcard
                bytesPattern.push_back(0x00);
                wildcard.push_back(true);
            }
            else {
                wildcard.push_back(false);

                Byte out{};

                // Converts a hex byte from its string format to the numeric one
                const auto result = std::from_chars(patternCpy.data() + idx, patternCpy.data() + idx + 2, out, 16);

                if (result.ec != std::errc{})
                    return {}; // Conversion failed

                bytesPattern.push_back(out);
            }
        }

        return { bytesPattern, wildcard };
    }

    // Computes the bounds of a module.
    [[nodiscard]]
    inline ModuleBounds getModuleBounds(ModuleName moduleName) noexcept {
        const HMODULE hModule{ GetModuleHandleA(moduleName) };

        if (!hModule)
            return {}; // Failed to get module handle

        const Address base{ reinterpret_cast<RawAddr>(hModule) };

        MODULEINFO moduleInfo;

        if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(MODULEINFO)))
            return {}; // Failed to get module info

        // Calculate the end address: base + size
        const Address end{ base + moduleInfo.SizeOfImage };

        return { base, end };
    }

    // Checks whether a memory region delimited by two addresses is safe to read
    [[nodiscard]]
    inline bool isReadingSafeRanged(const Range& range) noexcept {
        if (!range)
            return false; // Invalid range

        LPCVOID currentPtr{ range.start.as<LPCVOID>() };
        LPCVOID endPtr{ range.end.as<LPCVOID>() };

        MEMORY_BASIC_INFORMATION mbi{};

        while (currentPtr < endPtr) {
            if (!Utils::isMemoryReadable(currentPtr, mbi))
                return false;

            currentPtr = static_cast<const Byte*>(mbi.BaseAddress) + mbi.RegionSize;
        }

        return true;
    }

    // Checks whether a memory region starting from an address and spanning a number of bytes is safe to read
    [[nodiscard]]
    inline bool isReadingSafe(Address start, ByteCount nBytes) noexcept {
        return isReadingSafeRanged({ start, start + nBytes });
    }

    // Checks whether a memory region delimited by two addresses is safe to write
    // It does NOT check if it's directly writeable, only if it's safe enough to
    // change its protection to a writeable page.
    [[nodiscard]]
    inline bool isWritingSafeRanged(const Range& range) noexcept {
        if (!range)
            return false; // Invalid range

        LPCVOID currentPtr{ range.start.as<LPCVOID>() };
        LPCVOID endPtr{ range.end.as<LPCVOID>() };

        MEMORY_BASIC_INFORMATION mbi{};

        while (currentPtr < endPtr) {
            if (!Utils::isMemorySafe(currentPtr, mbi))
                return false;

            currentPtr = static_cast<const Byte*>(mbi.BaseAddress) + mbi.RegionSize;
        }

        return true;
    }

    // Checks whether a memory region starting from an address and spanning a number of bytes is safe to read
    [[nodiscard]]
    inline bool isWritingSafe(Address start, ByteCount nBytes) noexcept {
        return isWritingSafeRanged({ start, start + nBytes });
    }

    /*
    template <Branch branch>
    [[nodiscard]]
    inline Address resolveRelativeAddress(Address address) noexcept {
        static_assert(branch != Branch::Any, "Branch must be specific.");

        switch (branch) {
            case Branch::Jump:
            {
                const Byte* const bytes{ address.as<const Byte*>() };

                const Byte firstByte{ bytes[0] };

                if (Utils::isByteShortJump(firstByte))
            }
            case Branch::Call:
            {
                const Rel32 relOffset{ Raw::readFromAddress<Rel32>(address + 1) };
                return address + relOffset + InstructionSize::CALL_REL32;
            }
            case Branch::Loop:
            {
                const Rel8 relOffset{ Raw::readFromAddress<Rel8>(address + 1) };
                return address + relOffset + InstructionSize::LOOP;
            }
        }
    }
    */
}