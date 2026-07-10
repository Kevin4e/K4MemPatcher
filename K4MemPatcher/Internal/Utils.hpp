#pragma once

/*
 *  K4MemPatcher — Utils Header
 *  File: Utils.hpp
 *
 *  Visibility: internal
 *
 *  Description: Defines quick utilities used throughout the library.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <vector>

#include <Windows.h>

#include "../Aliases.hpp"
#include "../Types.hpp"

#include "Constants.hpp"

namespace K4MemPatcher::Detail::Utils {
    // Validates two ranges:
    // - Ensures each range's starting point is not greater or equal to its ending point.
    // - Checks that the ranges do not overlap.
    [[nodiscard]]
    inline bool areRangesValid(const Range& firstRange, const Range& secondRange) noexcept {
        if (!firstRange || !secondRange)
            return false; // Starting points are greater or equal to the ending ones

        if (firstRange.start <= secondRange.end && secondRange.start <= firstRange.end)
            return false; // Ranges overlap

        return true;
    }

    // Computes the absolute distance between two addresses
    [[nodiscard]]
    inline Distance getDistance(Address a, Address b) noexcept {
        return (a > b) ? (a - b) : (b - a);
    }

    // Checks whether a bytes compounds a short jump (any condition)
    [[nodiscard]]
    inline constexpr bool isByteShortJump(Byte byte) noexcept {
        return byte == Opcode::JMP_REL8 || (byte >= 0x70 && byte <= 0x7F);
    }

    // Checks whether two bytes compound a relative jump
    [[nodiscard]]
    inline constexpr bool areBytesRelativeConditionalJump(Byte firstByte, Byte secondByte) noexcept {
        return firstByte == 0x0F && (secondByte >= 0x80 && secondByte <= 0x8F);
    }

    // Checks whether a byte compounds a loop (any condition)
    inline constexpr bool isByteLoop(Byte byte) noexcept {
        return byte == Opcode::LOOP_CX || byte == Opcode::LOOP_E || byte == Opcode::LOOP_NE;
    }

    // Inserts the bytes of a value to the specified address
    template <typename T>
    inline void addBytesToAddressFromValue(Address address, T value) noexcept {
        std::memcpy(address.as<void*>(), &value, sizeof(T));
    }

    // Inserts the bytes of an address to the buffer
    inline void addBytesToBufferFromAddress(ByteBuffer& v, Address address, ByteCount len) {
        const Byte* const ptr = address.as<const Byte*>();
        v.insert(v.end(), ptr, ptr + len);
    }

    // Takes an enum and returns its index
    template <typename E>
    [[nodiscard]]
    inline constexpr Size toIndex(E value) noexcept {
        static_assert(std::is_enum_v<E>, "E must be an enum");
        return static_cast<Size>(value);
    }

    // Validates if a memory page is committed
    [[nodiscard]]
    inline bool isMemoryCommitted(const MEMORY_BASIC_INFORMATION& mbi) noexcept {
        return mbi.State == MEM_COMMIT;
    }
    
    // Validates if a memory page is guarded
    [[nodiscard]]
    inline bool isMemoryGuarded(const MEMORY_BASIC_INFORMATION& mbi) noexcept {
        return mbi.Protect & PAGE_GUARD;
    }

    // Validates if a memory page is not accessible at all
    [[nodiscard]]
    inline bool isNoAccessPage(const MEMORY_BASIC_INFORMATION& mbi) noexcept {
        return mbi.Protect == PAGE_NOACCESS;
    }

    // Validates if a memory page is committed, not guarded and accessible
    [[nodiscard]]
    inline bool isMemorySafe(LPCVOID lpAddress, MEMORY_BASIC_INFORMATION& mbi) noexcept {
        if (!VirtualQuery(lpAddress, &mbi, sizeof(mbi)))
            return false;

        return isMemoryCommitted(mbi) && !isMemoryGuarded(mbi) && !isNoAccessPage(mbi);
    }

    // Validates if a memory page is accessible for read operations
    [[nodiscard]]
    inline bool isMemoryReadable(LPCVOID lpAddress, MEMORY_BASIC_INFORMATION& mbi) noexcept {
        if (!isMemorySafe(lpAddress, mbi))
            return false;

        const DWORD readable
        {
            PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY |
            0
        };

        return (mbi.Protect & readable) == mbi.Protect;
    }

    // Inserts the bytes of a value to a byte array
    template <typename T, Size N>
    inline void addBytesToArrayFromValue(ByteArray<N>& v, Size startIndex, T value) noexcept {
        static_assert(std::is_trivially_copyable_v<T>);

        addBytesToAddressFromValue(&v[startIndex], value);
    }

    // Inserts the bytes of a value to a byte array
    // Specialized version when the value is Address type
    template <Size N>
    inline void addBytesToArrayFromValue(ByteArray<N>& v, Size startIndex, Address value) noexcept {
        addBytesToArrayFromValue(v, startIndex, value.get());
    }

    // Inserts elements to a byte array
    template <typename... Args, Size N>
    inline void addElementsToArray(ByteArray<N>& v, Size startIndex, Args... args) noexcept {
        Size currentOffset{ startIndex };

        ((
            addBytesToArrayFromValue(v, currentOffset, args),
            currentOffset += sizeof(args)
        ), ...);
    }

    // Checks if a number fits inside the range of a data type
    template <typename T, typename U>
    [[nodiscard]]
    inline constexpr bool isInRange(U n) noexcept {
        return n >= Limit::min<T> && n <= Limit::max<T>;
    }

    // Returns the size of a relative jump given its condition
    // rel32 JMP = 5
    // rel32 JCC = 6
    template <JmpCondition jumpCond>
    [[nodiscard]]
    inline constexpr Size getRelativeJmpSize() noexcept {
        if constexpr (jumpCond == JmpCondition::Unconditional)
            return InstructionSize::JMP_REL32;

        return InstructionSize::JCC_REL32;
    }

    // Removes duplicates from a vector
    template <typename T>
    inline void removeDuplicates(std::vector<T>& v) {
        std::unordered_set<Address> seen;
        v.erase(
            std::remove_if(v.begin(), v.end(),
                [&](const Address& value) {
                    return !seen.insert(value).second;
                }),
            v.end()
        );
    }

    // Sorts a vector in ascending order
    // The vector must contain items that behave like scalars and be sorted
    template <typename T>
    inline void sortVector(std::vector<T>& v) {
        static_assert(std::totally_ordered<T>, "T must behave like a scalar and be sorted");
        std::sort(v.begin(), v.end());
    }
}