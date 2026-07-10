#pragma once

/*
 *  K4MemPatcher — Aliases Header
 *  File: Aliases.hpp
 *
 *  Visibility: public
 *
 *  Description: Defines aliases for existing types.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <Windows.h>

namespace K4MemPatcher {
    struct Address; // Forward declaration

    // Integer types
    using Int8 = std::int8_t;
    using UInt8 = std::uint8_t;
    using Int16 = std::int16_t;
    using UInt16 = std::uint16_t;
    using Int32 = std::int32_t;
    using UInt32 = std::uint32_t;
    using Int64 = std::int64_t;
    using UInt64 = std::uint64_t;

    // Relative offsets
    using Rel8 = std::int8_t;
    using Rel32 = std::int32_t;

    // Semantic instruction operand types
    using StackAdjustment = std::uint16_t;
    using Interrupt = std::uint8_t;

    // Memory primitives
    using Byte = UInt8;
    using RawAddr = std::uintptr_t;
    using Distance = std::int64_t;

    // Sizing
    using Size = std::size_t;
    using ByteCount = std::size_t;
    using InstructionCount = std::size_t;

    // Collections
    using Addresses = std::vector<Address>;
    using ByteBuffer = std::vector<Byte>;
    using WildcardMask = std::vector<bool>;

    template <Size N>
    using ByteArray = std::array<Byte, N>;

    // Win32 isolation
    using ModuleName = LPCSTR;
}