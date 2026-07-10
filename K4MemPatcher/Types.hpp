#pragma once

/*
 *  K4MemPatcher — Types Header
 *  File: Types.hpp
 *
 *  Visibility: public
 *
 *  Description: Defines types for the public interface such as the 'Address' wrapper, stable pointers and ranges.
 */

#include <cstddef>
#include <iomanip>
#include <vector>

#include <Windows.h>

#include "Aliases.hpp"
#include "Enums.hpp"

namespace K4MemPatcher {
    class Address {
    private:
        RawAddr address{};
    public:
        // --- Constructors --- //
        constexpr Address() noexcept = default;

        constexpr Address(RawAddr address) noexcept
            : address{address} {}

        Address(void* ptr) noexcept
            : address{reinterpret_cast<RawAddr>(ptr)} {}

        Address(const void* ptr) noexcept
            : address{reinterpret_cast<RawAddr>(ptr)} {}

        template <typename Func>
        Address(Func* funcPtr) noexcept
            : address{reinterpret_cast<RawAddr>(funcPtr)} {}

        constexpr Address(std::nullptr_t) noexcept
            : address{0} {}

        // --- Named Accessors --- //

        template <typename T>
        T as() const noexcept {
            return reinterpret_cast<T>(address);
        }

        RawAddr get() const noexcept {
            return address;
        }

        // --- Operators Overloading --- //
        constexpr bool operator == (Address other) const noexcept { return address == other.address; }
        constexpr bool operator != (Address other) const noexcept { return address != other.address; }
        constexpr bool operator >  (Address other) const noexcept { return address >  other.address; }
        constexpr bool operator >= (Address other) const noexcept { return address >= other.address; }
        constexpr bool operator <  (Address other) const noexcept { return address <  other.address; }
        constexpr bool operator <= (Address other) const noexcept { return address <= other.address; }

        constexpr bool operator == (RawAddr addr) const noexcept { return address == addr; }
        constexpr bool operator >  (RawAddr addr) const noexcept { return address >  addr; }
        constexpr bool operator >= (RawAddr addr) const noexcept { return address >= addr; }
        constexpr bool operator <  (RawAddr addr) const noexcept { return address <  addr; }
        constexpr bool operator <= (RawAddr addr) const noexcept { return address <= addr; }

        bool operator == (void* ptr) const noexcept { return as<void*>() == ptr; }
        bool operator >  (void* ptr) const noexcept { return as<void*>() >  ptr; }
        bool operator >= (void* ptr) const noexcept { return as<void*>() >= ptr; }
        bool operator <  (void* ptr) const noexcept { return as<void*>() <  ptr; }
        bool operator <= (void* ptr) const noexcept { return as<void*>() <= ptr; }

        bool operator == (const void* ptr) const noexcept { return as<const void*>() == ptr; }
        bool operator >  (const void* ptr) const noexcept { return as<const void*>() >  ptr; }
        bool operator >= (const void* ptr) const noexcept { return as<const void*>() >= ptr; }
        bool operator <  (const void* ptr) const noexcept { return as<const void*>() <  ptr; }
        bool operator <= (const void* ptr) const noexcept { return as<const void*>() <= ptr; }

        // operator (RawAddr) //
        constexpr Address& operator=(RawAddr addr) noexcept {
            address = addr;
            return *this;
        }
        constexpr Address operator+(RawAddr offset) const noexcept {
            return Address(address + offset);
        }
        constexpr Address operator-(RawAddr offset) const noexcept {
            return Address(address - offset);
        }
        constexpr Address& operator+=(RawAddr offset) noexcept {
            address += offset;
            return *this;
        }
        constexpr Address& operator-=(RawAddr offset) noexcept {
            address -= offset;
            return *this;
        }

        // operator (Address) //
        constexpr Address& operator=(Address other) noexcept {
            address = other.address;
            return *this;
        }

        constexpr Int64 operator-(Address other) const noexcept {
            return address - other.address;
        }

        constexpr Address& operator++() noexcept {
            ++address;
            return *this;
        }
        
        friend std::ostream& operator<<(std::ostream& os, Address addr) {
            return os << std::hex << addr.address;
        }

        explicit constexpr operator bool() const noexcept { return address != 0; }
    };

    class StablePtr {
    private:
        std::vector<Distance> offsets{};
        bool alwaysResolve{};
        Address baseAddress{};

        bool isResolved{false};
        Address stablePtr{};

        Size nOffsetsRequired{};

    public:
        StablePtr(Address baseAddress, const std::vector<Distance>& offsets, bool alwaysResolve = true) :
            offsets{offsets},
            alwaysResolve{alwaysResolve},
            baseAddress{baseAddress},
            nOffsetsRequired{offsets.size() == 0 ? 0 : offsets.size() - 1}
        {}

        StablePtr(ModuleName moduleName, const std::vector<Distance>& offsets, bool alwaysResolve = true)
            : StablePtr(Address(GetModuleHandleA(moduleName)), offsets, alwaysResolve)
        {}

        StablePtr(const std::vector<Distance>& offsets, bool alwaysResolve = true)
            : StablePtr(nullptr, offsets, alwaysResolve)
        {}

        Address Resolve() noexcept {
            if (nOffsetsRequired == 0)
                return baseAddress;

            if (!alwaysResolve && isResolved)
                return stablePtr; // Return cached pointer if it was already resolved and it doesn't have to resolved every time

            stablePtr = baseAddress; // Start from the base address

            for (Size i{0}; i < nOffsetsRequired; ++i) {
                const Address currentAddress{ stablePtr + offsets[i] };

                const RawAddr valueRead{ *currentAddress.as<const RawAddr*>() };

                if (!valueRead)
                    return {};

                stablePtr = Address(valueRead);
            }

            stablePtr += offsets.back();

            isResolved = true;

            return stablePtr;
        }

        explicit operator bool() const noexcept {
            return isResolved;
        }
    };

    struct Range {
        Address start{};
        Address end{};

        constexpr Range() noexcept = default;

        constexpr Range(Address start, Address end) noexcept
            : start{start}, end{end} {}

        explicit constexpr operator bool() const noexcept {
            return start < end;
        }

        constexpr Size size() const noexcept {
            return *this ? end - start : 0;
        }

        constexpr bool operator==(const Range& other) const noexcept {
            return start == other.start && end == other.end;
        }
    };

    struct BranchInfo {
        Address target{};
        Branch type{ Branch::Any };

        constexpr BranchInfo() noexcept = default;

        constexpr BranchInfo(Address target) noexcept
            : target{target} {}

        constexpr BranchInfo(Address target, Branch type) noexcept
            : target{target}, type{type} {}
    };
}

namespace std {
    // Hash specialization(s)

    // Address
    template <>
    struct hash<K4MemPatcher::Address> {
        size_t operator()(const K4MemPatcher::Address& a) const noexcept {
            return std::hash<K4MemPatcher::RawAddr>{}(a.get());
        }
    };
}