#pragma once

/*
 *  K4MemPatcher — Miscellaneous Header
 *  File: Misc.hpp
 *
 *  Visibility: internal
 *
 *  Description: Defines tools and other types used throughout the library.
 */

#include <cstddef>
#include <cstdint>

#ifndef K4MP_NO_MUTEX
#include <mutex>
#endif

#include <Windows.h>

#include "../Aliases.hpp"
#include "../Enums.hpp"
#include "../Types.hpp"

namespace K4MemPatcher::Detail {
    #ifndef K4MP_NO_MUTEX
        inline std::mutex& getMutex() noexcept {
            static std::mutex mtx;
            return mtx;
        }
    #endif

    class [[nodiscard]] PageWriteGuard {
    private:
        const LPVOID pAddress{};
        const SIZE_T len{};
        const bool flushICache{};
        DWORD oldProtection{};
        const BOOL protectionChangeSucceeded{};

    public:
        // Changes the protection of the page.
        // By default, the new protection is set to make the page writeable (PAGE_EXECUTE_READWRITE)
        PageWriteGuard(
            Address address,
            SIZE_T len,
            bool flushICache = true,
            DWORD newProtection = PAGE_EXECUTE_READWRITE
        ) noexcept :
            pAddress{address.as<LPVOID>()},
            len{len},
            flushICache{flushICache},
            protectionChangeSucceeded{VirtualProtect(pAddress, len, newProtection, &oldProtection)}
        {}

        // Flushes instruction cache if needed and restores original protection when the guard goes out of scope
        ~PageWriteGuard() noexcept {
            if (protectionChangeSucceeded) {
                if (flushICache)
                    // Flush instruction cache to ensure CPU fetches the updated instructions, recommended after writing new bytes into code memory
                    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(pAddress), len);

                // Restore original protection
                VirtualProtect(pAddress, len, oldProtection, &oldProtection);
            }
        }

        explicit operator bool() const noexcept {
            return protectionChangeSucceeded;
        }
    };

    template <typename OffsetT>
    struct OffsetResult {
        OffsetT offset{};
        Result result{};

        constexpr OffsetResult() noexcept = default;

        constexpr OffsetResult(OffsetT offset, Result result) noexcept
            : offset{offset}, result{result} {}
    };

    struct ModuleBounds {
        Address base{};
        Address end{};
        
        constexpr ModuleBounds() noexcept = default;

        constexpr ModuleBounds(Address base, Address end) noexcept
            : base{base}, end{end} {}

        explicit constexpr operator bool() const noexcept {
            return base && end && base <= end;
        }

        constexpr Size size() const noexcept {
            return *this ? end - base : 0;
        }

        constexpr bool isInRange(Address addr) const noexcept {
            return addr >= base && addr <= end;
        }
    };

    struct PatternParsingResult {
        ByteBuffer bytes{};
        WildcardMask wildcard{};

        constexpr PatternParsingResult() noexcept = default;

        constexpr PatternParsingResult(ByteBuffer bytes, WildcardMask wildcard) noexcept
            : bytes{bytes}, wildcard{wildcard} {}

        explicit constexpr operator bool() const noexcept {
            return !bytes.empty() && !wildcard.empty();
        }
    };

    struct ScanWindow {
        const Byte* const start{};
        const Byte* const end{};

        constexpr ScanWindow() noexcept = default;

        ScanWindow(Address start, Address end, Distance offset = 0) noexcept :
            start{ start.as<const Byte*>() },
            end{ end.as<const Byte*>() - offset }
        {}
    };
};