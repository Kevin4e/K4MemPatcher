#pragma once

/*
 *  K4MemPatcher — Raw Header
 *  File: Raw.hpp
 *
 *  Visibility: internal
 *
 *  Description: Defines memory patching utilities without safety checks (except for JMP and CALL instructions)
 * 
 *  Note to the user: Use the functions inside of this header if you're sure of what you're doing.
 */

#include <cstring>

#ifndef K4MP_NO_MUTEX
#include <mutex>
#endif

#include "Constants.hpp"
#include "Helpers.hpp"
#include "Maps.hpp"
#include "Misc.hpp"
#include "Utils.hpp"

#include "../Aliases.hpp"
#include "../Enums.hpp"
#include "../Types.hpp"

namespace K4MemPatcher::Detail::Raw {
    template <typename T>
    [[nodiscard]]
    inline T readFromAddress(Address address) noexcept {
        T value;
        std::memcpy(&value, address.as<const void*>(), sizeof(T));
        return value;
    }

    // Writes a sequence of raw bytes to a memory address, repeated 'count' times consecutively.
    inline Result writeRawBytes(Address address, const Byte* bytes, Size len, Size count = 1) noexcept {
        if (len == 0 || count == 0)
            return Result::Success;

        // Overflow check
        if (len > Limit::max<Size> / count)
            return Result::InvalidRange;

        const ByteCount totalBytes{ len * count };

        #ifndef K4MP_NO_MUTEX
            std::lock_guard<std::mutex> lock(getMutex());
        #endif

        const PageWriteGuard guard{ address, totalBytes };

        if (!guard) return Result::ProtectionChangeFailed;

        Byte* ptrAddr{ address.as<Byte*>() };

        if (len == 1)
            std::memset(ptrAddr, bytes[0], count);

        else if (count == 1)
            std::memcpy(ptrAddr, bytes, len);

        else {
            for (Size i{0}; i < count; ++i) {
                std::memcpy(ptrAddr, bytes, len); // Patches and shifts
                ptrAddr += len;
            }
        }

        return Result::Success;
    }

    // Writes a byte buffer to a memory address, repeated 'count' times consecutively.
    inline Result writeByteBuffer(Address address, const ByteBuffer& bytes, Size count = 1) noexcept {
        return writeRawBytes(address, bytes.data(), bytes.size(), count);
    }

    // Writes a byte array to a memory address, repeated 'count' times consecutively.
    template <Size N>
    inline Result writeByteArray(Address address, const ByteArray<N>& bytes, Size count = 1) noexcept {
        return writeRawBytes(address, bytes.data(), N, count);
    }

    // Writes a single byte to a memory address, repeated 'count' times consecutively.
    inline Result writeByte(Address address, Byte byte, Size count = 1) noexcept {
        return writeRawBytes(address, &byte, 1, count);
    }

    // Creates a short jump from an address to another one.
    // The distance between the two addresses must be within +/- 128 bytes.
    template <JmpCondition jumpCond = JmpCondition::Unconditional>
    inline Result makeShortJMP(
        Address from,
        Address to,
        bool    validateMemory = false,
        bool    checkDistance = true
    ) noexcept
    {
        constexpr Size jmpSize{ InstructionSize::JMP_REL8 };

        if (validateMemory && !Helpers::isWritingSafe(from, jmpSize))
            return Result::UnsafeMemory;

        constexpr Size jumpCondIndex{ Utils::toIndex(jumpCond) };

        if (jumpCondIndex >= JMP_COND_ENUM_SIZE) return Result::InvalidJump;

        ByteArray<jmpSize> patch;

        const Result r{ Helpers::buildShortPatch(from, to, shortJumpsMap[jumpCondIndex], patch, checkDistance) };

        if (r != Result::Success) return r;

        return writeByteArray(from, patch);
    }

    // Creates a relative jump from an address to another one.
    // The distance between the two addresses must be within +/- 2GiB (≈ 2GB).
    template <JmpCondition jumpCond = JmpCondition::Unconditional>
    inline Result makeRelativeJMP(
        Address from,
        Address to,
        bool    validateMemory = false,
        bool    checkDistance = true
    ) noexcept
    {
        static_assert(jumpCond != JmpCondition::EqualCXZero, "JECXZ cannot be used for rel32 jumps.");

        constexpr Size jmpSize{ Utils::getRelativeJmpSize<jumpCond>() }; // unconditional rel32 jump size = 5; conditional rel32 jump size = 6

        if (validateMemory && !Helpers::isWritingSafe(from, jmpSize))
            return Result::UnsafeMemory;

        constexpr Size jumpCondIndex{ Utils::toIndex(jumpCond) };

        if (jumpCondIndex >= JMP_COND_ENUM_SIZE) return Result::InvalidJump;

        ByteArray<jmpSize> patch{};

        const Result r{ Helpers::buildRelativePatch(from, to, relativeJumpsMap[jumpCondIndex], patch, checkDistance) };

        if (r != Result::Success) return r;

        return writeByteArray(from, patch);
    }

    // Creates an absolute jump from an address to another one using the RAX register.
    // The distance between the two addresses is irrelevant.
    inline Result makeAbsoluteJMP(
        Address from,
        Address to,
        bool    validateMemory = false
    ) noexcept
    {
        constexpr Size jmpSize{ InstructionSize::JMP_ABS };

        if (validateMemory && !Helpers::isWritingSafe(from, jmpSize))
            return Result::UnsafeMemory;

        ByteArray<jmpSize> patch{};

        Helpers::buildAbsolutePatch(to, Opcode::JMP_RAX_MODRM, patch);

        return writeByteArray(from, patch);
    }

    // Writes a relative call from an address to another one.
    // The distance between the two addresses must be within +/- 2GiB (≈ 2GB).
    inline Result makeRelativeCALL(
        Address from,
        Address to,
        bool    validateMemory = false,
        bool    checkDistance = true
    ) noexcept
    {
        constexpr Size callSize{ InstructionSize::CALL_REL32 };

        if (validateMemory && !Helpers::isWritingSafe(from, callSize))
            return Result::UnsafeMemory;

        ByteArray<callSize> patch{};

        const Result r{ Helpers::buildRelativePatch(from, to, { Opcode::CALL_REL32, 0x00 }, patch, checkDistance) };

        if (r != Result::Success) return r;

        return writeByteArray(from, patch);
    }

    // Writes an absolute call from an address to another one using the RAX register.
    // The distance between the two addresses is irrelevant.
    inline Result makeAbsoluteCALL(
        Address from,
        Address to,
        bool    validateMemory = false
    ) noexcept
    {
        constexpr Size callSize{ InstructionSize::CALL_ABS };

        if (validateMemory && !Helpers::isWritingSafe(from, callSize))
            return Result::UnsafeMemory;

        ByteArray<callSize> patch{};

        Helpers::buildAbsolutePatch(to, Opcode::CALL_RAX_MODRM, patch);

        return writeByteArray(from, patch);
    }

    /*  Writes an instruction whose operand is a register. It can be:

         - PUSH
         - POP
         - INC
         - DEC
         - NEG
         - NOT

        All distinct based on the opcode passed to 'baseOpcode' argument
     */
    template <Register reg>
    inline Result makeRegInstruction(Address address, Byte baseOpcode, Size count = 1) {
        constexpr Size regIndex{ Utils::toIndex(reg) };

        if constexpr (regIndex >= REG_ENUM_SIZE)
            return Result::InvalidRegister;

        const Byte opcode{ baseOpcode + (regIndex % 8) };

        if constexpr (regIndex < 8) { // AX-DI
            if (baseOpcode == Opcode::PUSH_REG || baseOpcode == Opcode::POP_REG) // PUSH/POP
                return writeByteArray<2>(address, { 0x66, opcode }, count);

            else if (baseOpcode == Opcode::MODRM_NEG_REG_BASE || baseOpcode == Opcode::MODRM_NOT_REG_BASE) // NEG/NOT
                return writeByteArray<3>(address, { 0x66, 0xF7, opcode }, count);

            else
                return writeByteArray<3>(address, { 0x66, 0xFF, opcode }, count); // INC/DEC
        }

        else if constexpr (regIndex < 16) { // EAX-EDI
            if (baseOpcode == Opcode::PUSH_REG || baseOpcode == Opcode::POP_REG) // PUSH/POP
                return writeByte(address, opcode, count);

            else if (baseOpcode == Opcode::MODRM_NEG_REG_BASE || baseOpcode == Opcode::MODRM_NOT_REG_BASE) // NEG/NOT
                return writeByteArray<2>(address, { 0xF7, opcode }, count);

            else
                return writeByteArray<2>(address, { 0xFF, opcode }, count); // INC/DEC
        }

        else if constexpr (regIndex < 24) { // RAX-RDI
            if (baseOpcode == Opcode::PUSH_REG || baseOpcode == Opcode::POP_REG) // PUSH/POP
                return writeByte(address, opcode, count);

            else if (baseOpcode == Opcode::MODRM_NEG_REG_BASE || baseOpcode == Opcode::MODRM_NOT_REG_BASE) // NEG/NOT
                return writeByteArray<3>(address, { Opcode::REX_W, 0xF7, opcode }, count);

            else
                return writeByteArray<3>(address, { Opcode::REX_W, 0xFF, opcode }, count); // INC/DEC
        }

        else { // R8-R15
            if (baseOpcode == Opcode::PUSH_REG || baseOpcode == Opcode::POP_REG) // PUSH/POP
                return writeByteArray<2>(address, { Opcode::REX_B, opcode }, count);

            else if (baseOpcode == Opcode::MODRM_NEG_REG_BASE || baseOpcode == Opcode::MODRM_NOT_REG_BASE) // NEG/NOT
                return writeByteArray<3>(address, { Opcode::REX_W, 0xF7, opcode }, count);

            else
                return writeByteArray<3>(address, { Opcode::REX_WB, 0xFF, opcode }, count); // INC/DEC
        }
    }

    // Finds a pattern at a specific pointer.
    // If found, returns the address, else 0
    [[nodiscard]]
    inline Address findPatternAt(
        const Byte* current,
        const ByteBuffer& bytesPattern,
        const WildcardMask& wildcard
    ) noexcept
    {
        bool isEqual{ true };

        for (Size i{ 0 }; i < bytesPattern.size(); ++i) {
            if (!wildcard[i] && bytesPattern[i] != current[i]) { // If not a wildcard and unequal
                isEqual = false;
                break;
            }
        }

        return isEqual ?
            current : Address{};
    }

    // Finds a branch at a specific pointer and advances it.
    // If found, returns the address, else 0
    inline Address findBranchAt(
        const Byte*& current,
        const BranchInfo& branchInfo,
        const Byte* const scanEnd
    ) noexcept
    {
        const Address target{ branchInfo.target };
        const Branch branchTypeToFind{ branchInfo.type };

        const Byte firstByte{ *current };

        Size instrSize{ 1 };
        Address address{ nullptr };

        if (branchTypeToFind == Branch::Jump || branchTypeToFind == Branch::Any) { // If it's a jump (any)
            if (Utils::isByteShortJump(firstByte) && current < scanEnd - 1) { // Short
                instrSize = InstructionSize::JMP_REL8;

                const Rel8 relOffset{ readFromAddress<Rel8>(current + 1) };

                if (target == current + relOffset + instrSize)
                    address = current;
            }
            else if (firstByte == Opcode::JMP_REL32 && current < scanEnd - 4) { // Relative (unconditional)
                instrSize = InstructionSize::JMP_REL32;

                const Rel32 relOffset{ readFromAddress<Rel32>(current + 1) };

                if (target == current + relOffset + instrSize)
                    address = current;
            }
            else if (Utils::areBytesRelativeConditionalJump(firstByte, current[1]) && current < scanEnd - 5) { // Relative (conditional)
                instrSize = InstructionSize::JCC_REL32;

                const Rel32 relOffset{ readFromAddress<Rel32>(current + 2) };

                if (target == current + relOffset + instrSize)
                    address = current;
            }
        }
        else if (firstByte == Opcode::CALL_REL32 && (branchTypeToFind == Branch::Call || branchTypeToFind == Branch::Any) && current < scanEnd - 4) {
            instrSize = InstructionSize::CALL_REL32;

            const Rel32 relOffset{ readFromAddress<Rel32>(current + 1) };

            if (target == current + relOffset + instrSize)
                address = current;
        }
        else if (Utils::isByteLoop(firstByte) && (branchTypeToFind == Branch::Loop || branchTypeToFind == Branch::Any) && current < scanEnd - 1) {
            instrSize = InstructionSize::LOOP;

            const Rel8 relOffset{ readFromAddress<Rel8>(current + 1) };

            if (target == current + relOffset + instrSize)
                address = current;
        }

        current += instrSize;

        return address;
    }

    [[nodiscard]]
    inline Address findRetFunctionAt(
        const Byte* current,
        const ModuleBounds& mb
    ) noexcept
    {
        if (*current != Opcode::CALL_REL32)
            return {}; // Not a CALL rel32

        const Rel32 relOffset{ Raw::readFromAddress<Rel32>(current + 1) };
        const Address function{ current + relOffset + InstructionSize::CALL_REL32 };

        if (!mb.isInRange(function))
            return {}; // Function not inside the module

        if (Raw::readFromAddress<Byte>(function) == Opcode::RET_NEAR)
            return function;

        return {}; // Function doesn't start with ret
    }
}