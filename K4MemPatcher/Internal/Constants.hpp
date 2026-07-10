#pragma once

/*  
 *  K4MemPatcher — Constants Header
 *  File: Constants.hpp
 *  
 *  Visibility: internal
 * 
 *  Description: Defines opcodes and instructions sizes for internal memory patching operations.
 */

#include <limits>

#include "../Aliases.hpp"

namespace K4MemPatcher::Detail::Opcode {
    /* JMPs */
    constexpr Byte JMP_REL8{ 0xEB };
    constexpr Byte JMP_REL32{ 0xE9 };
    constexpr Byte JMP_RAX_MODRM{ 0xE0 };

    /* CALLs */
    constexpr Byte CALL_REL32{ 0xE8 };
    constexpr Byte CALL_RAX_MODRM{ 0xD0 };

    /* RETs */
    constexpr Byte RET_NEAR{ 0xC3 };
    constexpr Byte RET_IMM16{ 0xC2 };

    /* INTs */
    constexpr Byte INT3{ 0xCC };
    constexpr Byte INT_IMM8{ 0xCD };

    /* REX prefixes */
    constexpr Byte REX_B{ 0x41 };
    constexpr Byte REX_W{ 0x48 };
    constexpr Byte REX_WB{ 0x49 };

    /* PUSHs */
    constexpr Byte PUSH_IMM8{ 0x6A };
    constexpr Byte PUSH_IMM32{ 0x68 };
    constexpr Byte PUSH_REG{ 0x50 };

    /* POP */
    constexpr Byte POP_REG{ 0x58 };

    /* LOOPs */
    constexpr Byte LOOP_CX{ 0xE2 };
    constexpr Byte LOOP_NE{ 0xE0 };
    constexpr Byte LOOP_E{ 0xE1 };

    /* Others */
    constexpr Byte NOP{ 0x90 };
    constexpr Byte MOV_RAX_IMM64{ 0xB8 };
    constexpr Byte INDIRECT_JMP_CALL{ 0xFF };
    constexpr Byte MODRM_INC_REG_BASE{ 0xC0 };
    constexpr Byte MODRM_DEC_REG_BASE{ 0xC8 };
    constexpr Byte MODRM_NOT_REG_BASE{ 0xD0 };
    constexpr Byte MODRM_NEG_REG_BASE{ 0xD8 };
}

namespace K4MemPatcher::Detail::InstructionSize {
    /* JMPs & JCC */
    constexpr Size JMP_REL8{ 2 };
    constexpr Size JMP_REL32{ 5 };
    constexpr Size JCC_REL32{ 6 };
    constexpr Size JMP_ABS{ 12 };

    /* CALLs */
    constexpr Size CALL_REL32{ 5 };
    constexpr Size CALL_ABS{ 12 };

    /* Others */
    constexpr Size RET_IMM16{ 3 };
    constexpr Size LOOP{ 2 };
    constexpr Size INT_IMM8{ 2 };
}

namespace K4MemPatcher::Detail::Limit {
    template <typename T>
    constexpr T min{ std::numeric_limits<T>::min() };

    template <typename T>
    constexpr T max{ std::numeric_limits<T>::max() };
}