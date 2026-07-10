#pragma once

/*
 *  K4MemPatcher — Enums Header
 *  File: Enums.hpp
 *
 *  Visibility: public
 *
 *  Description: Defines enums to handle operations' results, jump conditions, registers, and branches.
 */

#include "Aliases.hpp"

namespace K4MemPatcher {
    enum class Result : Int8 {
        Success,
        ProtectionChangeFailed,
        InvalidRange,
        TooFarDistance,
        InvalidJump,
        InvalidLoop,
        InvalidRegister,
        InvalidOperand,
        UnsafeMemory
    };

    enum class JmpCondition : Int8 {
        Unconditional,  // JMP
        Above,          // JA  = JNBE (NotBelowOrEqual)
        AboveOrEqual,   // JAE = JNB  (NotBelow) = JNC (NotCarry)
        Below,          // JB  = JNAE (NotAboveOrEqual)
        BelowOrEqual,   // JBE = JNA  (NotAbove)
        Carry,          // JC
        Equal,          // JE  = JZ   (Zero)
        EqualCXZero,    // JECXZ
        Greater,        // JG  = JNLE (NotLessOrEqual)
        GreaterOrEqual, // JGE = JNL  (NotLess)
        Less,           // JL  = JNGE (NotGreaterOrEqual)
        LessOrEqual,    // JLE = JNG  (NotGreater)
        NotEqual,       // JNE = JNZ  (NotZero)        
        NotOverflow,    // JNO
        NotParity,      // JNP = JPO  (ParityOdd)
        NotSign,        // JNS
        Overflow,       // JO
        Parity,         // JP  = JPE  (ParityEven)
        Sign,           // JS

        Count           // Number of jumps
    };

    enum class Register : Int8 {
        AX, CX, DX, BX, SP, BP, SI, DI,         // 16-bit

        EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, // 32-bit

        RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, // 64-bit

        R8, R9, R10, R11, R12, R13, R14, R15,   // Extended 64-bit

        Count // Number of registers
    };

    enum class Branch : Int8 {
        Any,
        Jump,
        Call,
        Loop,

        Count // Number of branches
    };

    enum class LoopCondition {
        CX,       // LOOP
        Equal,    // LOOPE
        NotEqual, // LOOPNE
        
        Count // Number of LOOPs
    };
}

namespace K4MemPatcher::Detail {
    inline constexpr Size JMP_COND_ENUM_SIZE = static_cast<Size>(JmpCondition::Count);
    inline constexpr Size REG_ENUM_SIZE = static_cast<Size>(Register::Count);
    inline constexpr Size BRANCH_ENUM_SIZE = static_cast<Size>(Branch::Count);
    inline constexpr Size LOOP_COND_ENUM_SIZE = static_cast<Size>(LoopCondition::Count);
}