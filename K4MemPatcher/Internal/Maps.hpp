#pragma once

/*
 *  K4MemPatcher — Maps Header
 *  File: Maps.hpp
 *
 *  Visibility: internal
 *
 *  Description: Defines short and relatives jumps map for O(1) lookup through array-indexing.
 */

#include <array>

#include "../Aliases.hpp"
#include "../Enums.hpp"

#include "Constants.hpp"

namespace K4MemPatcher::Detail {
    // Opcodes for all jumps (rel8)
    inline constexpr ByteArray<JMP_COND_ENUM_SIZE> shortJumpsMap = {
        0xEB,  /*  Unconditional  (JMP)    */
        0x77,  /*  Above          (JA)     */
        0x73,  /*  AboveOrEqual   (JAE)    */
        0x72,  /*  Below          (JB)     */
        0x76,  /*  BelowOrEqual   (JBE)    */
        0x72,  /*  Carry          (JC)     */
        0x74,  /*  Equal          (JE)     */
        0xE3,  /*  EqualCXZero    (JECXZ)  */
        0x7F,  /*  Greater        (JG)     */
        0x7D,  /*  GreaterOrEqual (JGE)    */
        0x7C,  /*  Less           (JL)     */
        0x7E,  /*  LessOrEqual    (JLE)    */
        0x75,  /*  NotEqual       (JNE)    */
        0x71,  /*  NotOverflow    (JNO)    */
        0x7B,  /*  NotParity      (JNP)    */
        0x79,  /*  NotSign        (JNS)    */
        0x70,  /*  Overflow       (JO)     */
        0x7A,  /*  Parity         (JP)     */
        0x78   /*  Sign           (JS)     */
    };

    // Opcodes for all jumps (rel32)
    inline constexpr std::array<ByteArray<2>, JMP_COND_ENUM_SIZE> relativeJumpsMap = { {
        {0xE9, 0x00},  /*  Unconditional  (JMP)  */
        {0x0F, 0x87},  /*  Above          (JA)   */
        {0x0F, 0x83},  /*  AboveOrEqual   (JAE)  */
        {0x0F, 0x82},  /*  Below          (JB)   */
        {0x0F, 0x86},  /*  BelowOrEqual   (JBE)  */
        {0x0F, 0x82},  /*  Carry          (JC)   */
        {0x0F, 0x84},  /*  Equal          (JE)   */
        {0x0F, 0x8F},  /*  Greater        (JG)   */
        {0x0F, 0x8D},  /*  GreaterOrEqual (JGE)  */
        {0x0F, 0x8C},  /*  Less           (JL)   */
        {0x0F, 0x8E},  /*  LessOrEqual    (JLE)  */
        {0x00, 0x00},  /*  --------------------- */
        {0x0F, 0x85},  /*  NotEqual       (JNE)  */
        {0x0F, 0x81},  /*  NotOverflow    (JNO)  */
        {0x0F, 0x8B},  /*  NotParity      (JNP)  */
        {0x0F, 0x89},  /*  NotSign        (JNS)  */
        {0x0F, 0x80},  /*  Overflow       (JO)   */
        {0x0F, 0x8A},  /*  Parity         (JP)   */
        {0x0F, 0x88}   /*  Sign           (JS)   */
    } };

    // Opcodes for all LOOPs
    inline constexpr ByteArray<LOOP_COND_ENUM_SIZE> LOOPsMap = {
        Opcode::LOOP_CX,
        Opcode::LOOP_E,
        Opcode::LOOP_NE
    };
}