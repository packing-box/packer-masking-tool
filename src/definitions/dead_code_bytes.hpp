#ifndef DEAD_CODE_BYTES_HPP
#define DEAD_CODE_BYTES_HPP

#include <vector>

const std::vector<std::vector<uint8_t>> dead_code_bytes = {
    {0x90},                                                   // NOP
{0x33, 0xC0},                                                 // XOR EAX, EAX
{0x33, 0xC9},                                                 // XOR ECX, ECX
{0x33, 0xDB},                                                 // XOR EBX, EBX
{0x83, 0xC0, 0x00},                                           // ADD EAX, 0
{0x87, 0xC0},                                                 // XCHG EAX, EAX
{0x83, 0xE9, 0x00},                                           // SUB ECX, 0
{0x89, 0xC2},                                                 // MOV EDX, EDX
{0x50, 0x58},                                                 // PUSH EAX + POP EAX
{0x8D, 0x1B},                                                 // LEA EBX, [EBX] (load effective address of EBX into EBX)
// ADD EDI, 1 + SUB EDI, 1
{0x81, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x81, 0xEF, 0x01, 0x00, 0x00, 0x00},  
{0x81, 0xE6, 0xFF, 0xFF, 0xFF, 0xFF},                         // AND ESI, 0xFFFFFFFF (bitwise AND with immediate value)
{0x83, 0xCA, 0x00},                                           // OR EDX, 0 (bitwise OR with immediate value)
{0xEB, 0x00},                                                 // JMP SHORT $+2 (jump short 2 bytes, same as NOP)
{0x33, 0xD2},                                                 // XOR EDX, EDX
{0xD1, 0xC0},                                                 // ROL EAX, 1 (rotate left)
{0x50, 0x58},                                                 // PUSH EAX + POP EAX
{0x05, 0x01, 0x00, 0x00, 0x00, 0x2D, 0x01, 0x00, 0x00, 0x00}, // ADD EAX, 1 + SUB EAX, 1
{0xF9, 0xF8},                                                 // STC + CLC (set carry flag + clear carry flag)
{0x89, 0xC1, 0x89, 0xC8},                                     // MOV ECX, EAX + MOV EAX, ECX
{0x8D, 0x80, 0x00, 0x00, 0x00, 0x00},                         // LEA EAX, [EAX]
{0x83, 0xC8, 0x00},                                           // OR EAX, 0
{0xEB, 0x00, 0x90},                                           // JMP SHORT 2 bytes over NOP
{0x50, 0x48, 0x89, 0xC1, 0x40, 0x58}                          // PUSH EAX + DEC EAX + MOV ECX, EAX + INC EAX + POP EAX
};

// 64-bit equivalents. The 32-bit table above must NOT be used on AMD64 targets:
// bytes such as 0x48 and 0x40 are REX prefixes in 64-bit mode (not DEC/INC EAX),
// so reusing it would corrupt the trampoline. These are genuine identity/no-op
// sequences that leave registers and the stack unchanged.
const std::vector<std::vector<uint8_t>> dead_code_bytes_64 = {
    {0x90},                               // NOP
    {0x66, 0x90},                         // 66 NOP (2-byte NOP)
    {0x0F, 0x1F, 0x00},                   // NOP dword ptr [rax]
    {0x0F, 0x1F, 0x40, 0x00},             // NOP dword ptr [rax+0x00]
    {0x0F, 0x1F, 0x44, 0x00, 0x00},       // NOP dword ptr [rax+rax*1+0x00]
    {0x48, 0x87, 0xC0},                   // XCHG RAX, RAX
    {0x48, 0x89, 0xC0},                   // MOV RAX, RAX
    {0x48, 0x8D, 0x00},                   // LEA RAX, [RAX]
    {0xEB, 0x00},                         // JMP SHORT $+2 (same as NOP)
    {0x50, 0x58},                         // PUSH RAX + POP RAX
    {0x51, 0x59},                         // PUSH RCX + POP RCX
    {0x48, 0x83, 0xC0, 0x00},             // ADD RAX, 0
    {0x48, 0x83, 0xC8, 0x00},             // OR RAX, 0
    {0x48, 0x83, 0xE8, 0x00},             // SUB RAX, 0
    {0x90, 0x90}                          // NOP + NOP
};

#endif // DEAD_CODE_BYTES_HPP
