'use strict';
const fs   = require('fs');
const path = require('path');
const E    = require('./encode-x64.js');
const { PE } = require('./pe-builder.js');

// ─── Fixed layout constants ───────────────────────────────────────────────────
const FUNCS      = ['ExitProcess','GetStdHandle','WriteFile','ReadFile',
                    'CreateFileA','GetFileSize','CloseHandle','VirtualAlloc'];
const TEXT_VS    = 0x4000;   // .text virtual size (must match ky-compiler.js)
const CODE_RVA   = 0x1000;   // .text base RVA
const IAT_BASE   = 0x5000;   // IAT base (= CODE_RVA + TEXT_VS)

// IAT entries for each API function
const IAT = {};
FUNCS.forEach((f, i) => { IAT[f] = IAT_BASE + i * 8; });

// ─── Build embedded PE template (0x8800 bytes) ───────────────────────────────
// This is what mini-kyc.exe copies into the output buffer when compiling a program.
const tplPE = new PE();
tplPE.subsys = 3;
tplPE.addImport('KERNEL32.dll', FUNCS);
tplPE.setCode(Buffer.alloc(TEXT_VS, 0x90));
tplPE.setData(Buffer.alloc(0x4000, 0));
const peBytes = tplPE.build();
const peHex   = peBytes.toString('hex');

// ─── Build startup code blob (68 bytes) ──────────────────────────────────────
// This is the x64 code emitted at the start of every compiled output program.
// It calls VirtualAlloc (state array = R15) and GetStdHandle (stdout = R14).
function buildStartup() {
  const b = new E.Buf();
  E.mov_ri(b, 1, 0n);           // mov rcx, 0  (lpAddress = NULL)
  E.mov_ri(b, 2, 0x20000n);     // mov rdx, 0x20000 (dwSize = 128KB)
  E.mov_ri(b, 8, 0x3000n);      // mov r8,  MEM_COMMIT|MEM_RESERVE
  E.mov_ri(b, 9, 0x40n);        // mov r9,  PAGE_EXECUTE_READWRITE
  const vaOff = b.tell();
  E.call_rip(b, IAT.VirtualAlloc - (CODE_RVA + vaOff + 6));
  E.mov_rr(b, 15, 0);           // mov r15, rax  (state array base)
  // Compute data section base and store in state_08
  const leaOff = b.tell();      // offset of the LEA instruction
  E.lea_rip(b, 0, 0x5000 - (CODE_RVA + leaOff + 7)); // lea rax, [rip + disp] -> data_base
  E.mov_mr64(b, 15, 8 * 8, 0); // mov [r15 + 64], rax = state_08 = data_base
  E.mov_ri(b, 1, -11n);         // mov rcx, STD_OUTPUT_HANDLE
  const gsOff = b.tell();
  E.call_rip(b, IAT.GetStdHandle - (CODE_RVA + gsOff + 6));
  E.mov_rr(b, 14, 0);           // mov r14, rax  (stdout handle)
  return b.b.slice(0, b.tell()); // 82 bytes
}
const startupBlob = buildStartup();
if (startupBlob.length !== 79) throw new Error('startup blob size changed: ' + startupBlob.length);

// Data section offsets (in mini-kyc.exe's 64KB data section)
const PE_BLOB_OFF      = 0x4000;  // embedded PE template
const STARTUP_BLOB_OFF = 0xCC00;  // startup code blob

// ─── KY source line builder ───────────────────────────────────────────────────
const lines = [];
const L  = s => lines.push(s);
const C  = s => lines.push('; ' + s);
const B  = ()  => lines.push('');

// KY instruction generators
const hx = (n, w) => n.toString(16).padStart(w || 2, '0');
const H    = n => '40 ' + hx(n);
const CH   = n => '41 ' + hx(n);
const JMP  = n => '70 ' + hx(n);
const JE   = n => '71 ' + hx(n);
const JNE  = n => '72 ' + hx(n);
const JBE  = n => '75 ' + hx(n);
const JB   = n => '77 ' + hx(n);
const JAE  = n => '78 ' + hx(n);
const JA   = n => '7A ' + hx(n);
const SET  = (s, v)    => '30 ' + hx(s) + ' ' + hx(v);
const GET  = (d, s)    => '60 ' + hx(d) + ' ' + hx(s);
const ADD  = (s, v)    => '61 ' + hx(s) + ' ' + hx(v);
const SUB  = (s, v)    => '62 ' + hx(s) + ' ' + hx(v);
const CMP  = (a, b)    => '65 ' + hx(a) + ' ' + hx(b);
const INC  = s         => '66 ' + hx(s);
const ADDV = (a, b)    => '68 ' + hx(a) + ' ' + hx(b);
const SUBV = (a, b)    => '69 ' + hx(a) + ' ' + hx(b);
const LDB  = (d, s, o) => '80 ' + hx(d) + ' ' + hx(s) + ' ' + hx(o || 0);
const RET  = ()        => 'FF';
const STR  = s         => '12 s' + Buffer.from(s + '\0', 'ascii').toString('hex');

// ════════════════════════════════════════════════════════════════════════════════
// KY SOURCE GENERATION
// ════════════════════════════════════════════════════════════════════════════════

C('mini-kyc.ky - Self-hosting KY compiler (Phase 1)');
C('Compiles .ky source -> Windows x64 PE executable');
C('Phase 1: handles opcodes 40 FF 30 60 65 66 70 71 41');
B();

// ── String definitions ────────────────────────────────────────────────────────
C('String definitions');
L(STR('input.ky'));   // string index 0
L(STR('output.exe')); // string index 1
B();

// ── Embedded PE template blob ─────────────────────────────────────────────────
C('Embedded PE template blob (' + peBytes.length + ' = 0x' + hx(peBytes.length, 4) + ' bytes)');
L('13 ' + hx(PE_BLOB_OFF, 4) + ' s' + peHex);
B();

// ── Startup code blob ─────────────────────────────────────────────────────────
C('Startup code blob (' + startupBlob.length + ' bytes at data offset 0x' + hx(STARTUP_BLOB_OFF, 4) + ')');
C('VirtualAlloc state array -> R15, GetStdHandle stdout -> R14');
L('13 ' + hx(STARTUP_BLOB_OFF, 4) + ' s' + startupBlob.toString('hex'));
B();

// ── Main operations (compiler initialization) ─────────────────────────────────
C('=== Compiler initialization ===');
C('Read input.ky -> state_0A (buffer ptr), state_0B (file size)');
L('50 0A 00');

C('Allocate 0x40000-byte output buffer -> state_02');
L('20 02 00040000');

C('Initialize scanner state variables');
L(SET(0x0E, 0)  + ' ; code_offset = 0');
L(GET(0x0C, 0x0A) + ' ; read_ptr = input_buf');
L(GET(0x0D, 0x0B) + ' ; end_ptr = file_size');
L(ADDV(0x0D, 0x0C) + ' ; end_ptr += read_ptr (= buf + size)');
L(SET(0x10, 0)  + ' ; scanner_state = 0');
L(SET(0x11, 0)  + ' ; acc = 0');
L(SET(0x12, 0)  + ' ; digit_count = 0');
L(SET(0x13, 0)  + ' ; opcode = 0');
L(SET(0x14, 0)  + ' ; arg_index = 0');
B();

C('Copy embedded PE template to output buffer');
L('84 02 ' + hx(PE_BLOB_OFF, 4) + ' 8800');
B();

C('=== H_30 emitter initialization ===');
C('Setup write base: state_03 = output_buf + 0x400 (= .text file offset)');
L(GET(0x03, 0x02));
L(ADD(0x03, 0x400));

C('Allocate handler offset table (256 entries x4 bytes = 1024) -> state_04');
L('20 04 400');

C('Allocate fixup hh array (max 256 fixups x4 bytes) -> state_05');
L('20 05 400');

C('Allocate fixup patch-position array -> state_06');
L('20 06 400');

C('Initialize emitter state: fixup_count=0, first_handler_flag=0');
L(SET(0x07, 0)  + ' ; fixup_count = 0');
L(SET(0x09, 0)  + ' ; first_handler_flag = 0');

C('Copy startup code (68 bytes) to output .text section (at offset 0)');
L(GET(0x4C, 0x03));
L('84 4C ' + hx(STARTUP_BLOB_OFF, 4) + ' 4F');
L(ADD(0x0E, 0x4F) + ' ; advance code_offset by 79 (startup size)');
B();

C('Run scanner -> emitter');
L(CH(1)  + ' ; call H_01 main scan loop');
C('Write output.exe');
L('51 02 01 0E');  // WriteFile: state_02 buffer, "output.exe", state_0E (write pos)
B();

// ════════════════════════════════════════════════════════════════════════════════
// SCANNER STATE MACHINE
// States: 0=looking for opcode, 1=accumulating opcode hex,
//         2=looking for arg, 3=accumulating arg hex,
//         4=string mode, 5=comment
// ════════════════════════════════════════════════════════════════════════════════
C('============================================================');
C('SCANNER');
C('============================================================');

// H_01: main loop
C('H_01: Main loop - read byte and dispatch by scanner state');
L(H(0x01));
L(CMP(0x0C, 0x0D));
L(JAE(0x1E) + '  ; EOF -> H_1E');
L(LDB(0x0F, 0x0C, 0) + ' ; read byte -> state_0F');
L(INC(0x0C)  + ' ; advance read ptr');
C('Dispatch by scanner state (state_10)');
L(GET(0x40, 0x10));
L(SET(0x41, 0)); L(CMP(0x40, 0x41)); L(JE(0x20) + ' ; state 0 -> H_20');
L(SET(0x41, 1)); L(CMP(0x40, 0x41)); L(JE(0x21) + ' ; state 1 -> H_21');
L(SET(0x41, 2)); L(CMP(0x40, 0x41)); L(JE(0x22) + ' ; state 2 -> H_22');
L(SET(0x41, 3)); L(CMP(0x40, 0x41)); L(JE(0x23) + ' ; state 3 -> H_23');
L(SET(0x41, 4)); L(CMP(0x40, 0x41)); L(JE(0x24) + ' ; state 4 -> H_24');
L(SET(0x41, 5)); L(CMP(0x40, 0x41)); L(JE(0x25) + ' ; state 5 -> H_25');
L(SET(0x10, 0) + ' ; unknown state, reset');
L(JMP(0x01));
B();

// H_20: state 0 - looking for opcode start
C('H_20: state 0 - looking for opcode start');
L(H(0x20));
L(SET(0x41, 0x20)); L(CMP(0x0F, 0x41)); L(JE(0x01) + '  ; space -> skip');
L(SET(0x41, 0x09)); L(CMP(0x0F, 0x41)); L(JE(0x01) + '  ; tab  -> skip');
L(SET(0x41, 0x0D)); L(CMP(0x0F, 0x41)); L(JE(0x01) + '  ; CR   -> skip');
L(SET(0x41, 0x0A)); L(CMP(0x0F, 0x41)); L(JE(0x01) + '  ; LF   -> skip');
L(SET(0x41, 0x3B)); L(CMP(0x0F, 0x41)); L(JE(0x25) + '  ; ;    -> comment');
L(SET(0x41, 0x73)); L(CMP(0x0F, 0x41)); L(JE(0x26) + '  ; s    -> string prefix');
C('Hex digit range check');
L(SET(0x41, 0x30)); L(CMP(0x0F, 0x41)); L(JB(0x01) + '  ; < \'0\' -> skip');
L(SET(0x41, 0x66)); L(CMP(0x0F, 0x41)); L(JA(0x01) + '  ; > \'f\' -> skip');
L(CH(0x0C) + '  ; H_0C: convert and accumulate nibble');
L(SET(0x10, 1) + ' ; state = 1 (accumulating opcode)');
L(JMP(0x01));
B();

// H_21: state 1 - accumulating opcode hex digits
C('H_21: state 1 - accumulating opcode hex');
L(H(0x21));
L(SET(0x41, 0x30)); L(CMP(0x0F, 0x41)); L(JB(0x28) + '  ; non-hex -> H_28 (separator)');
L(SET(0x41, 0x66)); L(CMP(0x0F, 0x41)); L(JA(0x28) + '  ; non-hex -> H_28 (separator)');
L(CH(0x0C));
L(JMP(0x01));
B();

// H_28: separator after opcode
C('H_28: separator after opcode digits');
L(H(0x28));
L(GET(0x13, 0x11) + ' ; opcode = accumulator');
L(SET(0x11, 0));
L(SET(0x12, 0));
C('LF/CR/; -> emit immediately (no args)');
L(SET(0x41, 0x0A)); L(CMP(0x0F, 0x41)); L(JE(0x30) + ' ; LF -> emit');
L(SET(0x41, 0x0D)); L(CMP(0x0F, 0x41)); L(JE(0x30) + ' ; CR -> emit');
L(SET(0x41, 0x3B)); L(CMP(0x0F, 0x41)); L(JE(0x30) + ' ; ;  -> emit');
L(SET(0x10, 2) + '  ; state = 2 (looking for first arg)');
L(JMP(0x01));
B();

// H_22: state 2 - looking for arg start
C('H_22: state 2 - looking for arg start');
L(H(0x22));
L(SET(0x41, 0x20)); L(CMP(0x0F, 0x41)); L(JE(0x01) + '  ; space -> skip');
L(SET(0x41, 0x09)); L(CMP(0x0F, 0x41)); L(JE(0x01) + '  ; tab   -> skip');
L(SET(0x41, 0x0D)); L(CMP(0x0F, 0x41)); L(JE(0x01) + '  ; CR    -> skip');
L(SET(0x41, 0x0A)); L(CMP(0x0F, 0x41)); L(JE(0x30) + '  ; LF -> emit');
L(SET(0x41, 0x3B)); L(CMP(0x0F, 0x41)); L(JE(0x30) + '  ; ;  -> emit');
L(SET(0x41, 0x73)); L(CMP(0x0F, 0x41)); L(JE(0x26) + '  ; s  -> string prefix');
L(SET(0x41, 0x30)); L(CMP(0x0F, 0x41)); L(JB(0x01) + '  ; < \'0\' -> skip');
L(SET(0x41, 0x66)); L(CMP(0x0F, 0x41)); L(JA(0x01) + '  ; > \'f\' -> skip');
L(CH(0x0C) + '  ; accumulate first nibble of arg');
L(SET(0x10, 3) + ' ; state = 3 (accumulating arg)');
L(JMP(0x01));
B();

// H_23: state 3 - accumulating arg hex
C('H_23: state 3 - accumulating arg hex');
L(H(0x23));
L(SET(0x41, 0x30)); L(CMP(0x0F, 0x41)); L(JB(0x29) + '  ; non-hex -> H_29 (arg separator)');
L(SET(0x41, 0x66)); L(CMP(0x0F, 0x41)); L(JA(0x29) + '  ; non-hex -> H_29 (arg separator)');
L(CH(0x0C));
L(JMP(0x01));
B();

// ── H_29: Arg separator (MULTI-ARG FIX) ──────────────────────────────────────
C('H_29: arg separator - dispatch by arg_index to state_50/51/52');
L(H(0x29));
L(SET(0x41, 0)); L(CMP(0x14, 0x41)); L(JE(0x2E) + ' ; arg_index==0 -> H_2E (state_50)');
L(SET(0x41, 1)); L(CMP(0x14, 0x41)); L(JE(0x2C) + ' ; arg_index==1 -> H_2C (state_51)');
L(JMP(0x2D) + '                                  ; arg_index>=2 -> H_2D (state_52)');
B();

C('H_2E: store accumulator -> state_50 (arg0), then continuation');
L(H(0x2E));
L(GET(0x50, 0x11));
L(JMP(0x2F));
B();

C('H_2C: store accumulator -> state_51 (arg1), then continuation');
L(H(0x2C));
L(GET(0x51, 0x11));
L(JMP(0x2F));
B();

C('H_2D: store accumulator -> state_52 (arg2), then continuation');
L(H(0x2D));
L(GET(0x52, 0x11));
L(JMP(0x2F));
B();

C('H_2F: continuation after arg store - reset acc, check emit');
L(H(0x2F));
L(SET(0x11, 0));
L(SET(0x12, 0));
L(INC(0x14) + ' ; arg_index++');
L(SET(0x41, 0x0A)); L(CMP(0x0F, 0x41)); L(JE(0x30) + ' ; LF -> emit');
L(SET(0x41, 0x0D)); L(CMP(0x0F, 0x41)); L(JE(0x30) + ' ; CR -> emit');
L(SET(0x41, 0x3B)); L(CMP(0x0F, 0x41)); L(JE(0x30) + ' ; ;  -> emit');
L(SET(0x10, 2));
L(JMP(0x01));
B();

// ── H_30: Emitter dispatch chain ─────────────────────────────────────────────
C('H_30: Emitter dispatch - route by opcode in state_13');
C('After the sub-handler runs, falls through to H_4C (reset scanner)');
L(H(0x30));
L(GET(0x40, 0x13) + ' ; state_40 = opcode');
L(SET(0x41, 0x40)); L(CMP(0x40, 0x41)); L(JNE(0x3A));
L(CH(0x31) + '  ; opcode 0x40: record handler offset');
L(JMP(0x4C));
B();

L(H(0x3A));
L(SET(0x41, 0xFF)); L(CMP(0x40, 0x41)); L(JNE(0x3B));
L(CH(0x32) + '  ; opcode 0xFF: emit ret');
L(JMP(0x4C));
B();

L(H(0x3B));
L(SET(0x41, 0x30)); L(CMP(0x40, 0x41)); L(JNE(0x3C));
L(CH(0x33) + '  ; opcode 0x30: emit SET (mov rax, vv; stPut ss)');
L(JMP(0x4C));
B();

L(H(0x3C));
L(SET(0x41, 0x60)); L(CMP(0x40, 0x41)); L(JNE(0x3D));
L(CH(0x34) + '  ; opcode 0x60: emit COPY (stGet -> stPut)');
L(JMP(0x4C));
B();

L(H(0x3D));
L(SET(0x41, 0x66)); L(CMP(0x40, 0x41)); L(JNE(0x3E));
L(CH(0x35) + '  ; opcode 0x66: emit INC');
L(JMP(0x4C));
B();

L(H(0x3E));
L(SET(0x41, 0x65)); L(CMP(0x40, 0x41)); L(JNE(0x3F));
L(CH(0x39) + '  ; opcode 0x65: emit CMP');
L(JMP(0x4C));
B();

L(H(0x3F));
L(SET(0x41, 0x70)); L(CMP(0x40, 0x41)); L(JNE(0x4A));
L(CH(0x36) + '  ; opcode 0x70: emit JMP rel32');
L(JMP(0x4C));
B();

L(H(0x4A));
L(SET(0x41, 0x71)); L(CMP(0x40, 0x41)); L(JNE(0x4B));
L(CH(0x38) + '  ; opcode 0x71: emit JE rel32');
L(JMP(0x4C));
B();

L(H(0x4B));
L(SET(0x41, 0x41)); L(CMP(0x40, 0x41)); L(JNE(0x4D));
L(CH(0x37) + '  ; opcode 0x41: emit CALL rel32');
L(JMP(0x4C));
B();

// ── New opcode dispatch entries (added for Phase 2 self-hosting) ────────
C('H_4D: opcode 0x55 - emit store u32');
L(H(0x4D));
L(SET(0x41, 0x55)); L(CMP(0x40, 0x41)); L(JNE(0x4E));
L(CH(0x74) + '  ; opcode 0x55: emit store u32');
L(JMP(0x4C));
B();

C('H_4E: opcode 0x57 - emit store byte at indexed offset');
L(H(0x4E));
L(SET(0x41, 0x57)); L(CMP(0x40, 0x41)); L(JNE(0x4F));
L(CH(0x75) + '  ; opcode 0x57: emit store byte');
L(JMP(0x4C));
B();

C('H_4F: opcode 0x61 - emit ADD immediate to state');
L(H(0x4F));
L(SET(0x41, 0x61)); L(CMP(0x40, 0x41)); L(JNE(0x50));
L(CH(0x70) + '  ; opcode 0x61: emit ADD');
L(JMP(0x4C));
B();

C('H_50: opcode 0x62 - emit SUB immediate from state');
L(H(0x50));
L(SET(0x41, 0x62)); L(CMP(0x40, 0x41)); L(JNE(0x51));
L(CH(0x71) + '  ; opcode 0x62: emit SUB');
L(JMP(0x4C));
B();

C('H_51: opcode 0x68 - emit ADDV (add state to state)');
L(H(0x51));
L(SET(0x41, 0x68)); L(CMP(0x40, 0x41)); L(JNE(0x52));
L(CH(0x72) + '  ; opcode 0x68: emit ADDV');
L(JMP(0x4C));
B();

C('H_52: opcode 0x69 - emit SUBV (sub state from state)');
L(H(0x52));
L(SET(0x41, 0x69)); L(CMP(0x40, 0x41)); L(JNE(0x53));
L(CH(0x73) + '  ; opcode 0x69: emit SUBV');
L(JMP(0x4C));
B();

C('H_53: opcode 0x72 - emit JNE rel32');
L(H(0x53));
L(SET(0x41, 0x72)); L(CMP(0x40, 0x41)); L(JNE(0x54));
L(CH(0x78) + '  ; opcode 0x72: emit JNE');
L(JMP(0x4C));
B();

C('H_54: opcode 0x75 - emit JBE rel32');
L(H(0x54));
L(SET(0x41, 0x75)); L(CMP(0x40, 0x41)); L(JNE(0x55));
L(CH(0x79) + '  ; opcode 0x75: emit JBE');
L(JMP(0x4C));
B();

C('H_55: opcode 0x77 - emit JB rel32');
L(H(0x55));
L(SET(0x41, 0x77)); L(CMP(0x40, 0x41)); L(JNE(0x56));
L(CH(0x7A) + '  ; opcode 0x77: emit JB');
L(JMP(0x4C));
B();

C('H_56: opcode 0x78 - emit JAE rel32');
L(H(0x56));
L(SET(0x41, 0x78)); L(CMP(0x40, 0x41)); L(JNE(0x57));
L(CH(0x7B) + '  ; opcode 0x78: emit JAE');
L(JMP(0x4C));
B();

C('H_57: opcode 0x7A - emit JA rel32');
L(H(0x57));
L(SET(0x41, 0x7A)); L(CMP(0x40, 0x41)); L(JNE(0x58));
L(CH(0x7C) + '  ; opcode 0x7A: emit JA');
L(JMP(0x4C));
B();

C('H_58: opcode 0x80 - emit LDB (load byte)');
L(H(0x58));
L(SET(0x41, 0x80)); L(CMP(0x40, 0x41)); L(JNE(0x59));
L(CH(0x76) + '  ; opcode 0x80: emit LDB');
L(JMP(0x4C));
B();

C('H_59: opcode 0x84 - emit REP MOVSB (memcpy)');
L(H(0x59));
L(SET(0x41, 0x84)); L(CMP(0x40, 0x41)); L(JNE(0x5A));
L(CH(0x77) + '  ; opcode 0x84: emit memcpy');
L(JMP(0x4C));
B();

C('H_5A: opcode 0x20 - emit VirtualAlloc call');
L(H(0x5A));
L(SET(0x41, 0x20)); L(CMP(0x40, 0x41)); L(JNE(0x5B));
L(CH(0x60) + '  ; opcode 0x20: emit VirtualAlloc');
L(JMP(0x4C));
B();

C('H_5B: opcode 0x50 - emit LoadFile');
L(H(0x5B));
L(SET(0x41, 0x50)); L(CMP(0x40, 0x41)); L(JNE(0x5C));
L(CH(0x61) + '  ; opcode 0x50: emit LoadFile');
L(JMP(0x4C));
B();

C('H_5C: opcode 0x51 - emit WriteFile');
L(H(0x5C));
L(SET(0x41, 0x51)); L(CMP(0x40, 0x41)); L(JNE(0x4C));
L(CH(0x62) + '  ; opcode 0x51: emit WriteFile');
L(JMP(0x4C));
B();

C('H_4C: reset scanner state and loop back to H_01');
L(H(0x4C));
L(SET(0x10, 0));
L(SET(0x11, 0));
L(SET(0x12, 0));
L(SET(0x14, 0));
L(JMP(0x01));
B();

// ── Comment handler ───────────────────────────────────────────────────────────
C('H_25: comment - skip to end of line');
L(H(0x25));
L(CMP(0x0C, 0x0D)); L(JAE(0x1E) + '  ; EOF -> H_1E');
L(LDB(0x0F, 0x0C, 0)); L(INC(0x0C));
L(SET(0x41, 0x0A)); L(CMP(0x0F, 0x41)); L(JE(0x2A) + '  ; LF -> end comment');
L(SET(0x41, 0x0D)); L(CMP(0x0F, 0x41)); L(JE(0x2A) + '  ; CR -> end comment');
L(JMP(0x25));
B();

C('H_2A: end of comment');
L(H(0x2A));
L(SET(0x10, 0));
L(JMP(0x01));
B();

// ── String handler ────────────────────────────────────────────────────────────
C('H_26: string prefix (\'s\' seen before arg)');
L(H(0x26));
L(SET(0x10, 4));
L(JMP(0x01));
B();

C('H_24: state 4 - reading string hex pairs');
L(H(0x24));
L(SET(0x41, 0x30)); L(CMP(0x0F, 0x41)); L(JB(0x2B) + '  ; non-hex -> H_2B');
L(SET(0x41, 0x66)); L(CMP(0x0F, 0x41)); L(JA(0x2B) + '  ; non-hex -> H_2B');
L(CH(0x0C));
L(JMP(0x01));
B();

// H_2B: string arg separator (same multi-arg dispatch as H_29)
C('H_2B: string arg separator - dispatch by arg_index');
L(H(0x2B));
L(SET(0x41, 0)); L(CMP(0x14, 0x41)); L(JE(0x2E) + ' ; arg_index==0 -> H_2E');
L(SET(0x41, 1)); L(CMP(0x14, 0x41)); L(JE(0x2C) + ' ; arg_index==1 -> H_2C');
L(JMP(0x2D));
B();

// ── H_0C/H_0D: hex digit converter + nibble accumulator ──────────────────────
C('H_0C: convert hex char in state_0F to nibble, accumulate into state_11');
L(H(0x0C));
L(GET(0x40, 0x0F));
L(SUB(0x40, 0x30) + '  ; digit -= \'0\'');
L(SET(0x41, 9)); L(CMP(0x40, 0x41)); L(JBE(0x0D) + '  ; 0-9 digit -> accumulate');
L(SUB(0x40, 7)  + '  ; A-F: -= 7 (so \'A\'-\'0\'-7 = 10)');
L(SET(0x41, 15)); L(CMP(0x40, 0x41)); L(JBE(0x0D) + ' ; A-F digit');
L(SUB(0x40, 32) + '  ; a-f: -= 32');
B();

C('H_0D: accumulate nibble into state_11');
L(H(0x0D));
L(GET(0x41, 0x11));
L(ADDV(0x41, 0x41)); L(ADDV(0x41, 0x41));
L(ADDV(0x41, 0x41)); L(ADDV(0x41, 0x41) + ' ; x16');
L(ADDV(0x41, 0x40) + ' ; + digit');
L(GET(0x11, 0x41));
L(INC(0x12));
L(RET());
B();

// ── H_1E: EOF handler ─────────────────────────────────────────────────────────
C('H_1E: emit auto-ret for the last handler, then resolve fixups');
L(H(0x1E));
L(SET(0x45, 0xC3));
L(CH(0xE0) + '  ; emit 0xC3 (RET) as auto-ret for last handler');
L(CH(0x63) + '  ; resolve all forward-jump fixups');
L(RET() + '      ; return to main ops -> 51 write, then ExitProcess');
B();

// ════════════════════════════════════════════════════════════════════════════════
// H_30 OPCODE EMITTER SUB-HANDLERS
// Convention: state_50=arg0, state_51=arg1, state_52=arg2
//             state_03=write_base, state_0E=code_offset
//             state_45=byte-to-emit, state_46=state-ID-for-stGet/Put
//             state_4D=u32-value-to-emit, state_4E=rel32-end-pos
//             state_47=disp-b0, state_49=disp-b1
// ════════════════════════════════════════════════════════════════════════════════

// ── Helper: H_E0 - emit one byte (state_45) to output code section ────────────
C('H_E0: emit byte from state_45 -> [state_03 + state_0E], advance state_0E');
L(H(0xE0));
L('57 03 0E 45');
L(INC(0x0E));
L(RET());
B();

// ── Helper: H_E1/H_E9 - compute LE32 disp bytes for state_id in state_46 ──────
// Output: state_47 = b0 (low byte), state_49 = b1 (second byte)
// Encodes: disp = state_46 * 8 (always use mod=2 for determinism)
C('H_E1: compute disp32 bytes for state[state_46]. disp = state_46*8.');
C('  Output: state_47=b0(low byte), state_49=b1, bytes 2-3 always 0.');
L(H(0xE1));
L(GET(0x47, 0x46));   // state_47 = state_46
L(ADDV(0x47, 0x47));  // *2
L(ADDV(0x47, 0x47));  // *4
L(ADDV(0x47, 0x47));  // *8 = disp = state_46 * 8
L(SET(0x49, 0));      // b1 = 0
L(SET(0x42, 0x100));  // threshold = 256
L(CMP(0x47, 0x42));   L(JB(0xE9) + '  ; disp < 256 -> done');
L(SUB(0x47, 0x100));  L(INC(0x49));
L(CMP(0x47, 0x42));   L(JB(0xE9));
L(SUB(0x47, 0x100));  L(INC(0x49));
L(CMP(0x47, 0x42));   L(JB(0xE9));
L(SUB(0x47, 0x100));  L(INC(0x49));
B();

C('H_E9: disp computation done (b0=state_47, b1=state_49)');
L(H(0xE9));
L(RET());
B();

// ── Helper: H_E4 - emit 4-byte LE disp (b0 b1 0 0) ──────────────────────────
C('H_E4: emit 4-byte LE disp (state_47, state_49, 0, 0)');
L(H(0xE4));
L('57 03 0E 47'); L(INC(0x0E));   // emit b0
L('57 03 0E 49'); L(INC(0x0E));   // emit b1
L(SET(0x45, 0));
L('57 03 0E 45'); L(INC(0x0E));   // emit 0
L('57 03 0E 45'); L(INC(0x0E));   // emit 0
L(RET());
B();

// ── Helper: H_E2 - emit stGet(RAX, state[state_46]) (7 bytes) ────────────────
// Encoding: REX(4D) 8B 87 disp32  (MOV RAX, [R15 + disp32])
C('H_E2: emit stGet(RAX, state_46) = 4D 8B 87 disp32  (7 bytes)');
L(H(0xE2));
L(SET(0x45, 0x4D)); L(CH(0xE0));   // REX: W=1, R=1(RAX<8), B=1(R15>=8)
L(SET(0x45, 0x8B)); L(CH(0xE0));   // MOV opcode
L(SET(0x45, 0x87)); L(CH(0xE0));   // ModRM: mod=2, reg=0(RAX), rm=7(R15)
L(CH(0xE1));                        // compute disp bytes
L(CH(0xE4));                        // emit disp32
L(RET());
B();

// ── Helper: H_EB - emit stGet(RDX, state[state_46]) (7 bytes) ────────────────
// Encoding: REX(4D) 8B 97 disp32  (MOV RDX, [R15 + disp32])
C('H_EB: emit stGet(RDX, state_46) = 4D 8B 97 disp32  (7 bytes)');
L(H(0xEB));
L(SET(0x45, 0x4D)); L(CH(0xE0));
L(SET(0x45, 0x8B)); L(CH(0xE0));
L(SET(0x45, 0x97)); L(CH(0xE0));   // ModRM: mod=2, reg=2(RDX), rm=7(R15)
L(CH(0xE1));
L(CH(0xE4));
L(RET());
B();

// ── Helper: H_E3 - emit stPut(state_46, RAX) (7 bytes) ───────────────────────
// Encoding: REX(49) 89 87 disp32  (MOV [R15 + disp32], RAX)
C('H_E3: emit stPut(state_46, RAX) = 49 89 87 disp32  (7 bytes)');
L(H(0xE3));
L(SET(0x45, 0x49)); L(CH(0xE0));   // REX: W=1, B=1(R15>=8)
L(SET(0x45, 0x89)); L(CH(0xE0));   // MOV [r/m], r opcode
L(SET(0x45, 0x87)); L(CH(0xE0));   // ModRM: mod=2, reg=0(RAX), rm=7(R15)
L(CH(0xE1));
L(CH(0xE4));
L(RET());
B();

// ── Helper: H_E5 - emit state_4D as 4-byte LE at current write position ──────
C('H_E5: write state_4D as u32-LE to (state_03 + state_0E), advance state_0E by 4');
L(H(0xE5));
L(GET(0x4C, 0x03));
L(ADDV(0x4C, 0x0E) + ' ; state_4C = write_base + code_off');
L('55 4C 4D' + '      ; [state_4C] = (u32) state_4D');
L(ADD(0x0E, 4));
L(RET());
B();

// ── Helper: H_E7 - read handler offset (state_50 -> state_4D) ────────────────
C('H_E7: state_4D = handler_table[state_50]  (reads 2-byte entry from table)');
L(H(0xE7));
L(GET(0x47, 0x50));                 // state_47 = hh
L(ADDV(0x47, 0x47));                // *2
L(ADDV(0x47, 0x47));                // *4 = hh * 4 (byte offset in table)
L(GET(0x48, 0x04));
L(ADDV(0x48, 0x47) + '  ; state_48 = table_base + hh*4');
L(LDB(0x49, 0x48, 0) + ' ; byte0');
L(LDB(0x4A, 0x48, 1) + ' ; byte1');
// state_4A * 256
L(ADDV(0x4A, 0x4A)); L(ADDV(0x4A, 0x4A)); L(ADDV(0x4A, 0x4A)); L(ADDV(0x4A, 0x4A));
L(ADDV(0x4A, 0x4A)); L(ADDV(0x4A, 0x4A)); L(ADDV(0x4A, 0x4A)); L(ADDV(0x4A, 0x4A));
L(ADDV(0x49, 0x4A));
L(GET(0x4D, 0x49) + '   ; state_4D = offset = byte0 + byte1*256');
L(RET());
B();

// ── Helper: H_E6 - add fixup entry ────────────────────────────────────────────
C('H_E6: record fixup: hh=state_50, patch_pos=state_0E, count=state_07');
L(H(0xE6));
L(GET(0x47, 0x07));                    // state_47 = count
L(ADDV(0x47, 0x47)); L(ADDV(0x47, 0x47) + ' ; *4 = count*4 = byte offset');
C('Write hh to fixup_hh[count]');
L(GET(0x48, 0x05));
L(ADDV(0x48, 0x47) + '  ; state_48 = hh_base + count*4');
L('55 48 50'         + '  ; [state_48] = state_50 (hh)');
C('Write patch_pos to fixup_pos[count]');
L(GET(0x48, 0x06));
L(ADDV(0x48, 0x47) + '  ; state_48 = pos_base + count*4');
L('55 48 0E'         + '  ; [state_48] = state_0E (patch_pos)');
L(INC(0x07) + '          ; fixup_count++');
L(RET());
B();

// ── Helper: H_ED/H_EE/H_EF - extract byte0 and quotient from state_51 ────────
// Input: state_51 = value to decompose
// Output: state_4F = byte0 (low byte = value mod 256)
//         state_47 = quotient (value / 256)
C('H_ED: extract low byte of state_51. state_4F=b0, state_47=b1 (quotient)');
L(H(0xED));
L(GET(0x4F, 0x51) + '  ; state_4F = value');
L(SET(0x42, 0x100)  + ' ; threshold = 256');
L(SET(0x47, 0)      + ' ; quotient = 0');
L(JMP(0xEE));
B();

C('H_EE: byte-extraction loop body');
L(H(0xEE));
L(CMP(0x4F, 0x42));
L(JB(0xEF) + '  ; state_4F < 256 -> done');
L(SUB(0x4F, 0x100));
L(INC(0x47));
L(JMP(0xEE));
B();

C('H_EF: byte-extraction done');
L(H(0xEF));
L(RET());
B();

// ════════════════════════════════════════════════════════════════════════════════
// OPCODE SUB-HANDLERS
// ════════════════════════════════════════════════════════════════════════════════

// ── H_31: opcode 0x40 - handler declaration ───────────────────────────────────
C('H_31: opcode 0x40 hh  - start of handler hh');
C('  First 0x40: emit ExitProcess call (default exit for unknown hh=0)');
C('  Subsequent 0x40: emit auto-ret (C3) for the PREVIOUS handler');
C('  Both cases then record handler_table[hh] = state_0E');
L(H(0x31));
C('Check first-handler flag (state_09)');
L(SET(0x41, 0)); L(CMP(0x09, 0x41)); L(JE(0x40) + '  ; not yet seen -> H_40 (first)');
C('Not first: emit C3 (auto-ret for previous handler)');
L(SET(0x45, 0xC3)); L(CH(0xE0));
L(JMP(0x41) + '  ; -> H_41 record offset');
B();

C('H_40: first-handler prologue - emit ExitProcess(0) call (9 bytes)');
C('  xor rcx,rcx (3B) + call [ExitProcess] (6B)');
C('  disp = ExitProcess_IAT - (CODE_RVA + state_0E + 9) = 0x3FFC - state_0E');
C('  (state_0E here = X+5 after emitting 48 31 C9 FF 15)');
L(H(0x40));
L(SET(0x45, 0x48)); L(CH(0xE0));   // xor rcx,rcx: 48
L(SET(0x45, 0x31)); L(CH(0xE0));   //              31
L(SET(0x45, 0xC9)); L(CH(0xE0));   //              C9
L(SET(0x45, 0xFF)); L(CH(0xE0));   // call [mem]: FF
L(SET(0x45, 0x15)); L(CH(0xE0));   //             15
C('Compute disp32 = 0x3FFC - state_0E  (ExitProcess IAT = 0x5000)');
L(SET(0x4D, 0x3FFC));
L(SUBV(0x4D, 0x0E));
L(CH(0xE5) + '  ; emit disp32');
L(SET(0x09, 1) + '  ; set first_handler_flag');
B();

C('H_41: record handler offset: handler_table[state_50] = state_0E');
L(H(0x41));
L(GET(0x47, 0x50));
L(ADDV(0x47, 0x47)); L(ADDV(0x47, 0x47) + ' ; hh*4');
L(GET(0x48, 0x04));
L(ADDV(0x48, 0x47) + '  ; table_base + hh*4');
L('55 48 0E' + '        ; handler_table[hh] = state_0E');
L(RET());
B();

// ── H_32: opcode 0xFF - emit ret ─────────────────────────────────────────────
C('H_32: opcode 0xFF - emit C3 (ret)');
L(H(0x32));
L(SET(0x45, 0xC3));
L(CH(0xE0));
L(RET());
B();

// ── H_33: opcode 0x30 ss vv - emit SET: state[ss] = vv ───────────────────────
// Emits: movabs rax, vv (10 bytes) + stPut(ss, RAX) (7 bytes) = 17 bytes
C('H_33: opcode 0x30 ss vv - emit: movabs rax, vv; stPut(ss, rax)');
C('  movabs rax, vv = 48 B8 <vv 8 bytes LE>  (10 bytes total)');
L(H(0x33));
L(SET(0x45, 0x48)); L(CH(0xE0));   // REX.W
L(SET(0x45, 0xB8)); L(CH(0xE0));   // MOV RAX, imm64
C('Decompose state_51 (vv) into byte0 and byte1, emit as LE64');
L(CH(0xED) + '  ; state_4F=b0, state_47=b1');
L('57 03 0E 4F'); L(INC(0x0E));    // emit b0
L('57 03 0E 47'); L(INC(0x0E));    // emit b1
C('Bytes 2-7 of imm64 are zero (values fit in 16 bits)');
L(SET(0x45, 0));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
C('Emit stPut(state_50, RAX) = 49 89 87 disp32');
L(GET(0x46, 0x50));
L(CH(0xE3));
L(RET());
B();

// ── H_34: opcode 0x60 dd ss - emit COPY: state[dd] = state[ss] ───────────────
// Emits: stGet(RAX, ss) + stPut(dd, RAX) = 7+7 = 14 bytes
C('H_34: opcode 0x60 dd ss - emit: stGet(RAX, ss); stPut(dd, RAX)');
L(H(0x34));
L(GET(0x46, 0x51) + '  ; ss = arg1');
L(CH(0xE2));                        // emit stGet(RAX, ss)
L(GET(0x46, 0x50) + '  ; dd = arg0');
L(CH(0xE3));                        // emit stPut(dd, RAX)
L(RET());
B();

// ── H_35: opcode 0x66 ss - emit INC: state[ss]++ ─────────────────────────────
// Emits: stGet(RAX, ss) + add rax,1 (4B) + stPut(ss, RAX) = 7+4+7 = 18 bytes
C('H_35: opcode 0x66 ss - emit: stGet(RAX,ss); add rax,1; stPut(ss,RAX)');
L(H(0x35));
L(GET(0x46, 0x50));
L(CH(0xE2));                        // stGet(RAX, ss)
L(SET(0x45, 0x48)); L(CH(0xE0));   // add rax,1 imm8: 48
L(SET(0x45, 0x83)); L(CH(0xE0));   //                  83
L(SET(0x45, 0xC0)); L(CH(0xE0));   //   ModRM(3,0,0)   C0
L(SET(0x45, 0x01)); L(CH(0xE0));   //   imm8=1          01
L(GET(0x46, 0x50));
L(CH(0xE3));                        // stPut(ss, RAX)
L(RET());
B();

// ── H_39: opcode 0x65 aa bb - emit CMP: flags = state[aa] - state[bb] ─────────
// Emits: stGet(RAX, aa) + stGet(RDX, bb) + cmp rax,rdx (3B) = 7+7+3 = 17 bytes
C('H_39: opcode 0x65 aa bb - emit: stGet(RAX,aa); stGet(RDX,bb); cmp rax,rdx');
L(H(0x39));
L(GET(0x46, 0x50));
L(CH(0xE2));                        // stGet(RAX, aa)
L(GET(0x46, 0x51));
L(CH(0xEB));                        // stGet(RDX, bb)
L(SET(0x45, 0x48)); L(CH(0xE0));   // cmp rax,rdx: 48 39 D0
L(SET(0x45, 0x39)); L(CH(0xE0));
L(SET(0x45, 0xD0)); L(CH(0xE0));
L(RET());
B();

// ── H_36/H_42: opcode 0x70 hh - emit JMP rel32 ───────────────────────────────
// Backward: E9 rel32 = 5 bytes
// Forward:  E9 00000000 + fixup entry = 5 bytes
C('H_36: opcode 0x70 hh - emit JMP rel32 (E9 disp32)');
L(H(0x36));
L(CH(0xE7) + '  ; state_4D = handler_table[state_50]');
C('If handler_table[hh]==0 it\'s a forward jump (handler not yet defined)');
L(SET(0x41, 0)); L(CMP(0x4D, 0x41)); L(JE(0x42) + '  ; forward -> H_42');
C('Backward jump: compute rel32 = target - (state_0E + 5)');
L(SET(0x45, 0xE9)); L(CH(0xE0));   // emit E9 opcode
C('state_4E = state_0E + 4  (end of instruction after disp32)');
L(GET(0x4E, 0x0E)); L(ADD(0x4E, 4));
L(SUBV(0x4D, 0x4E) + '  ; rel32 = target - end');
L(CH(0xE5));
L(RET());
B();

C('H_42: forward JMP - emit E9 placeholder and record fixup');
L(H(0x42));
L(SET(0x45, 0xE9)); L(CH(0xE0));   // emit E9
L(CH(0xE6) + '  ; record fixup (hh=state_50, patch_pos=state_0E)');
L(SET(0x45, 0));                    // emit 4 zero bytes placeholder
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L(RET());
B();

// ── H_37/H_43: opcode 0x41 hh - emit CALL rel32 ──────────────────────────────
C('H_37: opcode 0x41 hh - emit CALL rel32 (E8 disp32)');
L(H(0x37));
L(CH(0xE7));
L(SET(0x41, 0)); L(CMP(0x4D, 0x41)); L(JE(0x43));
L(SET(0x45, 0xE8)); L(CH(0xE0));
L(GET(0x4E, 0x0E)); L(ADD(0x4E, 4));
L(SUBV(0x4D, 0x4E));
L(CH(0xE5));
L(RET());
B();

C('H_43: forward CALL - emit E8 placeholder and record fixup');
L(H(0x43));
L(SET(0x45, 0xE8)); L(CH(0xE0));
L(CH(0xE6));
L(SET(0x45, 0));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L(RET());
B();

// ── H_38/H_44: opcode 0x71 hh - emit JE rel32 ────────────────────────────────
// JE rel32 encoding: 0F 84 rel32 (6 bytes)
C('H_38: opcode 0x71 hh - emit JE rel32 (0F 84 disp32)');
L(H(0x38));
L(CH(0xE7));
L(SET(0x41, 0)); L(CMP(0x4D, 0x41)); L(JE(0x44));
L(SET(0x45, 0x0F)); L(CH(0xE0));
L(SET(0x45, 0x84)); L(CH(0xE0));
L(GET(0x4E, 0x0E)); L(ADD(0x4E, 4));
L(SUBV(0x4D, 0x4E));
L(CH(0xE5));
L(RET());
B();

C('H_44: forward JE - emit 0F 84 placeholder and record fixup');
L(H(0x44));
L(SET(0x45, 0x0F)); L(CH(0xE0));
L(SET(0x45, 0x84)); L(CH(0xE0));
L(CH(0xE6));
L(SET(0x45, 0));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L(RET());
B();

// ════════════════════════════════════════════════════════════════════════════════
// NEW HELPERS (stGet variants for additional registers)
// H_E8: stGet(R8, state_46)  - mov r8, [r15 + id*8]
// H_EA: stGet(RDI, state_46) - mov rdi, [r15 + id*8]
// H_EC: stGet(RSI, state_46) - mov rsi, [r15 + id*8]
// ════════════════════════════════════════════════════════════════════════════════
C('H_E8: stGet(R8, state_46) - mov r8, [r15 + disp32]');
L(H(0xE8));
L(SET(0x45, 0x4B)); L(CH(0xE0));   // REX.W REX.R(R8>=8=1) REX.B(R15>=8=1)
L(SET(0x45, 0x8B)); L(CH(0xE0));   // MOV opcode
L(SET(0x45, 0x87)); L(CH(0xE0));   // ModRM(2, reg=R8&7=0, rm=R15&7=7)
L(CH(0xE1));                        // compute disp bytes
L(CH(0xE4));                        // emit disp32
L(RET());
B();

C('H_EA: stGet(RDI, state_46) - mov rdi, [r15 + disp32]');
L(H(0xEA));
L(SET(0x45, 0x49)); L(CH(0xE0));   // REX.W REX.R(RDI<8=0) REX.B(R15>=8=1)
L(SET(0x45, 0x8B)); L(CH(0xE0));   // MOV opcode
L(SET(0x45, 0xBF)); L(CH(0xE0));   // ModRM(2, reg=RDI&7=7, rm=R15&7=7)
L(CH(0xE1));                        // compute disp bytes
L(CH(0xE4));                        // emit disp32
L(RET());
B();

C('H_EC: stGet(RSI, state_46) - mov rsi, [r15 + disp32]');
L(H(0xEC));
L(SET(0x45, 0x49)); L(CH(0xE0));   // REX.W REX.R(RSI<8=0) REX.B(R15>=8=1)
L(SET(0x45, 0x8B)); L(CH(0xE0));   // MOV opcode
L(SET(0x45, 0xB7)); L(CH(0xE0));   // ModRM(2, reg=RSI&7=6, rm=R15&7=7)
L(CH(0xE1));                        // compute disp bytes
L(CH(0xE4));                        // emit disp32
L(RET());
B();

// ════════════════════════════════════════════════════════════════════════════════
// NEW OPCODE EMITTERS (Phase 2 self-hosting)
// Convention: state_50=arg0, state_51=arg1, state_52=arg2
// ════════════════════════════════════════════════════════════════════════════════

// ── H_70: opcode 0x61 ss vv - emit ADD immediate: state[ss] += vv ──────────────
// Encoding: stGet(RAX,ss); 48 83 C0 <imm8>; stPut(ss,RAX) = 7+4+7 = 18 bytes
C('H_70: opcode 0x61 ss vv - emit: stGet(RAX,ss); add rax,vv; stPut(ss,RAX)');
L(H(0x70));
L(GET(0x46, 0x50)); L(CH(0xE2));   // stGet(RAX, ss)
L(SET(0x45, 0x48)); L(CH(0xE0));   // ADD RAX, imm8: 48 83 C0 <imm8>
L(SET(0x45, 0x83)); L(CH(0xE0));
L(SET(0x45, 0xC0)); L(CH(0xE0));
L('57 03 0E 51'); L(INC(0x0E));    // emit imm8 = state_51
L(GET(0x46, 0x50)); L(CH(0xE3));   // stPut(ss, RAX)
L(RET());
B();

// ── H_71: opcode 0x62 ss vv - emit SUB immediate: state[ss] -= vv ──────────────
C('H_71: opcode 0x62 ss vv - emit: stGet(RAX,ss); sub rax,vv; stPut(ss,RAX)');
L(H(0x71));
L(GET(0x46, 0x50)); L(CH(0xE2));
L(SET(0x45, 0x48)); L(CH(0xE0));   // SUB RAX, imm8: 48 83 E8 <imm8>
L(SET(0x45, 0x83)); L(CH(0xE0));
L(SET(0x45, 0xE8)); L(CH(0xE0));
L('57 03 0E 51'); L(INC(0x0E));
L(GET(0x46, 0x50)); L(CH(0xE3));
L(RET());
B();

// ── H_72: opcode 0x68 aa bb - emit ADDV: state[aa] += state[bb] ───────────────
// Encoding: stGet(RAX,aa); stGet(RDX,bb); 48 01 D0; stPut(aa,RAX) = 7+7+3+7 = 24
C('H_72: opcode 0x68 aa bb - emit: stGet(RAX,aa); stGet(RDX,bb); add rax,rdx; stPut(aa,RAX)');
L(H(0x72));
L(GET(0x46, 0x50)); L(CH(0xE2));
L(GET(0x46, 0x51)); L(CH(0xEB));
L(SET(0x45, 0x48)); L(CH(0xE0));   // add rax, rdx: 48 01 D0
L(SET(0x45, 0x01)); L(CH(0xE0));
L(SET(0x45, 0xD0)); L(CH(0xE0));
L(GET(0x46, 0x50)); L(CH(0xE3));
L(RET());
B();

// ── H_73: opcode 0x69 aa bb - emit SUBV: state[aa] -= state[bb] ───────────────
C('H_73: opcode 0x69 aa bb - emit: stGet(RAX,aa); stGet(RDX,bb); sub rax,rdx; stPut(aa,RAX)');
L(H(0x73));
L(GET(0x46, 0x50)); L(CH(0xE2));
L(GET(0x46, 0x51)); L(CH(0xEB));
L(SET(0x45, 0x48)); L(CH(0xE0));   // sub rax, rdx: 48 29 D0
L(SET(0x45, 0x29)); L(CH(0xE0));
L(SET(0x45, 0xD0)); L(CH(0xE0));
L(GET(0x46, 0x50)); L(CH(0xE3));
L(RET());
B();

// ── H_74: opcode 0x55 aa vv - emit store u32: [state[aa]] = state[vv] (u32)
// Encoding: stGet(RDX,aa); stGet(RAX,vv); 89 02 = 7+7+2 = 16 bytes
C('H_74: opcode 0x55 aa vv - emit: stGet(RDX,aa); stGet(RAX,vv); mov [rdx], eax');
L(H(0x74));
L(GET(0x46, 0x50)); L(CH(0xEB));   // stGet(RDX, aa) = addr
L(GET(0x46, 0x51)); L(CH(0xE2));   // stGet(RAX, vv) = value
L(SET(0x45, 0x89)); L(CH(0xE0));   // mov [rdx], eax: 89 02
L(SET(0x45, 0x02)); L(CH(0xE0));
L(RET());
B();

// ── H_75: opcode 0x57 dd ii vv - emit store byte: [state[dd]+state[ii]] = state[vv]
// Encoding: stGet(RDX,dd); stGet(R8,ii); add rdx,r8; stGet(RAX,vv); 88 02 = 26 bytes
C('H_75: opcode 0x57 dd ii vv - emit: stGet(RDX,dd); stGet(R8,ii); add rdx,r8; stGet(RAX,vv); mov [rdx], al');
L(H(0x75));
L(GET(0x46, 0x50)); L(CH(0xEB));   // stGet(RDX, dd) = base
L(GET(0x46, 0x51)); L(CH(0xE8));   // stGet(R8, ii)  = index
L(SET(0x45, 0x4C)); L(CH(0xE0));   // add rdx, r8: 4C 01 C2
L(SET(0x45, 0x01)); L(CH(0xE0));
L(SET(0x45, 0xC2)); L(CH(0xE0));
L(GET(0x46, 0x52)); L(CH(0xE2));   // stGet(RAX, vv) = value
L(SET(0x45, 0x88)); L(CH(0xE0));   // mov [rdx], al: 88 02
L(SET(0x45, 0x02)); L(CH(0xE0));
L(RET());
B();

// ── H_76: opcode 0x80 dd ss - emit LDB: state[dd] = byte [state[ss]]
// Encoding: stGet(RDX,ss); 0F B6 02; stPut(dd,RAX) = 7+4+7 = 18 bytes
C('H_76: opcode 0x80 dd ss - emit: stGet(RDX,ss); movzx rax,byte [rdx]; stPut(dd,RAX)');
L(H(0x76));
L(GET(0x46, 0x51)); L(CH(0xEB));   // stGet(RDX, ss) = src addr
L(SET(0x45, 0x0F)); L(CH(0xE0));   // movzx rax, byte [rdx]: 0F B6 02
L(SET(0x45, 0xB6)); L(CH(0xE0));
L(SET(0x45, 0x02)); L(CH(0xE0));
L(GET(0x46, 0x50)); L(CH(0xE3));   // stPut(dd, RAX)
L(RET());
B();

// ── H_77: opcode 0x84 dd off sz - emit REP MOVSB: memcpy(state[dd], data_base+off, sz)
// Encoding: stGet(RDI,dd); stGet(RSI,8); 48 81 C6 <off32>; mov rcx,sz; F3 A4 = 7+7+7+10+2 = 33
// Uses state_08 = data_base (computed at startup)
C('H_77: opcode 0x84 dd off sz - emit: stGet(RDI,dd); stGet(RSI,8); add rsi,off; mov rcx,sz; rep movsb');
L(H(0x77));
L(GET(0x46, 0x50)); L(CH(0xEA));   // stGet(RDI, dd) = dest
L(SET(0x46, 8)); L(CH(0xEC));      // stGet(RSI, 8) = data_base from state_08
L(SET(0x45, 0x48)); L(CH(0xE0));   // add rsi, blob_off: 48 81 C6 <imm32>
L(SET(0x45, 0x81)); L(CH(0xE0));
L(SET(0x45, 0xC6)); L(CH(0xE0));
L(CH(0xED) + '  ; decompose state_51 (blob_off) into b0,b1');
L('57 03 0E 4F'); L(INC(0x0E));    // emit b0
L('57 03 0E 47'); L(INC(0x0E));    // emit b1
L(SET(0x45, 0));
L('57 03 0E 45'); L(INC(0x0E));    // emit 0
L('57 03 0E 45'); L(INC(0x0E));    // emit 0
C('mov rcx, size (state_52) as 64-bit immediate');
L(SET(0x45, 0x48)); L(CH(0xE0));   // movabs rcx, imm64: 48 B9 <8 bytes>
L(SET(0x45, 0xB9)); L(CH(0xE0));
C('Decompose state_52 into 8 bytes (only bottom 2 used for small sizes)');
L(GET(0x51, 0x52) + '  ; state_51 = size (for H_ED decomposition)');
L(CH(0xED) + '  ; decompose -> state_4F=b0, state_47=b1');
L('57 03 0E 4F'); L(INC(0x0E));    // emit b0
L('57 03 0E 47'); L(INC(0x0E));    // emit b1
L(SET(0x45, 0));
L('57 03 0E 45'); L(INC(0x0E));    // emit bytes 2-7 = 0
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L(SET(0x45, 0xF3)); L(CH(0xE0));   // rep movsb: F3 A4
L(SET(0x45, 0xA4)); L(CH(0xE0));
L(RET());
B();

// ── Conditional jump emitters (follow same pattern as H_38/H_44 for JE)
// H_78: opcode 0x72 hh - emit JNE rel32 (0F 85 disp32)
C('H_78: opcode 0x72 hh - emit JNE rel32');
L(H(0x78));
L(CH(0xE7));                                   // read handler offset -> state_4D
L(SET(0x41, 0)); L(CMP(0x4D, 0x41)); L(JE(0x7D));  // forward -> H_7D
L(SET(0x45, 0x0F)); L(CH(0xE0));              // backward: 0F 85 disp32
L(SET(0x45, 0x85)); L(CH(0xE0));
L(GET(0x4E, 0x0E)); L(ADD(0x4E, 4));
L(SUBV(0x4D, 0x4E));
L(CH(0xE5));
L(RET());
B();

C('H_7D: forward JNE - emit 0F 85 placeholder and record fixup');
L(H(0x7D));
L(SET(0x45, 0x0F)); L(CH(0xE0));
L(SET(0x45, 0x85)); L(CH(0xE0));
L(CH(0xE6));
L(SET(0x45, 0));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L(RET());
B();

// H_79: opcode 0x75 hh - emit JBE rel32 (0F 86 disp32)
C('H_79: opcode 0x75 hh - emit JBE rel32');
L(H(0x79));
L(CH(0xE7));
L(SET(0x41, 0)); L(CMP(0x4D, 0x41)); L(JE(0x7E));
L(SET(0x45, 0x0F)); L(CH(0xE0));
L(SET(0x45, 0x86)); L(CH(0xE0));
L(GET(0x4E, 0x0E)); L(ADD(0x4E, 4));
L(SUBV(0x4D, 0x4E));
L(CH(0xE5));
L(RET());
B();

C('H_7E: forward JBE - emit 0F 86 placeholder and record fixup');
L(H(0x7E));
L(SET(0x45, 0x0F)); L(CH(0xE0));
L(SET(0x45, 0x86)); L(CH(0xE0));
L(CH(0xE6));
L(SET(0x45, 0));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L(RET());
B();

// H_7A: opcode 0x77 hh - emit JB rel32 (0F 82 disp32)
C('H_7A: opcode 0x77 hh - emit JB rel32');
L(H(0x7A));
L(CH(0xE7));
L(SET(0x41, 0)); L(CMP(0x4D, 0x41)); L(JE(0x7F));
L(SET(0x45, 0x0F)); L(CH(0xE0));
L(SET(0x45, 0x82)); L(CH(0xE0));
L(GET(0x4E, 0x0E)); L(ADD(0x4E, 4));
L(SUBV(0x4D, 0x4E));
L(CH(0xE5));
L(RET());
B();

C('H_7F: forward JB - emit 0F 82 placeholder and record fixup');
L(H(0x7F));
L(SET(0x45, 0x0F)); L(CH(0xE0));
L(SET(0x45, 0x82)); L(CH(0xE0));
L(CH(0xE6));
L(SET(0x45, 0));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L(RET());
B();

// H_7B: opcode 0x78 hh - emit JAE rel32 (0F 83 disp32)
C('H_7B: opcode 0x78 hh - emit JAE rel32');
L(H(0x7B));
L(CH(0xE7));
L(SET(0x41, 0)); L(CMP(0x4D, 0x41)); L(JE(0x80));
L(SET(0x45, 0x0F)); L(CH(0xE0));
L(SET(0x45, 0x83)); L(CH(0xE0));
L(GET(0x4E, 0x0E)); L(ADD(0x4E, 4));
L(SUBV(0x4D, 0x4E));
L(CH(0xE5));
L(RET());
B();

C('H_80: forward JAE - emit 0F 83 placeholder and record fixup');
L(H(0x80));
L(SET(0x45, 0x0F)); L(CH(0xE0));
L(SET(0x45, 0x83)); L(CH(0xE0));
L(CH(0xE6));
L(SET(0x45, 0));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L(RET());
B();

// H_7C: opcode 0x7A hh - emit JA rel32 (0F 87 disp32)
C('H_7C: opcode 0x7A hh - emit JA rel32');
L(H(0x7C));
L(CH(0xE7));
L(SET(0x41, 0)); L(CMP(0x4D, 0x41)); L(JE(0x81));
L(SET(0x45, 0x0F)); L(CH(0xE0));
L(SET(0x45, 0x87)); L(CH(0xE0));
L(GET(0x4E, 0x0E)); L(ADD(0x4E, 4));
L(SUBV(0x4D, 0x4E));
L(CH(0xE5));
L(RET());
B();

C('H_81: forward JA - emit 0F 87 placeholder and record fixup');
L(H(0x81));
L(SET(0x45, 0x0F)); L(CH(0xE0));
L(SET(0x45, 0x87)); L(CH(0xE0));
L(CH(0xE6));
L(SET(0x45, 0));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));
L(RET());
B();

// ── H_60: opcode 0x20 id sz - emit VirtualAlloc ────────────────────────────────
// Emits: xor rcx,rcx; mov rdx,size; mov r8,0x3000; mov r9,0x40;
//        call [rip + VAlloc_IAT]; stPut(id,rax)
C('H_60: opcode 0x20 id sz - emit VirtualAlloc(state[id]=VirtualAlloc(0,sz,0x3000,0x40))');
L(H(0x60));
C('xor rcx, rcx');
L(SET(0x45, 0x48)); L(CH(0xE0));   // 48 31 C9
L(SET(0x45, 0x31)); L(CH(0xE0));
L(SET(0x45, 0xC9)); L(CH(0xE0));
C('mov rdx, size (state_51)');
L(SET(0x45, 0x48)); L(CH(0xE0));   // 48 BA <size 8 LE>
L(SET(0x45, 0xBA)); L(CH(0xE0));
L(CH(0xED) + '  ; decompose state_51 -> state_4F=b0, state_47=b1');
L('57 03 0E 4F'); L(INC(0x0E));
L('57 03 0E 47'); L(INC(0x0E));
L(SET(0x45, 0));
L('57 03 0E 45'); L(INC(0x0E));   L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));   L('57 03 0E 45'); L(INC(0x0E));
L('57 03 0E 45'); L(INC(0x0E));   L('57 03 0E 45'); L(INC(0x0E));
C('mov r8, 0x3000');
L(SET(0x45, 0x49)); L(CH(0xE0));  // 49 B8 00300000 00000000
L(SET(0x45, 0xB8)); L(CH(0xE0));
L(SET(0x45, 0x00)); L(CH(0xE0));  L(SET(0x45, 0x30)); L(CH(0xE0));
L(SET(0x45, 0x00)); L(CH(0xE0));  L(SET(0x45, 0x00)); L(CH(0xE0));
L(SET(0x45, 0x00)); L(CH(0xE0));  L(SET(0x45, 0x00)); L(CH(0xE0));
L(SET(0x45, 0x00)); L(CH(0xE0));  L(SET(0x45, 0x00)); L(CH(0xE0));
C('mov r9, 0x40');
L(SET(0x45, 0x49)); L(CH(0xE0));  // 49 B9 40000000 00000000
L(SET(0x45, 0xB9)); L(CH(0xE0));
L(SET(0x45, 0x40)); L(CH(0xE0));  L(SET(0x45, 0x00)); L(CH(0xE0));
L(SET(0x45, 0x00)); L(CH(0xE0));  L(SET(0x45, 0x00)); L(CH(0xE0));
L(SET(0x45, 0x00)); L(CH(0xE0));  L(SET(0x45, 0x00)); L(CH(0xE0));
L(SET(0x45, 0x00)); L(CH(0xE0));  L(SET(0x45, 0x00)); L(CH(0xE0));
C('call [rip + VirtualAlloc IAT]');
C('  disp32 = 0x5038 - (0x1000 + state_0E + 6) = 0x4034 - state_0E');
L(SET(0x45, 0xFF)); L(CH(0xE0));   // FF 15 <disp32>
L(SET(0x45, 0x15)); L(CH(0xE0));
L(SET(0x4D, 0x4034));
L(SUBV(0x4D, 0x0E) + '  ; disp32 = 0x4034 - state_0E');
L(CH(0xE5));                        // emit disp32
L(GET(0x46, 0x50)); L(CH(0xE3));   // stPut(id, RAX)
L(RET());
B();

// ── H_61: opcode 0x50 id str - emit LoadFile ──────────────────────────────────
// Reads file named by string[str_idx] into buffer, stores (ptr,size) in state[id],[id+1]
// Emits CreateFileA + GetFileSize + VirtualAlloc + ReadFile + CloseHandle
C('H_61: opcode 0x50 id str_idx - emit LoadFile');
C('  state[id] = buffer, state[id+1] = file_size');
L(H(0x61));
C('lea rcx, [rip + string_data_addr] - filename from data section');
C('  string offset = str_list_off(state_51), str_at data_base');
C('  disp32 = 0x5000 + str_list_start + str_idx*entry_size - ...');
C('  Simplified: hardcoded string table offsets for mini-kyc (idx 0="input.ky", idx 1="output.exe")');
C('  str_list_start = 16, entry_size = 4 + len + 1');
C('  For generic: use data_base (state_08) + 16 + (state_51 * entry_size calc)');

// ── Helper sub-handler: H_85 - emit CreateFileA call (filename already in RCX, access in RDX) ──
// Emits CreateFileA setup + call + handle in RAX (for LoadFile)
// For LoadFile: access=0x80000000, share=3, security=NULL, disposition=3, flags=0x80, template=NULL
C('H_85: emit CreateFileA(rcx=filename,rdx=access,r8=share,r9=security,stack{disposition,flags,template})');
L(H(0x85));
C('mov r8, 3 (FILE_SHARE_READ)');
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0xB8)); L(CH(0xE0));
L(SET(0x45, 3)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
C('xor r9, r9 (security=NULL)');
L(SET(0x45, 0x4D)); L(CH(0xE0)); L(SET(0x45, 0x31)); L(CH(0xE0)); L(SET(0x45, 0xC9)); L(CH(0xE0));
C('stack: disposition=3, flags=0x80, template=NULL');
L('48 C7 44 24 20 03 00 00 00'); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E));
L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); // mov [rsp+0x20], 3
L('48 C7 44 24 28 80 00 00 00'); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E));
L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); // mov [rsp+0x28], 0x80
L('48 C7 44 24 30 00 00 00 00'); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E));
L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); // mov [rsp+0x30], 0
C('call [CreateFileA IAT]');
L(SET(0x45, 0xFF)); L(CH(0xE0));
L(SET(0x45, 0x15)); L(CH(0xE0));
L(SET(0x4D, 0x401C)); L(SUBV(0x4D, 0x0E) + '  ; disp = 0x401C - state_0E');
L(CH(0xE5));
L(RET());
B();

// ── H_61: opcode 0x50 id str_idx - emit LoadFile ──────────────────────────────
// For self-hosting bootstrap: string 0="input.ky", string 1="output.exe"
// Embed filename inline using jmp-over + LEA trick, then CreateFileA + GetFileSize + VirtualAlloc + ReadFile + CloseHandle
C('H_61: opcode 0x50 id str_idx - emit LoadFile');
L(H(0x61));
C('Embed filename: check if str_idx==0 ("input.ky") or str_idx==1 ("output.exe")');
C('Use jmp-over-filename trick for both cases');
L(SET(0x41, 0)); L(CMP(0x51, 0x41)); L(JE(0x86) + '  ; str_idx==0 -> "input.ky"');
C('str_idx==1: embed "output.exe"');
L('EB 11'); L(INC(0x0E)); L(INC(0x0E));   // jmp $+0x13 (over 17 bytes of filename+lea)
L(SET(0x45, 0x6F)); L(CH(0xE0));   // 'o'
L(SET(0x45, 0x75)); L(CH(0xE0));   // 'u'
L(SET(0x45, 0x74)); L(CH(0xE0));   // 't'
L(SET(0x45, 0x70)); L(CH(0xE0));   // 'p'
L(SET(0x45, 0x75)); L(CH(0xE0));   // 'u'
L(SET(0x45, 0x74)); L(CH(0xE0));   // 't'
L(SET(0x45, 0x2E)); L(CH(0xE0));   // '.'
L(SET(0x45, 0x65)); L(CH(0xE0));   // 'e'
L(SET(0x45, 0x78)); L(CH(0xE0));   // 'x'
L(SET(0x45, 0x65)); L(CH(0xE0));   // 'e'
L(SET(0x45, 0)); L(CH(0xE0));      // NUL
L(JMP(0x87) + '  ; -> emit LEA');
B();

C('H_86: embed "input.ky" for str_idx==0');
L(H(0x86));
L('EB 0C'); L(INC(0x0E)); L(INC(0x0E));   // jmp $+14 (over 12 bytes of filename+lea)
L(SET(0x45, 0x69)); L(CH(0xE0));   // 'i'
L(SET(0x45, 0x6E)); L(CH(0xE0));   // 'n'
L(SET(0x45, 0x70)); L(CH(0xE0));   // 'p'
L(SET(0x45, 0x75)); L(CH(0xE0));   // 'u'
L(SET(0x45, 0x74)); L(CH(0xE0));   // 't'
L(SET(0x45, 0x2E)); L(CH(0xE0));   // '.'
L(SET(0x45, 0x6B)); L(CH(0xE0));   // 'k'
L(SET(0x45, 0x79)); L(CH(0xE0));   // 'y'
L(SET(0x45, 0)); L(CH(0xE0));      // NUL
B();

C('H_87: emit LEA rcx, [rip - distance_to_filename] and continue');
L(H(0x87));
C('Compute disp: For "input.ky": filename at code_off-(8+2), LEA at code_off');
C('  LEA rcx, [rip + disp32] = 7 bytes, RIP after = code_off+7');
C('  disp = filename_start - (code_off+7) = -(8+2+7) for "input.ky" = -17');
C('  For "output.exe": disp = -(11+2+7) = -20');
C('  Since we don\'t know which was emitted, compute at runtime');
C('  Actually just pre-compute disp based on str_idx check above');
C('  For simplicity, use fixed disp: "input.ky" disp=-17, "output.exe" disp=-20');
C('  But emit-relative disp is also off by jmp size difference. Let me use simple hardcode:');
L(SET(0x45, 0x48)); L(CH(0xE0));   // REX.W
L(SET(0x45, 0x8D)); L(CH(0xE0));   // LEA
L(SET(0x45, 0x0D)); L(CH(0xE0));   // ModRM(0,1,5) = [rip+disp]
C('Emit disp32 = -17 for "input.ky" (str_idx=0) or -20 for "output.exe" (str_idx=1)');
C('We need to check str_idx and emit appropriate disp');
L(SET(0x41, 0)); L(CMP(0x51, 0x41)); L(JE(0x88) + '  ; str_idx==0 -> disp=-17');
C('str_idx==1: disp = -20 = 0xFFFFFFEC');
L(SET(0x4D, 0xFFEC)); L(CH(0xE5));  // emit -20 as LE32 (low 16 bits)
L(JMP(0x89));
B();

C('H_88: disp = -17 = 0xFFFFFFEF for "input.ky"');
L(H(0x88));
L(SET(0x4D, 0xFFEF)); L(CH(0xE5));
B();

C('H_89: filename in RCX -> CreateFileA call');
L(H(0x89));
C('mov rdx, 0x80000000 (GENERIC_READ)');
L(SET(0x45, 0x48)); L(CH(0xE0)); L(SET(0x45, 0xBA)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0x80)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
C('call H_85 to emit CreateFileA + stack args');
L(CH(0x85));
C('mov r13, rax (file handle)');
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xC5)); L(CH(0xE0));
C('mov rcx, r13; xor rdx,rdx; call GetFileSize');
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xCD)); L(CH(0xE0)); // mov rcx, r13
L(SET(0x45, 0x48)); L(CH(0xE0)); L(SET(0x45, 0x31)); L(CH(0xE0)); L(SET(0x45, 0xD2)); L(CH(0xE0)); // xor rdx, rdx
L(SET(0x45, 0xFF)); L(CH(0xE0)); L(SET(0x45, 0x15)); L(CH(0xE0));  // call [GetFileSize]
L(SET(0x4D, 0x4024)); L(SUBV(0x4D, 0x0E) + '  ; disp = 0x4024 - state_0E');
L(CH(0xE5));
C('mov r12, rax (file size)');
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xC4)); L(CH(0xE0));
C('VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)');
L(SET(0x45, 0x48)); L(CH(0xE0)); L(SET(0x45, 0x31)); L(CH(0xE0)); L(SET(0x45, 0xC9)); L(CH(0xE0)); // xor rcx, rcx
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xD4)); L(CH(0xE0)); // mov rdx, r12
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0xB8)); L(CH(0xE0)); // mov r8d, 0x3000
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0x30)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0xB9)); L(CH(0xE0)); // mov r9d, 0x40
L(SET(0x45, 0x40)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
L(SET(0x45, 0xFF)); L(CH(0xE0)); L(SET(0x45, 0x15)); L(CH(0xE0));  // call [VirtualAlloc]
L(SET(0x4D, 0x4034)); L(SUBV(0x4D, 0x0E) + '  ; disp = 0x4034 - state_0E');
L(CH(0xE5));
C('stPut(id, RAX) = buffer, stPut(id+1, R12) = size');
L(GET(0x46, 0x50)); L(CH(0xE3));   // stPut(id, RAX) = buffer
L(ADD(0x50, 1));                     // id+1
L(GET(0x46, 0x50)); L(CH(0xEB));   // stGet(RDX, id+1) - for stPut
// Actually we want stPut(id+1, R12) but R12 value is in a register, not from a state
// We need to mov [r15 + (id+1)*8], r12
// That's: REX(0x4D) 89 A7 <disp> = mov [r15 + disp], r12
L(SET(0x45, 0x4D)); L(CH(0xE0));   // REX.W REX.B(R15)
L(SET(0x45, 0x89)); L(CH(0xE0));   // MOV opcode
L(SET(0x45, 0xA7)); L(CH(0xE0));   // ModRM(2,4=R12,7=R15)
L(GET(0x46, 0x50)); L(CH(0xE1));   // compute disp for id+1 in state_46
L(CH(0xE4));                        // emit disp32
L(SUB(0x50, 1));                     // restore id
C('ReadFile(handle, buffer, size, &bytesWritten, NULL)');
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xCD)); L(CH(0xE0)); // mov rcx, r13
L(GET(0x46, 0x50)); L(CH(0xE2));   // stGet(RAX, id) = buffer
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xC2)); L(CH(0xE0)); // mov rdx, rax
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xE0)); L(CH(0xE0)); // mov r8, r12
L('48 8D 4C 24 20'); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); // lea r9, [rsp+0x20]
L('48 C7 44 24 20 00 00 00 00'); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E));
L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); // mov [rsp+0x20], 0
L(SET(0x45, 0xFF)); L(CH(0xE0)); L(SET(0x45, 0x15)); L(CH(0xE0));  // call [ReadFile]
L(SET(0x4D, 0x4014)); L(SUBV(0x4D, 0x0E) + '  ; disp = 0x4014 - state_0E');
L(CH(0xE5));
C('CloseHandle(r13)');
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xCD)); L(CH(0xE0)); // mov rcx, r13
L(SET(0x45, 0xFF)); L(CH(0xE0)); L(SET(0x45, 0x15)); L(CH(0xE0));  // call [CloseHandle]
L(SET(0x4D, 0x402C)); L(SUBV(0x4D, 0x0E) + '  ; disp = 0x402C - state_0E');
L(CH(0xE5));
L(RET());
B();

// ── H_62: opcode 0x51 id str_idx sz - emit WriteFile ──────────────────────────
C('H_62: opcode 0x51 id str_idx sz - emit WriteFile');
L(H(0x62));
C('Embed filename (same as LoadFile)');
L(SET(0x41, 0)); L(CMP(0x51, 0x41)); L(JE(0x8A) + '  ; str_idx==0 -> "input.ky"');
C('str_idx==1: embed "output.exe"');
L('EB 11'); L(INC(0x0E)); L(INC(0x0E));
L(SET(0x45, 0x6F)); L(CH(0xE0)); L(SET(0x45, 0x75)); L(CH(0xE0));
L(SET(0x45, 0x74)); L(CH(0xE0)); L(SET(0x45, 0x70)); L(CH(0xE0));
L(SET(0x45, 0x75)); L(CH(0xE0)); L(SET(0x45, 0x74)); L(CH(0xE0));
L(SET(0x45, 0x2E)); L(CH(0xE0)); L(SET(0x45, 0x65)); L(CH(0xE0));
L(SET(0x45, 0x78)); L(CH(0xE0)); L(SET(0x45, 0x65)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0));
L(JMP(0x8B));
B();

C('H_8A: embed "input.ky"');
L(H(0x8A));
L('EB 0C'); L(INC(0x0E)); L(INC(0x0E));
L(SET(0x45, 0x69)); L(CH(0xE0)); L(SET(0x45, 0x6E)); L(CH(0xE0));
L(SET(0x45, 0x70)); L(CH(0xE0)); L(SET(0x45, 0x75)); L(CH(0xE0));
L(SET(0x45, 0x74)); L(CH(0xE0)); L(SET(0x45, 0x2E)); L(CH(0xE0));
L(SET(0x45, 0x6B)); L(CH(0xE0)); L(SET(0x45, 0x79)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0));
B();

C('H_8B: emit LEA rcx + CreateFileA for WRITE');
L(H(0x8B));
L(SET(0x45, 0x48)); L(CH(0xE0)); L(SET(0x45, 0x8D)); L(CH(0xE0)); L(SET(0x45, 0x0D)); L(CH(0xE0));
L(SET(0x41, 0)); L(CMP(0x51, 0x41)); L(JE(0x8C) + '  ; str_idx==0 -> disp=-17');
L(SET(0x4D, 0xFFEC)); L(CH(0xE5));  // disp = -20
L(JMP(0x8D));
B();
L(H(0x8C));
L(SET(0x4D, 0xFFEF)); L(CH(0xE5));  // disp = -17
B();
L(H(0x8D));
C('mov rdx, 0x40000000 (GENERIC_WRITE)');
L(SET(0x45, 0x48)); L(CH(0xE0)); L(SET(0x45, 0xBA)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0x40)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
L(SET(0x45, 0)); L(CH(0xE0)); L(SET(0x45, 0)); L(CH(0xE0));
C('call H_85 for CreateFileA (share=0, disposition=2 for CREATE_ALWAYS)');
// Modify H_85 behavior: need different share/disposition/flags for write
// Instead of reusing H_85, emit directly
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x31)); L(CH(0xE0)); L(SET(0x45, 0xC0)); L(CH(0xE0)); // xor r8, r8
L(SET(0x45, 0x4D)); L(CH(0xE0)); L(SET(0x45, 0x31)); L(CH(0xE0)); L(SET(0x45, 0xC9)); L(CH(0xE0)); // xor r9, r9
L('48 C7 44 24 20 02 00 00 00'); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E));
L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); // mov [rsp+0x20], 2 (CREATE_ALWAYS)
L('48 C7 44 24 28 80 00 00 00'); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E));
L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); // mov [rsp+0x28], 0x80
L('48 C7 44 24 30 00 00 00 00'); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E));
L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); // mov [rsp+0x30], 0
L(SET(0x45, 0xFF)); L(CH(0xE0)); L(SET(0x45, 0x15)); L(CH(0xE0));
L(SET(0x4D, 0x401C)); L(SUBV(0x4D, 0x0E) + '  ; disp = 0x401C - state_0E');
L(CH(0xE5));
C('mov r13, rax (file handle)');
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xC5)); L(CH(0xE0));
C('WriteFile(handle, buffer, size, &written, NULL)');
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xCD)); L(CH(0xE0)); // mov rcx, r13
L(GET(0x46, 0x50)); L(CH(0xE2));   // stGet(RAX, id) = buffer
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xC2)); L(CH(0xE0)); // mov rdx, rax
L(GET(0x46, 0x52)); L(CH(0xE2));   // stGet(RAX, sz) = size
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xC0)); L(CH(0xE0)); // mov r8, rax
L('48 8D 4C 24 20'); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); // lea r9, [rsp+0x20]
L('48 C7 44 24 20 00 00 00 00'); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E));
L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); L(INC(0x0E)); // mov [rsp+0x20], 0
L(SET(0x45, 0xFF)); L(CH(0xE0)); L(SET(0x45, 0x15)); L(CH(0xE0));  // call [WriteFile]
L(SET(0x4D, 0x400C)); L(SUBV(0x4D, 0x0E) + '  ; disp = 0x400C - state_0E');
L(CH(0xE5));
C('CloseHandle(r13)');
L(SET(0x45, 0x49)); L(CH(0xE0)); L(SET(0x45, 0x89)); L(CH(0xE0)); L(SET(0x45, 0xCD)); L(CH(0xE0)); // mov rcx, r13
L(SET(0x45, 0xFF)); L(CH(0xE0)); L(SET(0x45, 0x15)); L(CH(0xE0));  // call [CloseHandle]
L(SET(0x4D, 0x402C)); L(SUBV(0x4D, 0x0E) + '  ; disp = 0x402C - state_0E');
L(CH(0xE5));
L(RET());
B();

// ════════════════════════════════════════════════════════════════════════════════
// FIXUP RESOLVER (H_63/H_64/H_65)
// At EOF, patch all recorded forward-jump displacements.
// For each fixup[i]:
//   hh = fixup_hh[i], patch_pos = fixup_pos[i]
//   target = handler_table[hh]
//   rel32 = target - (patch_pos + 4)
//   write rel32 to write_base + patch_pos  (u32 LE)
// ════════════════════════════════════════════════════════════════════════════════
C('H_63: fixup resolver - setup loop counter');
L(H(0x63));
L(SET(0x47, 0) + '  ; i = 0');
L(JMP(0x64));
B();

C('H_64: fixup resolver loop body');
L(H(0x64));
C('Exit when i >= fixup_count');
L(CMP(0x47, 0x07));
L(JAE(0x65) + '  ; i >= count -> done');
C('Compute byte offset into fixup arrays: offset = i * 4');
L(GET(0x48, 0x47));
L(ADDV(0x48, 0x48)); L(ADDV(0x48, 0x48) + ' ; state_48 = i*4');
C('Read hh from fixup_hh[i]');
L(GET(0x49, 0x05));
L(ADDV(0x49, 0x48) + '  ; state_49 = hh_base + i*4');
L(LDB(0x4A, 0x49, 0) + ' ; byte0 of hh');
L(LDB(0x4B, 0x49, 1) + ' ; byte1 of hh');
L(ADDV(0x4B, 0x4B)); L(ADDV(0x4B, 0x4B)); L(ADDV(0x4B, 0x4B)); L(ADDV(0x4B, 0x4B));
L(ADDV(0x4B, 0x4B)); L(ADDV(0x4B, 0x4B)); L(ADDV(0x4B, 0x4B)); L(ADDV(0x4B, 0x4B) + ' ; byte1*256');
L(ADDV(0x4A, 0x4B) + '  ; hh = byte0 + byte1*256');
L(GET(0x50, 0x4A) + '    ; state_50 = hh (for H_E7)');
L(CH(0xE7) + '           ; state_4D = handler_table[hh] = target offset');
C('Recompute i*4 (H_E7 trashes slot_0x48)');
L(GET(0x48, 0x47));
L(ADDV(0x48, 0x48)); L(ADDV(0x48, 0x48) + ' ; state_48 = i*4 (recomputed)');
C('Read patch_pos from fixup_pos[i]');
L(GET(0x49, 0x06));
L(ADDV(0x49, 0x48) + '  ; state_49 = pos_base + i*4');
L(LDB(0x4A, 0x49, 0));
L(LDB(0x4B, 0x49, 1));
L(ADDV(0x4B, 0x4B)); L(ADDV(0x4B, 0x4B)); L(ADDV(0x4B, 0x4B)); L(ADDV(0x4B, 0x4B));
L(ADDV(0x4B, 0x4B)); L(ADDV(0x4B, 0x4B)); L(ADDV(0x4B, 0x4B)); L(ADDV(0x4B, 0x4B));
L(ADDV(0x4A, 0x4B) + '  ; patch_pos');
C('rel32 = target - (patch_pos + 4)');
L(GET(0x4E, 0x4A));
L(ADD(0x4E, 4) + '  ; state_4E = patch_pos + 4');
L(SUBV(0x4D, 0x4E) + '  ; state_4D = rel32');
C('Write rel32 to write_base + patch_pos');
L(GET(0x4C, 0x03));
L(ADDV(0x4C, 0x4A) + '  ; state_4C = write_base + patch_pos');
L('55 4C 4D' + '         ; [state_4C] = (u32) rel32');
C('i++, loop');
L(INC(0x47));
L(JMP(0x64));
B();

C('H_65: fixup resolver done');
L(H(0x65));
L(RET());
B();

// ════════════════════════════════════════════════════════════════════════════════
// Write output file
// ════════════════════════════════════════════════════════════════════════════════
const outPath = path.join(__dirname, 'projects', 'mini-kyc.ky');
const content = lines.join('\n');
fs.writeFileSync(outPath, content);
console.log('Written ' + outPath);
console.log('  ' + lines.length + ' lines, ' + content.length + ' bytes');
