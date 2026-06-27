// Minimal Windows debugger for mini-kyc.exe using koffi + Windows Debug API.
//
// Usage: node debug.js <rva> [<input.ky>]
//   <rva>: RVA in mini-kyc.exe to set hardware breakpoint on (e.g. 0x5010 = WriteFile IAT)
//   <input.ky>: input file piped to mini-kyc.exe (default: empty)
//
// On breakpoint: prints RIP/RSP/RBP/R12-R15/RAX and the caller's return stack.
// On access violation: prints RIP and registers, then exits.

const fs = require('fs');
const path = require('path');
const koffi = require('koffi');

// ─── Bind Windows Debug API via koffi ────────────────────────────────────────

const kernel32 = koffi.load('kernel32.dll');

// Basic types
const BOOL = koffi.alias('BOOL', 'int');
const DWORD = koffi.alias('DWORD', 'uint32');
const WORD = koffi.alias('WORD', 'uint16');
const BYTE = koffi.alias('BYTE', 'uint8');
const HANDLE = koffi.alias('HANDLE', 'void*');
const LPCWSTR = koffi.alias('LPCWSTR', 'uint64');
const LPWSTR = koffi.alias('LPWSTR', 'uint64');
const LPBYTE = koffi.alias('LPBYTE', 'uint64');
const LPTHREAD_START_ROUTINE = koffi.alias('LPTHREAD_START_ROUTINE', 'void*');

// STARTUPINFOW
const STARTUPINFOW = koffi.struct('STARTUPINFOW', {
  cb: DWORD,
  lpReserved: LPWSTR,
  lpDesktop: LPWSTR,
  lpTitle: LPWSTR,
  dwX: DWORD,
  dwY: DWORD,
  dwXSize: DWORD,
  dwYSize: DWORD,
  dwXCountChars: DWORD,
  dwYCountChars: DWORD,
  dwFillAttribute: DWORD,
  dwFlags: DWORD,
  wShowWindow: WORD,
  cbReserved2: WORD,
  lpReserved2: LPBYTE,
  hStdInput: HANDLE,
  hStdOutput: HANDLE,
  hStdError: HANDLE,
});

// PROCESS_INFORMATION
const PROCESS_INFORMATION = koffi.struct('PROCESS_INFORMATION', {
  hProcess: HANDLE,
  hThread: HANDLE,
  dwProcessId: DWORD,
  dwThreadId: DWORD,
});

// DEBUG_EVENT
const DEBUG_EVENT = koffi.struct('DEBUG_EVENT', {
  dwDebugEventCode: DWORD,
  dwProcessId: DWORD,
  dwThreadId: DWORD,
  // union of various event-specific data — declare as raw buffer
  u: koffi.array('uint8', 80),
});

// CONTEXT for x64
// We only need the integer registers; other fields are zeroed.
// Layout per winnt.h: ContextFlags (DWORD), then segments, then integer regs:
//   Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8..R15 (16 regs), Rip, EFlags
// We use a raw buffer with offsets matching CONTEXT.
const CONTEXT_SIZE = 1232; // sizeof(CONTEXT) for x64 in user-mode
const CONTEXT_BUFFER_TYPE = koffi.array('uint8', CONTEXT_SIZE);

function allocContext() {
  const buf = Buffer.alloc(CONTEXT_SIZE);
  return { ptr: koffi.address(buf), buf };
}

// Offsets within CONTEXT (x64):
const CTX = {
  ContextFlags: 0x30,
  SegCs: 0x38, SegDs: 0x3A, SegEs: 0x3C, SegFs: 0x3E, SegGs: 0x40, SegSs: 0x42,
  EFlags: 0x44,
  Dr0: 0x48, Dr1: 0x50, Dr2: 0x58, Dr3: 0x60, Dr6: 0x68, Dr7: 0x70,
  Rax: 0x78, Rcx: 0x80, Rdx: 0x88, Rbx: 0x90,
  Rsp: 0x98, Rbp: 0xA0, Rsi: 0xA8, Rdi: 0xB0,
  R8:  0xB8, R9:  0xC0, R10: 0xC8, R11: 0xD0,
  R12: 0xD8, R13: 0xE0, R14: 0xE8, R15: 0xF0,
  Rip: 0xF8,
};

// Function bindings
const CreateProcessW = kernel32.func('CreateProcessW', 'BOOL', [
  LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR,
  BOOL, DWORD, 'void*', LPCWSTR,
  koffi.pointer(STARTUPINFOW), koffi.pointer(PROCESS_INFORMATION),
]);

const WaitForDebugEvent = kernel32.func('WaitForDebugEvent', 'BOOL', [
  koffi.pointer(DEBUG_EVENT), DWORD,
]);

const ContinueDebugEvent = kernel32.func('ContinueDebugEvent', 'BOOL', [
  DWORD, DWORD, DWORD,
]);

const GetThreadContext = kernel32.func('GetThreadContext', 'BOOL', [
  'void*', 'void*',
]);

const SetThreadContext = kernel32.func('SetThreadContext', 'BOOL', [
  'void*', 'void*',
]);

const ReadProcessMemory = kernel32.func('ReadProcessMemory', 'BOOL', [
  'void*', 'void*', 'void*', 'size_t', koffi.out(koffi.pointer(DWORD)),
]);

const DebugActiveProcessStop = kernel32.func('DebugActiveProcessStop', 'BOOL', ['DWORD']);

const CloseHandle = kernel32.func('CloseHandle', 'BOOL', ['void*']);

// Debug event codes
const EXCEPTION_DEBUG_EVENT   = 1;
const CREATE_THREAD_DEBUG_EVENT = 2;
const CREATE_PROCESS_DEBUG_EVENT = 3;
const EXIT_THREAD_DEBUG_EVENT  = 4;
const EXIT_PROCESS_DEBUG_EVENT  = 5;
const LOAD_DLL_DEBUG_EVENT    = 6;
const UNLOAD_DLL_DEBUG_EVENT  = 7;
const OUTPUT_DEBUG_STRING_EVENT = 8;
const RIP_EVENT               = 9;

// Exception codes
const EXCEPTION_BREAKPOINT    = 0x80000003;
const EXCEPTION_SINGLE_STEP   = 0x80000004;
const EXCEPTION_ACCESS_VIOLATION = 0xC0000005;

// Continue status
const DBG_CONTINUE = 0x00010002;
const DBG_EXCEPTION_HANDLED = 0x00010001;
const DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

// CREATE_PROCESS_DEBUG_EVENT data layout (offset within DEBUG_EVENT.u):
//   HANDLE hFile (8)
//   HANDLE hProcess (8)
//   HANDLE hThread (8)
//   HANDLE hEvent (8)  — undocumented
//   LPVOID lpBaseOfImage (8)
//   DWORD dwDebugInfoFileOffset (4)
//   DWORD nDebugInfoSize (4)
//   LPTHREAD_START_ROUTINE lpThreadLocalBase (8)
//   LPTHREAD_START_ROUTINE lpStartAddress (8)
//   LPVOID lpImageName (8)
//   WORD  fUnicode (2)
// padding to align, total ~80 bytes
const U_OFFSET = 16; // skip 4 DWORDs at start

// ─── Helpers ────────────────────────────────────────────────────────────────

function toWide(s) {
  const buf = Buffer.from(s + '\0', 'ucs2');
  return koffi.address(buf);
}

function dumpContext(ctxBuf, label) {
  const buf = ctxBuf.buf || ctxBuf;
  const get = off => buf.readBigUInt64LE(off);
  console.log(`--- ${label} ---`);
  console.log(`  RIP = 0x${get(CTX.Rip).toString(16)}`);
  console.log(`  RSP = 0x${get(CTX.Rsp).toString(16)}`);
  console.log(`  RBP = 0x${get(CTX.Rbp).toString(16)}`);
  console.log(`  RAX = 0x${get(CTX.Rax).toString(16)}  RCX = 0x${get(CTX.Rcx).toString(16)}`);
  console.log(`  RDX = 0x${get(CTX.Rdx).toString(16)}  RBX = 0x${get(CTX.Rbx).toString(16)}`);
  console.log(`  RSI = 0x${get(CTX.Rsi).toString(16)}  RDI = 0x${get(CTX.Rdi).toString(16)}`);
  console.log(`  R8  = 0x${get(CTX.R8).toString(16)}  R9  = 0x${get(CTX.R9).toString(16)}`);
  console.log(`  R10 = 0x${get(CTX.R10).toString(16)} R11 = 0x${get(CTX.R11).toString(16)}`);
  console.log(`  R12 = 0x${get(CTX.R12).toString(16)} R13 = 0x${get(CTX.R13).toString(16)}`);
  console.log(`  R14 = 0x${get(CTX.R14).toString(16)} R15 = 0x${get(CTX.R15).toString(16)}`);
  console.log(`  EFlags = 0x${buf.readUInt32LE(CTX.EFlags).toString(16)}`);
}

function readState(process, r15, slot) {
  if (r15 === 0n) return 0n;
  const addr = Number(r15) + slot * 8;
  const buf = Buffer.alloc(8);
  const bytesRead = [0];
  const ok = ReadProcessMemory(process, addr, buf, 8, bytesRead);
  if (!ok || bytesRead[0] !== 8) return null;
  return buf.readBigUInt64LE(0);
}

const WriteProcessMemory = kernel32.func('WriteProcessMemory', 'BOOL', [
  HANDLE, 'void*', 'void*', 'size_t', koffi.out(koffi.pointer(DWORD)),
]);

function patchExeWithInt3(exePath, rvas) {
  const buf = fs.readFileSync(exePath);
  const origBytes = {};
  for (const rva of rvas) {
    const fileOff = 0x400 + (rva - 0x1000); // .text: RVA 0x1000, file offset 0x400
    origBytes[rva] = buf[fileOff];
    buf[fileOff] = 0xCC;
    console.log(`[*] INT3 at RVA 0x${rva.toString(16)} (file off 0x${fileOff.toString(16)}, orig=0x${origBytes[rva].toString(16)})`);
  }
  const tmpPath = exePath.replace('.exe', '-patched-' + Date.now() + '.exe');
  fs.writeFileSync(tmpPath, buf);
  return { tmpPath, origBytes };
}

function main() {
  const inputFile = process.argv[2] || null;
  const exePath = path.join(__dirname, 'mini-kyc.exe');

  // ── INT3 probe: checkpoint RVAs to narrow down hang ─────────────────
  // After startup (68 bytes = 0x44), first top-level opcode is LoadFile (0x50).
  // The RVA list below are guessed probe points. We update them based on results.
  const CHECKPOINTS = [0x1000, 0x1044, 0x1080, 0x1100, 0x1200];
  let checkIdx = 0;
  const { tmpPath: patchedExe, origBytes } = patchExeWithInt3(exePath, CHECKPOINTS);

  console.log(`[*] Patched exe: ${patchedExe}`);
  console.log(`[*] INT3 checkpoints: ${CHECKPOINTS.map(r=>'0x'+r.toString(16)).join(', ')}`);
  console.log(`[*] Input file: ${inputFile || '(none)'}`);

  // Prepare stdin redirection if input file given
  let stdinReadHandle = null;
  if (inputFile) {
    const GENERIC_READ = 0x80000000;
    const FILE_SHARE_READ = 1;
    const OPEN_EXISTING = 3;
    const CreateFileW = kernel32.func('CreateFileW', 'void*', [
      LPCWSTR, DWORD, DWORD, 'void*', DWORD, DWORD, 'void*',
    ]);
    stdinReadHandle = CreateFileW(
      toWide(inputFile),
      GENERIC_READ,
      FILE_SHARE_READ,
      null,
      OPEN_EXISTING,
      0x80, // FILE_ATTRIBUTE_NORMAL
      null,
    );
    if (!stdinReadHandle || koffi.address(stdinReadHandle) === 0xFFFFFFFFFFFFFFFFn) {
      console.error('[!] Failed to open input file');
      process.exit(1);
    }
  }

  // Setup STARTUPINFOW
  const siBuf = Buffer.alloc(Number(STARTUPINFOW.size));
  siBuf.writeUInt32LE(Number(STARTUPINFOW.size), 0); // cb
  siBuf.writeUInt32LE(0x00000100, 0x30 + 0x18); // dwFlags STARTF_USESTDHANDLES
  if (stdinReadHandle) {
    // hStdInput is at offset 0x38 + 0x10 in STARTUPINFOW? Let me compute
    // STARTUPINFOW layout: cb(4) + Reserved(8) + Desktop(8) + Title(8) + X(4)+Y(4)+XSize(4)+YSize(4)+
    //   XCountChars(4)+YCountChars(4)+FillAttribute(4)+dwFlags(4)+wShowWindow(2)+cbReserved2(2)+
    //   lpReserved2(8) + hStdInput(8) + hStdOutput(8) + hStdError(8) = 0x58 bytes
    siBuf.writeBigUInt64LE(BigInt(koffi.address(stdinReadHandle).toString()), 0x48);
  }
  const piBuf = Buffer.alloc(Number(PROCESS_INFORMATION.size));

  const DEBUG_PROCESS              = 0x00000001;
  const DEBUG_ONLY_THIS_PROCESS    = 0x00000002;

  const ok = CreateProcessW(
    toWide(patchedExe),
    koffi.address(Buffer.alloc(0)), // lpCommandLine = NULL
    koffi.address(Buffer.alloc(0)), // lpProcessAttributes = NULL
    koffi.address(Buffer.alloc(0)), // lpThreadAttributes = NULL
    1, // bInheritHandles
    DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
    koffi.address(Buffer.alloc(0)), // lpEnvironment = NULL
    koffi.address(Buffer.alloc(0)), // lpCurrentDirectory = NULL
    koffi.address(siBuf),
    koffi.address(piBuf),
  );
  if (!ok) {
    console.error('[!] CreateProcessW failed');
    process.exit(1);
  }
  console.log(`[*] Process started: PID ${piBuf.readUInt32LE(8)}`);

  let imageBase = 0n;
  // PROCESS_INFORMATION layout: hProcess(8), hThread(8), dwProcessId(4), dwThreadId(4)
  const processHandle = piBuf.readBigUInt64LE(0);
  const mainThreadHandle = piBuf.readBigUInt64LE(8);
  const processId = piBuf.readUInt32LE(16);
  console.log(`[*] hProcess=${processHandle} hThread=${mainThreadHandle}`);
  let hitCount = 0;
  let crashed = false;

  // Helper: dump current thread registers + state
  const dumpState = (label) => {
    const ctx = allocContext();
    ctx.buf.writeUInt32LE(0x0010000F, CTX.ContextFlags);
    if (!GetThreadContext(mainThreadHandle, ctx.ptr)) return;
    const rip = ctx.buf.readBigUInt64LE(CTX.Rip);
    const r15 = ctx.buf.readBigUInt64LE(CTX.R15);
    const rsp = ctx.buf.readBigUInt64LE(CTX.Rsp);
    const rax = ctx.buf.readBigUInt64LE(CTX.Rax);
    const rcx = ctx.buf.readBigUInt64LE(CTX.Rcx);
    const rdx = ctx.buf.readBigUInt64LE(CTX.Rdx);
    const r8  = ctx.buf.readBigUInt64LE(CTX.R8);
    const r9  = ctx.buf.readBigUInt64LE(CTX.R9);
    const r12 = ctx.buf.readBigUInt64LE(CTX.R12);
    const r13 = ctx.buf.readBigUInt64LE(CTX.R13);
    const r14 = ctx.buf.readBigUInt64LE(CTX.R14);
    console.log(`\n=== ${label} ===`);
    console.log(`  RIP=0x${rip.toString(16)} (RVA 0x${(rip - imageBase).toString(16)})`);
    console.log(`  R15=0x${r15.toString(16)} RSP=0x${rsp.toString(16)} RAX=0x${rax.toString(16)}`);
    console.log(`  RCX=0x${rcx.toString(16)} RDX=0x${rdx.toString(16)} R8=0x${r8.toString(16)} R9=0x${r9.toString(16)}`);
    console.log(`  R12=0x${r12.toString(16)} R13=0x${r13.toString(16)} R14=0x${r14.toString(16)}`);
    // State slots
    if (r15 !== 0n) {
      console.log('  State slots:');
      for (let slot = 0; slot < 0x10; slot++) {
        const v = readState(processHandle, r15, slot);
        if (v !== null && v !== 0n) console.log(`    [0x${slot.toString(16)}] = 0x${v.toString(16)}`);
      }
    }
  };

  // Restore INT3 back to original byte via WriteProcessMemory
  const restoreInt3 = (rva) => {
    if (origBytes[rva] === undefined) return;
    const addr = Number(imageBase + BigInt(rva));
    const buf = Buffer.from([origBytes[rva]]);
    const bw = [0];
    const ok = WriteProcessMemory(processHandle, addr, koffi.address(buf), 1, bw);
    if (ok) console.log(`[*] Restored RVA 0x${rva.toString(16)} to 0x${origBytes[rva].toString(16)}`);
  };

  // Debug event loop
  const eventBuf = Buffer.alloc(Number(DEBUG_EVENT.size));
  while (true) {
    const got = WaitForDebugEvent(koffi.address(eventBuf), 10000); // 10s timeout
    if (!got) {
      // Check which checkpoints were hit vs missed
      const hit = checkIdx;
      const nextRva = CHECKPOINTS[checkIdx];
      if (nextRva !== undefined) {
        console.error(`[!] TIMEOUT after checkpoint 0x${CHECKPOINTS[Math.max(0,checkIdx-1)].toString(16)} — never hit 0x${nextRva.toString(16)}`);
        console.error(`[!] Hang is BETWEEN RVA 0x${CHECKPOINTS[Math.max(0,checkIdx-1)].toString(16)} and RVA 0x${nextRva.toString(16)}`);
      } else {
        console.error('[!] WaitForDebugEvent failed (final timeout)');
      }
      break;
    }
    const code = eventBuf.readUInt32LE(0);
    const pid = eventBuf.readUInt32LE(4);
    const tid = eventBuf.readUInt32LE(8);

    if (code === EXCEPTION_DEBUG_EVENT) {
      const exCode = eventBuf.readUInt32LE(U_OFFSET);

      if (exCode === EXCEPTION_BREAKPOINT) {
        // ExceptionAddress = address of the INT3 instruction
        const exAddr = eventBuf.readBigUInt64LE(U_OFFSET + 16);
        const hitRva = Number(exAddr - imageBase);

        // System initial BP (ntdll, not in our .text)
        if (hitRva < 0x1000) {
          console.log(`[*] System BP at 0x${exAddr.toString(16)}`);
          ContinueDebugEvent(pid, tid, DBG_CONTINUE);
          continue;
        }

        const idx = CHECKPOINTS.indexOf(hitRva);
        if (idx >= 0) {
          hitCount++;
          const ctx = allocContext();
          ctx.buf.writeUInt32LE(0x0010000F, CTX.ContextFlags);
          GetThreadContext(mainThreadHandle, ctx.ptr);
          dumpState(`INT3 #${hitCount} at RVA 0x${hitRva.toString(16)}`);
          restoreInt3(hitRva);
          // RIP points past INT3; set it back to execute original instruction
          const rip = ctx.buf.readBigUInt64LE(CTX.Rip);
          ctx.buf.writeBigUInt64LE(rip - 1n, CTX.Rip);
          SetThreadContext(mainThreadHandle, ctx.ptr);
          checkIdx = idx + 1;
          ContinueDebugEvent(pid, tid, DBG_CONTINUE);
          continue;
        }

        console.log(`[?] Unexpected BP at 0x${exAddr.toString(16)}`);
        ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED);
        continue;
      }

      if (exCode === EXCEPTION_ACCESS_VIOLATION) {
        crashed = true;
        dumpState('!!! ACCESS VIOLATION');
        const exAddr = eventBuf.readBigUInt64LE(U_OFFSET + 16);
        console.log(`  ExceptionAddress: 0x${exAddr.toString(16)}`);
        ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED);
        break;
      }

      // Other exceptions
      ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED);
      continue;

    } else if (code === CREATE_PROCESS_DEBUG_EVENT) {
      imageBase = eventBuf.readBigUInt64LE(U_OFFSET + 24);
      console.log(`[*] Image base: 0x${imageBase.toString(16)}`);
      ContinueDebugEvent(pid, tid, DBG_CONTINUE);
      continue;
    } else if (code === EXIT_PROCESS_DEBUG_EVENT) {
      const exitCode = eventBuf.readUInt32LE(U_OFFSET);
      console.log(`[*] Process exited with code ${exitCode}`);
      break;
    } else {
      ContinueDebugEvent(pid, tid, DBG_CONTINUE);
      continue;
    }
  }

  if (stdinReadHandle) CloseHandle(stdinReadHandle);
  CloseHandle(processHandle);
  CloseHandle(mainThreadHandle);
  DebugActiveProcessStop(processId);
  console.log(`[*] Done. Hits=${hitCount}, Crashed=${crashed}`);
}

main();