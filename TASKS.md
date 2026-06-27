# mini-kyc 编译器 — 任务清单

## 已完成
- ✅ `51`/`50` handler crash 根因定位并打workaround：文件I/O放main ops，handler只做计算
- ✅ `create-mini-kyc3.js` 生成器修复：blob offset `0000→4000`，`84` 用 `4000 8800`
- ✅ I/O 重构：`51 写output.exe` 从 H_62 移到 main ops（`41 01` 之后），H_62 改为 `FF` ret
- ✅ mini-kyc.exe 编译成功，运行后正确生成 output.exe（34816字节 PE 模板）
- ✅ encode-x64.js 重构：添加 mov_mr64/rm64/cmp_rr/sub_rr/imul_rr，移除未使用的函数
- ✅ pe-builder.js 重构
- ✅ 仓库清理：添加 .gitignore，移除旧测试文件
- ✅ 自举前置门禁脚本：`scripts/bootstrap-check.sh`
- ✅ strict 报告：`bootstrap-report.txt` + `bootstrap-report-diff.txt`
- ✅ 固定基线与锁定检查：`bootstrap-baseline.txt` + `--strict --lock`

## 自举门禁（当前推荐流程）

1. 设定或更新基线（仅在你确认当前状态正确时执行）
	- `./scripts/bootstrap-check.sh --strict --update-baseline`
2. 日常回归门禁（每次改动后执行）
	- `./scripts/bootstrap-check.sh --strict --lock`
3. 快速健康检查（不写报告）
	- `./scripts/bootstrap-check.sh`

### 产物说明

- `bootstrap-report.txt`: 当前运行的摘要（hash 与 cmp 状态）
- `bootstrap-report-diff.txt`: 当前结果与固定基线差异
- `bootstrap-baseline.txt`: 固定基线（lock 模式对比对象）

## 下一步：实现 H_30 opcode emitter（自举关键）

### 各指令 x64 编码体积

| 组 | 指令 | x64 体积 | 关键点 |
|----|------|---------|--------|
| 简单 | `FF` ret | 1B | `C3` |
| 简单 | `71-7A` jcc | 6B | `0F [tbl[cc]] [rel32]` |
| 简单 | `70` jmp | 5B | `E9 [rel32]` |
| 简单 | `41` call | 5B | `E8 [rel32]` |
| 中等 | `66 ss` inc | 12-18B | stGet+add_ri(1)+stPut |
| 中等 | `60 dd ss` copy | 6-14B | stGet+stPut |
| 中等 | `30 ss vv` set | 13-17B | mov_ri(vv)+stPut |
| 中等 | `65 a b` cmp | 9-17B | 2×stGet+cmp_rr |
| 中等 | `62 ss vv` sub | 10-18B | stGet+sub_ri+stPut |
| 中等 | `68 a b` add | 9-17B | 2×stGet+add_rr+stPut |
| 中等 | `80 dd ss oo` ldb | 11-14B | stGet+movzx+stPut |
| 中等 | `84 dd ss ll` cpy | 23B | stGet+ld(RSI)+mov_ri(rcx)+rep movsb |
| 复杂 | `20 ss vv` alloc | ~50B | 4×mov_ri+call[VirtualAlloc]+stPut |
| 复杂 | `51` write | ~129B | CreateFileA+WriteFile+CloseHandle |
| 复杂 | `50` read | ~193B | CreateFileA+GetFileSize+VirtualAlloc+ReadFile+CloseHandle |

### 实现策略

**Phase 1 — 最小自举子集**（6个常用指令）
- 只用 `30`、`60`、`66`、`70`、`71`(je)、`FF` 这 6 个指令就能写有用的 ky 程序
- 实现 H_30 对这 6 个指令的发射
- 验证 mini-kyc.exe → mini-kyc2.exe 自举链路
- jmp/call rel32 **预先计算好长度**（所有 handler 在第一次编译时 layout 固定），发射时用已知偏移

**Phase 2 — 完整指令集**
- 逐个添加剩余的指令：`65`、`62`、`68`、`41`、`71-7A` 其他 jcc、`80`、`84`
- 支持 `20`(VirtualAlloc)、`50`(read)、`51`(write) —— 需要 `call_rip` IAT fixup

**Phase 3 — 完善与验证**
- 三阶段自举测试：mini-kyc.exe → mini-kyc2.exe → mini-kyc3.exe
- 二进制完全一致证明 self-hosting 成功

### 关键知识

- stGet/stPut disp8 threshold: state_id ≤ 15 → disp8 (4B), state_id ≥ 16 → disp32 (7B)
- add_ri/sub_ri s8 threshold: imm ∈ [-128, 127] → 4B, else → 7B
- ModRM 计算需要 lookup table（ky 无位运算）
- `ld` 的 RIP-relative 值 = dataRVA + dataOffset - (textRVA + instrOffset + 7)
- jmp/call rel32 = target_offset - (current_offset + 5)
- jcc rel32 = target_offset - (current_offset + 6)
- 所有 jcc 编码表（jcc32 lookup in encode-x64.js:117）: `[0x84,0x85,0x8C,0x8D,0x8E,0x8F,0x82,0x83,0x86,0x87]` 对应 ky 71-7A

### 相关文件
- `F:\yoyo-ide\projects\mini-kyc.ky`: 编译器源码（当前 scanner + placeholder emitter）
- `F:\yoyo-ide\create-mini-kyc3.js`: 生成器（下一步需要扩展 H_30 发射代码生成）
- `F:\yoyo-ide\ky-compiler.js`: JS 参考实现（emit 函数 lines 89-169）
- `F:\yoyo-ide\encode-x64.js`: x64 编码参考（全部指令 133 lines）
- `F:\yoyo-ide\pe-builder.js`: PE 构建器
