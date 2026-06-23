# textdb.js — 纯文本数据库引擎

## 迁移到 yoyo-ide

1. 把 `textdb/textdb.js` 复制到 yoyo-ide 仓库
2. 用 yoyo-ide 编译器编译成原生可执行文件

## 编译命令（参考 yoyo-ide 的 build-transpiler.js）

```bash
# 在 yoyo-ide 仓库目录下
node build-transpiler.js  # 生成 transpiler.exe
./transpiler.exe textdb.js  # 编译 textdb.js 为原生可执行文件
```

## 依赖

- Node.js (用于开发/测试)
- yoyo-ide 编译器 (用于编译成原生可执行文件)

## 功能

- TSV 格式加载/保存
- 过滤 (where)
- 排序 (orderBy)
- 聚合 (groupBy)
- 连接 (join)
- 去重 (distinct)
- 统计 (count/sum/avg/min/max)
- 转换 (map)
- 链式查询

## 性能

- 加载 7947 行 < 1 秒
- 查询/排序/聚合: 内存操作, 极快
- 保存: 写入 TSV 文件

## 与 openhxcc 集成

textdb.js 已集成到 openhxcc:
- 原子数据导出为 TSV 格式
- TSV 缓存替代 JSON 缓存
- 人类可读, Excel 可打开
