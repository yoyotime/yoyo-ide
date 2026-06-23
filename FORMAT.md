# 文本数据库存储格式规范

## 1. 文件格式

**TSV (Tab-Separated Values)**，UTF-8 编码，LF 换行。

```
列名1\t列名2\t列名3\t...
值1\t值2\t值3\t...
值1\t值2\t值3\t...
```

## 2. 表结构

### atoms.tsv — 原子数据表

| 列名 | 类型 | 说明 |
|---|---|---|
| date | string | 日期时间 (YYYY-MM-DD HH:MM) |
| team | string | 班组名 |
| company | string | 公司名 |
| worktype | string | 工种 (钢筋/竖向钢筋安装/套筒安装/...) |
| factory | string | 厂房子项 |
| quantity | float64 | 完成量 |
| unit | string | 单位 (吨/根/个/平米/...) |
| people | float64 | 投入人数 |
| shift | string | 班次 (白班/夜班/空) |
| source_file | string | 来源文件名 |
| source_sheet | string | 来源 sheet 名 |
| source_row | int | 来源行号 |

### person_days.tsv — 出勤数据表

| 列名 | 类型 | 说明 |
|---|---|---|
| date | string | 日期时间 (YYYY-MM-DD HH:MM) |
| team | string | 班组名 |
| people | float64 | 出勤人数 |

## 3. 命名规则

- 表名: 小写字母 + 下划线 (atoms, person_days)
- 列名: 小写字母 + 下划线 (worktype, source_file)
- 文件扩展名: `.tsv`

## 4. 数据规则

- 空值: 空字符串 (不是 NULL)
- 数值: 小数点后 4 位 (quantity), 整数 (people, source_row)
- 日期: YYYY-MM-DD HH:MM 格式
- 工种: 使用 WorkType 常量字符串

## 5. 缓存文件

- 路径: `<dataDir>/.atom_cache.tsv`
- 格式: atoms 表 + `---PERSON_DAYS---` 分隔符 + person_days 表
- 用途: 加速重复加载, 人类可读, Excel 可打开
