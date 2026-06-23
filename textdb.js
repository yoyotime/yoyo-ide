// textdb.js — 纯文本数据库引擎
// 格式: TSV (Tab-Separated Values), 第一行为列名
// 加载快, 人类可读, Excel 可打开
//
// API:
//   load(path)                    — 加载 TSV 文件
//   table.where(col, op, value)   — 过滤 (=, !=, >, <, >=, <=, contains)
//   table.orderBy(col, desc)      — 排序
//   table.select(...cols)         — 选择列
//   table.groupBy(col, agg, fn)   — 聚合 (sum/count/avg/min/max)
//   table.limit(n)                — 限制行数
//   table.distinct(col)           — 去重
//   table.count()                 — 计数
//   table.sum(col)                — 求和
//   table.avg(col)                — 平均值
//   table.min(col)                — 最小值
//   table.max(col)                — 最大值
//   table.join(other, onCol)      — 连接
//   table.map(fn)                 — 转换
//   table.forEach(fn)             — 遍历
//   table.print(maxRows)          — 打印
//   table.save(path)              — 保存 TSV

const FS = require('fs');

class Table {
  constructor(name, columns, rows) {
    this.name = name;
    this.columns = columns;
    this.rows = rows;
    this.colIdx = {};
    for (let i = 0; i < columns.length; i++) {
      this.colIdx[columns[i]] = i;
    }
  }

  col(name) {
    const idx = this.colIdx[name];
    if (idx === undefined) throw new Error(`Column not found: ${name}`);
    return idx;
  }

  get(row, colName) {
    return this.rows[row][this.col(colName)];
  }

  getNum(row, colName) {
    const v = parseFloat(this.rows[row][this.col(colName)]);
    return isNaN(v) ? 0 : v;
  }

  get length() {
    return this.rows.length;
  }

  // ===== 查询 =====

  where(colName, op, value) {
    const idx = this.col(colName);
    const filtered = this.rows.filter(row => {
      const cell = row[idx];
      switch (op) {
        case '=':  return cell === value;
        case '!=': return cell !== value;
        case '>':  return parseFloat(cell) > parseFloat(value);
        case '<':  return parseFloat(cell) < parseFloat(value);
        case '>=': return parseFloat(cell) >= parseFloat(value);
        case '<=': return parseFloat(cell) <= parseFloat(value);
        case 'contains': return cell.includes(value);
        case 'startsWith': return cell.startsWith(value);
        case 'endsWith': return cell.endsWith(value);
        default: return false;
      }
    });
    return new Table(this.name, this.columns, filtered);
  }

  orderBy(colName, desc = false) {
    const idx = this.col(colName);
    const sorted = [...this.rows].sort((a, b) => {
      const va = parseFloat(a[idx]);
      const vb = parseFloat(b[idx]);
      if (!isNaN(va) && !isNaN(vb)) {
        return desc ? vb - va : va - vb;
      }
      return desc ? b[idx].localeCompare(a[idx]) : a[idx].localeCompare(b[idx]);
    });
    return new Table(this.name, this.columns, sorted);
  }

  select(...colNames) {
    const indices = colNames.map(c => this.col(c));
    const newRows = this.rows.map(row => indices.map(i => row[i]));
    return new Table(this.name, colNames, newRows);
  }

  limit(n) {
    return new Table(this.name, this.columns, this.rows.slice(0, n));
  }

  // ===== 聚合 =====

  groupBy(groupCol, aggCol, aggFn) {
    const gIdx = this.col(groupCol);
    const aIdx = this.col(aggCol);
    const groups = {};
    for (const row of this.rows) {
      const key = row[gIdx];
      if (!groups[key]) groups[key] = [];
      groups[key].push(parseFloat(row[aIdx]) || 0);
    }
    const result = [];
    for (const [key, values] of Object.entries(groups)) {
      let val;
      switch (aggFn) {
        case 'sum':   val = values.reduce((a, b) => a + b, 0); break;
        case 'count': val = values.length; break;
        case 'avg':   val = values.reduce((a, b) => a + b, 0) / values.length; break;
        case 'min':   val = Math.min(...values); break;
        case 'max':   val = Math.max(...values); break;
        default:      val = values.reduce((a, b) => a + b, 0);
      }
      result.push([key, String(Math.round(val * 100) / 100)]);
    }
    return new Table(this.name + '_agg', [groupCol, aggCol + '_' + aggFn], result);
  }

  distinct(colName) {
    const idx = this.col(colName);
    const seen = new Set();
    const result = [];
    for (const row of this.rows) {
      if (!seen.has(row[idx])) {
        seen.add(row[idx]);
        result.push(row);
      }
    }
    return new Table(this.name, this.columns, result);
  }

  count() {
    return this.rows.length;
  }

  sum(colName) {
    const idx = this.col(colName);
    let total = 0;
    for (const row of this.rows) {
      total += parseFloat(row[idx]) || 0;
    }
    return Math.round(total * 100) / 100;
  }

  avg(colName) {
    if (this.rows.length === 0) return 0;
    return Math.round(this.sum(colName) / this.rows.length * 100) / 100;
  }

  min(colName) {
    const idx = this.col(colName);
    let min = Infinity;
    for (const row of this.rows) {
      const v = parseFloat(row[idx]);
      if (!isNaN(v) && v < min) min = v;
    }
    return min === Infinity ? 0 : min;
  }

  max(colName) {
    const idx = this.col(colName);
    let max = -Infinity;
    for (const row of this.rows) {
      const v = parseFloat(row[idx]);
      if (!isNaN(v) && v > max) max = v;
    }
    return max === -Infinity ? 0 : max;
  }

  // ===== 连接 =====

  join(otherTable, onCol) {
    const thisIdx = this.col(onCol);
    const otherIdx = otherTable.col(onCol);
    const newColumns = [...this.columns, ...otherTable.columns.filter(c => c !== onCol)];
    const newRows = [];
    for (const row of this.rows) {
      const key = row[thisIdx];
      for (const otherRow of otherTable.rows) {
        if (otherRow[otherIdx] === key) {
          const newRow = [...row, ...otherRow.filter((_, i) => i !== otherIdx)];
          newRows.push(newRow);
        }
      }
    }
    return new Table(this.name + '_join_' + otherTable.name, newColumns, newRows);
  }

  // ===== 转换 =====

  map(fn) {
    const newRows = this.rows.map((row, i) => fn(row, i));
    return new Table(this.name, this.columns, newRows);
  }

  forEach(fn) {
    for (let i = 0; i < this.rows.length; i++) {
      fn(this.rows[i], i);
    }
  }

  // ===== 输出 =====

  print(maxRows = 20) {
    const widths = this.columns.map(c => c.length);
    const displayRows = this.rows.slice(0, maxRows);
    for (const row of displayRows) {
      for (let i = 0; i < row.length; i++) {
        widths[i] = Math.max(widths[i], String(row[i]).length);
      }
    }
    const header = this.columns.map((c, i) => c.padEnd(widths[i])).join(' | ');
    console.log(header);
    console.log('-'.repeat(header.length));
    for (const row of displayRows) {
      console.log(row.map((c, i) => String(c).padEnd(widths[i])).join(' | '));
    }
    if (this.rows.length > maxRows) {
      console.log(`... (${this.rows.length - maxRows} more rows)`);
    }
    console.log(`\nTotal: ${this.rows.length} rows`);
  }

  save(path) {
    const lines = [this.columns.join('\t')];
    for (const row of this.rows) {
      lines.push(row.join('\t'));
    }
    FS.writeFileSync(path, lines.join('\n'), 'utf8');
    console.log(`Saved: ${path} (${this.rows.length} rows)`);
  }

  toJSON() {
    const result = [];
    for (const row of this.rows) {
      const obj = {};
      for (let i = 0; i < this.columns.length; i++) {
        obj[this.columns[i]] = row[i];
      }
      result.push(obj);
    }
    return result;
  }
}

// ===== 加载 =====

function load(path) {
  const content = FS.readFileSync(path, 'utf8');
  const lines = content.split('\n').filter(l => l.trim());
  if (lines.length === 0) throw new Error('Empty file');
  const columns = lines[0].split('\t');
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    rows.push(lines[i].split('\t'));
  }
  const name = path.replace(/\.tsv$/, '').replace(/.*[\\/]/, '');
  return new Table(name, columns, rows);
}

// ===== 导出 =====

module.exports = { Table, load };
