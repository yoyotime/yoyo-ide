// test-textdb.js — 测试文本数据库引擎
// 用法: node test-textdb.js

const { load } = require('./textdb.js');

console.log('=== 1. 加载原子数据 ===');
const atoms = load('data/2026.06.14/atoms.tsv');
atoms.print(5);

console.log('\n=== 2. 过滤: 郭靖洋钢筋班 ===');
const guojingyang = atoms.where('team', '=', '郭靖洋钢筋班');
guojingyang.print(5);

console.log('\n=== 3. 排序: 钢筋工种 Top 5 ===');
const rebarTop = atoms.where('worktype', '=', '钢筋').orderBy('quantity', true).limit(5);
rebarTop.print(5);

console.log('\n=== 4. 聚合: 按公司统计总产量 ===');
const byCompany = atoms.groupBy('company', 'quantity', 'sum').orderBy('quantity_sum', true);
byCompany.print(10);

console.log('\n=== 5. 聚合: 按班组统计总产量 Top 10 ===');
const byTeam = atoms.groupBy('team', 'quantity', 'sum').orderBy('quantity_sum', true).limit(10);
byTeam.print(10);

console.log('\n=== 6. 去重: 所有工种 ===');
const worktypes = atoms.distinct('worktype').select('worktype');
worktypes.print(20);

console.log('\n=== 7. 统计: 钢筋工种产量 ===');
const rebar = atoms.where('worktype', '=', '钢筋');
console.log(`  钢筋 atom 数: ${rebar.count()}`);
console.log(`  钢筋总产量: ${rebar.sum('quantity')} 吨`);
console.log(`  钢筋平均产量: ${rebar.avg('quantity')} 吨/atom`);
console.log(`  钢筋最大产量: ${rebar.max('quantity')} 吨`);
console.log(`  钢筋最小产量: ${rebar.min('quantity')} 吨`);

console.log('\n=== 8. 转换: 添加效率列 ===');
const withEff = atoms.map((row, i) => {
  const qty = parseFloat(row[atoms.col('quantity')]) || 0;
  const ppl = parseFloat(row[atoms.col('people')]) || 0;
  const eff = ppl > 0 ? Math.round(qty / ppl * 100) / 100 : 0;
  return [...row, String(eff)];
});
const withEffTable = new (require('./textdb.js').Table)(
  atoms.name, [...atoms.columns, 'efficiency'], withEff.rows
);
withEffTable.where('worktype', '=', '钢筋').orderBy('efficiency', true).limit(5).print(5);

console.log('\n=== 9. 保存结果 ===');
const topTeams = atoms.groupBy('team', 'quantity', 'sum').orderBy('quantity_sum', true).limit(20);
topTeams.save('textdb/top_teams.tsv');

console.log('\n=== 10. 链式查询: 广达公司钢筋班组 ===');
const result = atoms
  .where('company', '=', '仪征广达')
  .where('worktype', '=', '钢筋')
  .groupBy('team', 'quantity', 'sum')
  .orderBy('quantity_sum', true);
result.print(10);
