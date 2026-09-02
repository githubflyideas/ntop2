const assert=require('assert');
// FIELDS 用运行中的服务真实返回的那份,而不是手写一份 —— 手写的迟早
// 与后端不同步,而 coerce 判类型完全依赖它。
global.FIELDS=require('./fields.json');
const {protoLabel,coerce,isIntField,pivot,localInput,
  ipOk,cidrOk,checkValue,filterTree,sortChoices,cellText,cellClass}=require('./ui.js');
let n=0; const t=(name,fn)=>{fn();n++;console.log('  ok',name)};

t('protoLabel 把数字换成名字',()=>{
  assert.strictEqual(protoLabel(6),'TCP');
  assert.strictEqual(protoLabel('17'),'UDP');
  assert.match(protoLabel(253),/253/);           // 未知协议要显示原值,不能变 undefined
});

t('coerce:整数字段必须是数字',()=>{
  assert.strictEqual(coerce('dst_port','22'),22);
  assert.strictEqual(coerce('src_asn','13335'),13335);
  assert.strictEqual(coerce('src_country','CN'),'CN');   // 字符串字段保持原样
  assert.ok(isIntField('dst_port') && !isIntField('src_ip'));
});

// pivot 是这次改动里最容易出错的一段:ECharts 堆叠按下标相加,
// 不按 x 值对齐。缺点的序列必须补 0,否则堆叠高度全错。
t('pivot 把缺失的时间点补 0',()=>{
  const rows=[[100,'a',10],[200,'a',20],[200,'b',5],[300,'b',7]];
  const s=pivot(rows,['a','b']);
  assert.strictEqual(s.length,2);
  const ts=s.map(x=>x.data.map(p=>p[0]));
  assert.deepStrictEqual(ts[0],ts[1],'两条序列的时间轴必须完全一致');
  assert.deepStrictEqual(ts[0],[100000,200000,300000],'时间要升序且换成毫秒');
  assert.deepStrictEqual(s[0].data.map(p=>p[1]),[10,20,0]);
  assert.deepStrictEqual(s[1].data.map(p=>p[1]),[0,5,7]);
});

t('pivot 时间乱序也要排好',()=>{
  const s=pivot([[300,'a',3],[100,'a',1],[200,'a',2]],['a']);
  assert.deepStrictEqual(s[0].data.map(p=>p[1]),[1,2,3]);
});

t('pivot 忽略不在 keys 里的行',()=>{
  const s=pivot([[100,'a',1],[100,'zzz',999]],['a']);
  assert.deepStrictEqual(s[0].data,[[100000,1]]);
});

t('pivot 空值显示成(未知)',()=>{
  assert.strictEqual(pivot([[100,'',1]],[''])[0].name,'(未知)');
  assert.strictEqual(pivot([[100,'6',1]],['6'],protoLabel)[0].name,'TCP');
});

// 直接切 ISO 字符串会把 UTC+8 的时间往前挪 8 小时,
// 表现为"选了自定义范围,图上的时间对不上"。
t('localInput 用本地时区',()=>{
  const d=new Date(2026,7,13,9,5,0);
  assert.strictEqual(localInput(d.toISOString()),'2026-08-13T09:05');
});

t('ipOk 认得合法与不合法的地址',()=>{
  assert.ok(ipOk('192.168.1.1') && ipOk('::1') && ipOk('2001:db8::1'));
  assert.ok(!ipOk('192.168.1.256'), '每段不能超过 255');
  assert.ok(!ipOk('192.168.1'), '少一段不算 IPv4');
  assert.ok(!ipOk('10.0.0.1x'));
  assert.ok(!ipOk('2001::db8::1'), '只能有一个 ::');
});

// 忘了写掩码位数是最常见的填法错误:192.168.1.0 当成网段传过去,
// ClickHouse 那边报的是一句看不懂的解析异常。
t('cidrOk 要求带掩码位数且位数在范围内',()=>{
  assert.ok(cidrOk('192.168.1.0/24') && cidrOk('fd00::/8'));
  assert.ok(!cidrOk('192.168.1.0'), '没有掩码位数');
  assert.ok(!cidrOk('192.168.1.0/33'), 'IPv4 最多 32 位');
  assert.ok(!cidrOk('fd00::/129'), 'IPv6 最多 128 位');
  assert.ok(cidrOk('fd00::/64'));
});

t('checkValue:整数字段只收整数',()=>{
  assert.strictEqual(checkValue('dst_port','eq','443').value, 443);
  assert.ok(checkValue('dst_port','eq','四四三').err, '不是整数要报错');
  assert.deepStrictEqual(checkValue('dst_port','in','22, 443').value, [22,443]);
});

t('checkValue:IP 字段按运算符换校验方式',()=>{
  assert.ok(checkValue('src_ip','cidr','192.168.1.0').err, 'cidr 必须带掩码');
  assert.strictEqual(checkValue('src_ip','cidr','192.168.1.0/24').value, '192.168.1.0/24');
  assert.ok(checkValue('src_ip','eq','192.168.1.0/24').err, 'eq 要的是单个地址');
  assert.strictEqual(checkValue('src_ip','eq','10.0.0.1').value, '10.0.0.1');
  assert.ok(checkValue('src_country','eq','CN').value === 'CN', '字符串字段不做 IP 校验');
  assert.ok(checkValue('src_ip','eq','   ').err, '空值要报错');
});

// filterTree 拼错了照样能查出结果,只是排掉的东西不对 —— 没有任何报错
// 会提醒,所以这里把形状钉死。
t('filterTree 把排除块编译成 NOT(OR(...))',()=>{
  const a={field:'dst_port',operator:'eq',value:22};
  const b={field:'src_ip',operator:'cidr',value:'10.0.0.0/8'};
  const c={field:'dst_port',operator:'eq',value:5353};

  assert.strictEqual(filterTree([],[],'AND'), undefined, '两块都空时不带 filters');
  assert.deepStrictEqual(filterTree([a],[],'AND'), a, '单条不该多包一层');

  const or=filterTree([a,b],[],'OR');
  assert.strictEqual(or.op,'OR');
  assert.strictEqual(or.conditions.length,2);

  const only=filterTree([],[b,c],'AND');
  assert.strictEqual(only.op,'NOT');
  assert.strictEqual(only.conditions[0].op,'OR','任一条命中就排掉');

  const both=filterTree([a],[b],'AND');
  assert.strictEqual(both.op,'AND');
  assert.deepStrictEqual(both.conditions[0],a,'必须满足的那块在前');
  assert.strictEqual(both.conditions[1].op,'NOT');
  assert.deepStrictEqual(both.conditions[1].conditions[0],b,'单条排除不该多包一层 OR');
});

// 排序字段必须是选出来的列之一,否则后端拒掉整个查询 —— 而拒绝发生在
// 点了查询之后。
t('sortChoices 只给选出来的列',()=>{
  assert.deepStrictEqual(sortChoices('',['src_ip'],['bytes'],''), ['bytes','src_ip']);
  assert.deepStrictEqual(sortChoices('',['src_ip'],['bytes'],'hour')[0], 'ts',
    '按时间分桶后才能按 ts 排');
  assert.ok(sortChoices('',[],[],'').length===0, '什么都没选时没有排序选项');
  assert.deepStrictEqual(sortChoices('',['bytes'],['bytes'],''), ['bytes'], '不该出现重复项');
  const d=sortChoices('detail',['src_ip'],['bytes'],'hour');
  assert.ok(d.includes('ts') && d.includes('duration_ms') && !d.includes('src_ip'),
    '明细模式用固定的那份列表');
});

// 明细行里 ts 是 Unix 秒、protocol 是协议号。原样印出来是一串十位数字
// 和一个 6 —— 表格能显示,但没人在读。
t('cellText 明细列该换成人看的形式',()=>{
  assert.match(cellText('ts', new Date(2026,7,13,9,5,0).getTime()/1000), /08-13 09:05/);
  assert.strictEqual(cellText('protocol',6),'TCP');
  assert.strictEqual(cellText('bytes',2048),'2.00 KB');
  assert.strictEqual(cellText('packets',1500),'1.5K');
  assert.strictEqual(cellText('src_org',''),'—','空值不留白格');
  assert.strictEqual(cellText('src_org','<b>'),'&lt;b&gt;','字符串列必须转义');
  assert.strictEqual(cellClass('bytes'),'num');
  assert.strictEqual(cellClass('src_ip'),'mono');
});

console.log(n+' 项通过');
