const E=require('./encode-x64.js');
const{PE}=require('./pe-builder.js');

const RCX=1,RDX=2,RSP=4,RSI=6,RDI=7,R8=8,R9=9,R12=12,R13=13,R14=14,R15=15;
const RAX=0;
const R= {ax:0,cx:1,dx:2,sp:4,si:6,di:7,r8:8,r9:9,r12:12,r13:13,r14:14,r15:15};

E.mov_mi64=function(b,b2,d,v){E.mov_ri(b,R.ax,v);E.mov_mr64(b,b2,d,R.ax);};
E.lea_rr=function(b,d,s,disp){
  b.rex(1,d>7,0,s>7);b.u8(0x8D);
  function w(m){if((s&7)===4){b.modrm(m,d&7,4);b.sib(0,4,s&7);}else{b.modrm(m,d&7,s&7);}}
  if(disp===0&&s!==5)w(0);else if(disp>=-128&&disp<=127){w(1);b.u8(disp&255);}else{w(2);b.u32(disp);}
};

function parse(text){
  const r=[];for(const l of text.split('\n')){
    const t=l.trim();if(!t||t[0]===';'||t[0]==='#')continue;
    const line=t.replace(/;.*$/,'').trim();if(!line)continue;
    const p=line.split(/\s+/);const op=parseInt(p[0],16);if(isNaN(op))continue;
    const args=p.slice(1).map(x=>{
      if(x[0]==='s'){const b=[];for(let i=1;i<x.length;i+=2)b.push(parseInt(x.substr(i,2),16)||0);const B=Buffer.from(b);return{t:'s',v:B.toString('utf8'),raw:B};}
      if(op===0xA0){return{t:'h',v:x};}  // A0 takes raw hex string
      return{t:'n',v:parseInt(x,16)||0};
    });
    if(op===0xFF){} // FF tokens handled by analyze, don't break parse
    r.push({op,args});
  }return r;
}

function analyze(tokens){
  const S={},B=[],O=[],H={};let si=0,ch=null;
  for(const t of tokens){
    if(ch!==null){if(t.op===0x40){ch=t.args[0].v;H[ch]=[];continue;}        if(t.op===0xFF){H[ch].push(t);ch=null;continue;}H[ch].push(t);continue;}
    if(t.op===0x12){S[si]={text:t.args[1]?t.args[1].v:(t.args[0].t==='s'?t.args[0].v:'')};si++;}
    else if(t.op===0x13){B.push({off:t.args[0].v,data:t.args[1].raw||Buffer.from(t.args[1].v,'hex')});}
    else if(t.op===0x40){ch=t.args[0].v;H[ch]=[];}
    else O.push(t);
  }return{strings:S,blobs:B,top:O,handlers:H};
}

function compile(src){
  const prog=analyze(parse(src));
  const strs=Object.values(prog.strings);let sOff=16;const strPos=[];
  for(const s of strs){strPos.push(sOff);sOff+=4+s.text.length+1;}

  const TEXT_VS=0x4000;
  const pe=new PE();pe.subsys=3;
  pe.addImport('KERNEL32.dll',['ExitProcess','GetStdHandle','WriteFile','ReadFile','CreateFileA','GetFileSize','CloseHandle','VirtualAlloc']);
  pe.setCode(Buffer.alloc(TEXT_VS,0x90));pe.setData(Buffer.alloc(1,0));pe.build();
  const P=pe.ptrMap;

  pe.setCode(Buffer.alloc(TEXT_VS,0x90));pe.setData(Buffer.alloc(1,0));pe.build();
  const dr=pe.dataRVA;

  const code=new E.Buf();code.labels={};code.fixups=[];code.iatFixups=[];
  code.label=n=>{code.labels[n]=code.tell();};
  code.jmp32=n=>{E.jmp_rel(code,0);code.fixups.push({p:code.tell()-4,n});};
  code.jcc32=(cc,n)=>{E.jcc32(code,cc,0);code.fixups.push({p:code.tell()-4,n});};

  function ci(n){const r=P[n];if(r===undefined)return;const c=0x1000+code.tell();E.call_rip(code,r-(c+6));code.iatFixups.push({n,dispPos:code.tell()-4,instrEnd:c+6});}
  function ld(r,o){code.u8(0x48+(r>7?4:0));code.u8(0x8D);code.u8(0x05|((r&7)<<3));const _p=code.tell();code.u32(0);const _e=code.tell();code.b.writeInt32LE(dr+o-(0x1000+_e),_p);code.iatFixups.push({o,dispPos:_p,instrEnd:0x1000+_e,isLd:1});}
  function lr(r,b,d){E.lea_rr(code,r,b,d);}

  // State helpers
  function stSet(id,v){E.mov_ri(code,RAX,BigInt(v));E.mov_mr64(code,R15,id*8,RAX);}
  function stGet(reg,id){E.mov_rm64(code,reg,R15,id*8);}
  function stPut(id,reg){E.mov_mr64(code,R15,id*8,reg);}
  function stAdd(id,v){stGet(RAX,id);E.add_ri(code,RAX,v);stPut(id,RAX);}
  function stSub(id,v){stGet(RAX,id);E.sub_ri(code,RAX,v);stPut(id,RAX);}
  function stCmp(a,b){stGet(RAX,a);stGet(RDX,b);E.cmp_rr(code,RAX,RDX);}

  // Startup
  E.mov_ri(code,RCX,0n);E.mov_ri(code,RDX,0x20000n);
  E.mov_ri(code,R8,0x3000n);E.mov_ri(code,R9,0x40n);ci('KERNEL32.dll.VirtualAlloc');
  E.mov_rr(code,R15,RAX);
  E.mov_ri(code,RCX,-11n);ci('KERNEL32.dll.GetStdHandle');
  E.mov_rr(code,R14,RAX);

  for(const op of prog.top)emit(op);
  E.xor_rr(code,RCX,RCX);ci('KERNEL32.dll.ExitProcess');
  for(const h of Object.keys(prog.handlers)){
    code.label('H'+h);for(const op of prog.handlers[h])emit(op);E.ret(code);
  }

  // Pad code to TEXT_VS to force textVS=TEXT_VS regardless of actual size
  while(code.tell()<TEXT_VS)code.u8(0x90);

  // === EMIT ===
  function emit(op){
    const a=op.args,o=op.op;
    if(o===0x30){stSet(a[0].v,a[1]?a[1].v:0);}
    else if(o===0x31||o===0x33){
      const si=a[0].v;
      E.mov_mi64(code,RSP,0x20,0n);E.mov_rr(code,RCX,R14);
      ld(RDX,strPos[si]+4);
      E.mov_ri(code,R8,BigInt(strs[si].text.length));
      lr(R9,RSP,0x28);ci('KERNEL32.dll.WriteFile');
      if(o===0x33){E.mov_mi64(code,RSP,0x20,0n);E.mov_rr(code,RCX,R14);ld(RDX,sOff);E.mov_ri(code,R8,2n);lr(R9,RSP,0x28);ci('KERNEL32.dll.WriteFile');}
    }
    else if(o===0x32){
      E.mov_mi64(code,RSP,0x20,0n);E.mov_rr(code,RCX,R14);ld(RDX,sOff);E.mov_ri(code,R8,2n);lr(R9,RSP,0x28);ci('KERNEL32.dll.WriteFile');
    }
    else if(o===0x40){} // handler start — handled by analyze
    else if(o===0x41){E.call_rel(code,0);code.fixups.push({p:code.tell()-4,n:'H'+a[0].v});}
    else if(o===0x50){
      ld(RCX,strPos[a[1].v]+4);
      E.mov_ri(code,RDX,0x80000000n);E.mov_ri(code,R8,1n);E.xor_rr(code,R9,R9);
      E.mov_mi64(code,RSP,0x20,3n);E.mov_mi64(code,RSP,0x28,0x80n);E.mov_mi64(code,RSP,0x30,0n);
      ci('KERNEL32.dll.CreateFileA');E.mov_rr(code,R13,RAX);
      E.mov_rr(code,RCX,R13);E.xor_rr(code,RDX,RDX);ci('KERNEL32.dll.GetFileSize');
      E.mov_rr(code,R12,RAX);
      E.mov_ri(code,RCX,0n);E.mov_rr(code,RDX,R12);
      E.mov_ri(code,R8,0x3000n);E.mov_ri(code,R9,0x40n);ci('KERNEL32.dll.VirtualAlloc');
      stPut(a[0].v,RAX);stPut(a[0].v+1,R12);
      E.mov_rr(code,RCX,R13);stGet(RDX,a[0].v);E.mov_rr(code,R8,R12);
      lr(R9,RSP,0x20);E.mov_mi64(code,RSP,0x20,0n);ci('KERNEL32.dll.ReadFile');
      E.mov_rr(code,RCX,R13);ci('KERNEL32.dll.CloseHandle');
    }
    else if(o===0x51){
      ld(RCX,strPos[a[1].v]+4);
      E.mov_ri(code,RDX,0x40000000n);E.xor_rr(code,R8,R8);E.xor_rr(code,R9,R9);
      E.mov_mi64(code,RSP,0x20,2n);E.mov_mi64(code,RSP,0x28,0x80n);E.mov_mi64(code,RSP,0x30,0n);
      ci('KERNEL32.dll.CreateFileA');E.mov_rr(code,R13,RAX);
      E.mov_rr(code,RCX,R13);stGet(RDX,a[0].v);
      stGet(R8,a[2]?a[2].v:0);
      lr(R9,RSP,0x20);E.mov_mi64(code,RSP,0x20,0n);ci('KERNEL32.dll.WriteFile');
      E.mov_rr(code,RCX,R13);ci('KERNEL32.dll.CloseHandle');
    }
    else if(o===0x60){stGet(RAX,a[1].v);stPut(a[0].v,RAX);}
    else if(o===0x61){stAdd(a[0].v,a[1].v);}
    else if(o===0x62){stSub(a[0].v,a[1].v);}
    else if(o===0x63){stGet(RAX,a[0].v);stGet(RDX,a[1].v);E.imul_rr(code,RAX,RDX);stPut(a[0].v,RAX);}
    else if(o===0x66){stGet(RAX,a[0].v);E.add_ri(code,RAX,1);stPut(a[0].v,RAX);}
    else if(o===0x67){stGet(RAX,a[0].v);E.sub_ri(code,RAX,1);stPut(a[0].v,RAX);}
    else if(o===0x68){stGet(RAX,a[0].v);stGet(RDX,a[1].v);E.add_rr(code,RAX,RDX);stPut(a[0].v,RAX);}
    else if(o===0x69){stGet(RAX,a[0].v);stGet(RDX,a[1].v);E.sub_rr(code,RAX,RDX);stPut(a[0].v,RAX);}
    else if(o===0x65){stCmp(a[0].v,a[1].v);}
    else if(o===0x70){code.jmp32('H'+a[0].v);}
    else if(o===0x71){code.jcc32(0,'H'+a[0].v);}  // je
    else if(o===0x72){code.jcc32(1,'H'+a[0].v);}  // jne
    else if(o===0x73){code.jcc32(2,'H'+a[0].v);}  // jl
    else if(o===0x74){code.jcc32(3,'H'+a[0].v);}  // jge
    else if(o===0x75){code.jcc32(4,'H'+a[0].v);}  // jle
    else if(o===0x76){code.jcc32(5,'H'+a[0].v);}  // jg
    else if(o===0x77){code.jcc32(6,'H'+a[0].v);}  // jb (unsigned below)
    else if(o===0x78){code.jcc32(7,'H'+a[0].v);}  // jae (unsigned above or equal)
    else if(o===0x79){code.jcc32(8,'H'+a[0].v);}  // jbe
    else if(o===0x7A){code.jcc32(9,'H'+a[0].v);}  // ja (unsigned above)
    else if(o===0x80){stGet(RDX,a[1].v);code.u8(0x0F);code.u8(0xB6);var _d=a[2]?a[2].v:0;if(_d===0&&2!==5)code.u8(0x02);else if(_d>=-128&&_d<=127){code.u8(0x42);code.u8(_d&255);}else{code.u8(0x82);code.u32(_d);}stPut(a[0].v,RAX);}
    else if(o===0x81){E.mov_ri(code,RAX,BigInt(a[1].v));stGet(RDX,a[0].v);E.mov_mr(code,RDX,a[2]?a[2].v:0,RAX,true);}
    else if(o===0x84){stGet(RDI,a[0].v);ld(RSI,a[1].v);E.mov_ri(code,RCX,BigInt(a[2].v));code.u8(0xF3);code.u8(0xA4);}
    else if(o===0x85){stGet(RDI,a[0].v);stGet(RSI,a[1].v);stGet(RCX,a[2].v);code.u8(0xF3);code.u8(0xA4);}
    else if(o===0x55){stGet(RDX,a[0].v);stGet(RAX,a[1].v);code.u8(0x89);code.u8(0x02);}
    else if(o===0x57){stGet(RDX,a[0].v);stGet(R8,a[1].v);E.add_rr(code,RDX,R8);stGet(RAX,a[2].v);code.u8(0x88);code.u8(0x02);}
    else if(o===0x87){stGet(RDX,a[0].v);stGet(RAX,a[1].v);var off=a[2]?a[2].v:0;if(off===0)code.u8(0x88);code.u8(0x02);}
    else if(o===0xFF){E.ret(code);}
    else if(o===0x20){
      E.mov_ri(code,RCX,0n);E.mov_ri(code,RDX,BigInt(a[1].v));
      E.mov_ri(code,R8,0x3000n);E.mov_ri(code,R9,0x40n);ci('KERNEL32.dll.VirtualAlloc');stPut(a[0].v,RAX);
    }
    else if(o===0xA0){
      // A0 <hexstring> — emit raw x64 bytes directly
      // Example: A0 48b9f5ffffffffffff (emit movabsq rcx, -11)
      const hex=a[0]?a[0].v:'';
      for(let i=0;i<hex.length;i+=2){
        const b=parseInt(hex.substr(i,2),16);
        if(!isNaN(b))code.u8(b);
      }
    }
  }

  // Fixups
  for(const f of code.fixups){const t=code.labels[f.n];if(t!==undefined)code.b.writeInt32LE(t-(f.p+4),f.p);}

  // Fix IAT and data displacements based on actual code size
  const peFix=new PE();peFix.subsys=3;
  peFix.addImport('KERNEL32.dll',['ExitProcess','GetStdHandle','WriteFile','ReadFile','CreateFileA','GetFileSize','CloseHandle','VirtualAlloc']);
  peFix.setCode(Buffer.alloc(code.tell(),0x90));peFix.setData(Buffer.alloc(1,0));peFix.build();
  const fixDR=peFix.dataRVA;
  for(const f of code.iatFixups){
    if(f.isLd){code.b.writeInt32LE(fixDR+f.o-(f.instrEnd),f.dispPos);}
    else{const cr=peFix.ptrMap[f.n];if(cr!==undefined)code.b.writeInt32LE(cr-(f.instrEnd),f.dispPos);}
  }

  // Assemble
  const total=Buffer.alloc(code.tell(),0);code.b.slice(0,code.tell()).copy(total,0);
  const data=Buffer.alloc(0x10000,0);
  data.writeUInt32LE(strs.length,0);
  for(let i=0;i<strs.length;i++){const off=strPos[i];const tb=Buffer.from(strs[i].text+'\0','ascii');data.writeUInt32LE(strs[i].text.length,off);tb.copy(data,off+4);}
  Buffer.from('\r\n\0','ascii').copy(data,sOff);for(const b of prog.blobs)b.data.copy(data,b.off);

  pe.setCode(total);pe.setData(data);return pe.build();
}

module.exports={compile,parse,analyze};
if (require.main===module){(async()=>{
  const fs=require('fs');
  const ky=fs.readFileSync(process.argv[2],'utf8');
  const exe=compile(ky);
  const out=process.argv[3]||(process.argv[2].replace(/\.ky$/,'')+'.exe');
  fs.writeFileSync(out,exe);
  console.log(`Compiled to ${out} (${exe.length} bytes)`);
})();}
