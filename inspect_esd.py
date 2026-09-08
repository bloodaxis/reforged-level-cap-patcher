import struct, zlib, re, pathlib, json, sys, xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent
if len(sys.argv)!=3:
    raise SystemExit('Usage: python3 inspect_esd.py INPUT.talkesdbnd.dcx OUTPUT_DIRECTORY')
src=pathlib.Path(sys.argv[1])
archive = zlib.decompress(src.read_bytes()[0x4c:])
doc = ET.parse(ROOT/'esdtool-v0.5.1/dist/ESDScriptingDocumentation_TalkER.xml')
funcs = {int(e.attrib['ID']): e.attrib['Name'] for e in doc.findall('.//Function')}
cmds = {(int(e.attrib['Bank']), int(e.attrib['ID'])): e.attrib['Name'] for e in doc.findall('.//Command')}
modern=json.loads((ROOT/'esdtool-v0.5.1/dist/ESDScriptingDocumentation_Talk.json').read_text(encoding='utf-8'))
for e in modern['functions']:
    if 'name' in e and ('games' not in e or 'er' in e['games']): funcs[e['id']]=e['name']
for e in modern['commands']:
    if 'name' in e and ('games' not in e or 'er' in e['games']): cmds[e['bank'],e['id']]=e['name']
ops = {0x8c:'+',0x8e:'-',0x8f:'*',0x90:'/',0x91:'<=',0x92:'>=',0x93:'<',0x94:'>',0x95:'==',0x96:'!=',0x98:'and',0x99:'or'}
if len(sys.argv)>2:
    ROOT=pathlib.Path(sys.argv[2]); ROOT.mkdir(parents=True,exist_ok=True)
def expr(b):
    stack=[]; i=0
    try:
        while i<len(b):
            op=b[i]; i+=1
            if op<0x80: stack.append(str(op-64))
            elif op in (0x80,0x81,0x82):
                fmt={0x80:'f',0x81:'d',0x82:'i'}[op]
                stack.append(str(struct.unpack_from('<'+fmt,b,i)[0])); i+=struct.calcsize(fmt)
            elif 0x84<=op<=0x8a:
                n=op-0x84; args=stack[-n:] if n else []
                if n: del stack[-n:]
                fid=int(stack.pop()); stack.append(f'{funcs.get(fid,"f"+str(fid))}({", ".join(args)})')
            elif op in ops:
                right=stack.pop(); left=stack.pop(); stack.append(f'({left} {ops[op]} {right})')
            elif op in (0x8d,0x9a): stack.append(f'{"-" if op==0x8d else "not "}({stack.pop()})')
            elif op==0xb8: stack.append(f'Arg({stack.pop()})')
            elif op==0xb9: stack.append('CallResult()')
            elif op==0xba: stack.append('CallOngoing()')
            elif 0xa7<=op<=0xae: stack.append(f'SetREG{op-0xa7}({stack.pop()})')
            elif 0xaf<=op<=0xb6: stack.append(f'GetREG{op-0xaf}()')
            elif op in (0xa1,0xa6,0xb7): pass
            elif op==0xa5:
                j=i
                while b[j:j+2]!=b'\0\0': j+=2
                stack.append(repr(b[i:j].decode('utf-16le'))); i=j+2
            else: stack.append(f'OP_{op:02x}')
        if len(stack)!=1: raise ValueError('residual stack')
        return stack[0]
    except Exception:
        return f'UNDECODED[{b.hex(" ")}] stack={stack}'

starts=[m.start() for m in re.finditer(b'fsSL',archive)]
print('BND header',archive[:64].hex(' '),'ESD offsets',starts)
for index,start in enumerate(starts):
    header=0x40+index*0x24
    dataoff,entryid,nameoff=struct.unpack_from('<III',archive,header+24)
    assert dataoff==start
    end=nameoff
    while archive[end:end+2]!=b'\0\0': end+=2
    name=archive[nameoff:end].decode('utf-16le').replace('\\','/').split('/')[-1]
    b=archive[start:]; base=0x6c
    def vals(off,n): return struct.unpack_from('<'+'q'*n,b,base+off)
    groupoff,ngroups=vals(24,2)
    out=[]
    def commands(off,n,indent):
        for j in range(n):
            bank,cid,ao,an=struct.unpack_from('<iiqq',b,base+off+j*24)
            args=[]
            for k in range(an):
                p,l=vals(ao+k*16,2); args.append(expr(b[base+p:base+p+l]))
            name=cmds.get((bank,cid),f'c{bank}_{cid}')
            out.append(f'{indent}{name}({", ".join(args)})')
    def condition(off,indent,seen):
        if off in seen: return
        target,co,cn,so,sn,eo,en=vals(off,7)
        tid=vals(target,1)[0] if target!=-1 else None
        out.append(f'{indent}IF {expr(b[base+eo:base+eo+en])} -> state {tid} [expr offset {base+eo:#x}]')
        commands(co,cn,indent+'  PASS ')
        for sub in vals(so,sn): condition(sub,indent+'  ',seen|{off})
    for g in range(ngroups):
        gid,st,n,duplicate=vals(groupoff+g*32,4)
        out.append(f'\nMACHINE {gid}')
        for j in range(n):
            sid,co,cn,en,enc,ex,exc,wh,whc=vals(st+j*72,9)
            out.append(f'  STATE {sid}')
            commands(en,enc,'    ENTRY ');commands(ex,exc,'    EXIT ');commands(wh,whc,'    WHILE ')
            for c in vals(co,cn): condition(c,'    ',set())
    dest=ROOT/f'archive-esd-{index}.txt'; dest.write_text('\n'.join(out), encoding='utf-8')
    (ROOT/(name+'.txt')).write_text('\n'.join(out), encoding='utf-8')
    print(dest,name,ngroups,'machines',len(out),'lines')
