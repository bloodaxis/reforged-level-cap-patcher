#!/usr/bin/env python3
"""Apply the user-tested ERR uncap and menu fix to recognized script structures.

Uses inspect_esd.py and its bundled documentation, plus uncap-signatures.json.
Known structures use verified signatures. Unrecognized structures can optionally
use experimental pattern recognition, with confirmation before writing.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
import zlib

ROOT = pathlib.Path(__file__).resolve().parent
TARGETS = {
    't000001000.esd': [1, 2147483536, 2147483537, 2147483613],
    't000001010.esd': [2147483536, 2147483537, 2147483613],
    't000004000.esd': [2147483536, 2147483537, 2147483613],
    't000001300.esd': [2147483646],
}



def bytecode_signatures(raw):
    """Fingerprint exact reachable bytecode, omitting physical file offsets."""
    result = {}
    for index in range(struct.unpack_from('<i', raw, 12)[0]):
        h = 64 + index*36
        start, _, np = struct.unpack_from('<III', raw, h+24)
        end = np
        while raw[end:end+2] != b'\0\0':
            if end+2 > len(raw): raise ValueError('Invalid entry name')
            end += 2
        name = raw[np:end].decode('utf-16le').replace('\\', '/').split('/')[-1]
        if name not in TARGETS: continue
        base = start+108
        def q(off, n):
            return struct.unpack_from('<'+'q'*n, raw, base+off)
        def expression(off, length):
            return raw[base+off:base+off+length].hex()
        def commands(off, count):
            out = []
            for k in range(count):
                bank, cid, ao, an = struct.unpack_from('<iiqq', raw, base+off+k*24)
                out.append([bank, cid, [expression(*q(ao+j*16, 2)) for j in range(an)]])
            return out
        def condition(off, seen):
            if off in seen: raise ValueError('Cyclic condition tree')
            target, co, cn, so, sn, eo, en = q(off, 7)
            return [q(target, 1)[0] if target != -1 else None,
                    commands(co, cn), expression(eo, en),
                    [condition(c, seen | {off}) for c in q(so, sn)]]
        go, gn = q(24, 2)
        for j in range(gn):
            gid, so, sn, _ = q(go+j*32, 4)
            if gid not in TARGETS[name]: continue
            states = []
            for k in range(sn):
                sid, co, cn, ent, entn, ex, exn, wh, whn = q(so+k*72, 9)
                states.append([sid, commands(ent, entn), commands(ex, exn), commands(wh, whn),
                               [condition(c, set()) for c in q(co, cn)]])
            result[f'{name}:{gid}'] = hashlib.sha256(json.dumps(sorted(states)).encode()).hexdigest()
    return result


def signatures(source):
    data = source.read_bytes()
    if data[:4] != b'DCX\0' or data[40:44] != b'DFLT':
        raise ValueError('Unsupported DCX format; expected DFLT.')
    raw = zlib.decompress(data[76:])
    if (raw[:4] != b'BND4' or raw[48:52] != bytes.fromhex('01740400')
            or struct.unpack_from('<Q', raw, 32)[0] != 36
            or struct.unpack_from('>I', data, 28)[0] != len(raw)
            or struct.unpack_from('>I', data, 32)[0] != len(data)-76):
        raise ValueError('Unsupported archive layout or invalid DCX lengths.')
    with tempfile.TemporaryDirectory(prefix='err-uncap-inspect-') as directory:
        run = subprocess.run([sys.executable, str(ROOT/'inspect_esd.py'), str(source), directory],
                             capture_output=True, text=True)
        if run.returncode:
            raise ValueError('Archive inspection failed: ' + run.stderr[-1500:])
        result = {}
        for name, groups in TARGETS.items():
            text = pathlib.Path(directory, name+'.txt').read_text(encoding='utf-8')
            machines = {}
            for block in text.split('\nMACHINE ')[1:]:
                gid = int(block.splitlines()[0])
                # Byte offsets may change when unrelated scripts grow.
                normalized = re.sub(r' \[expr offset 0x[0-9a-f]+\]', '', block).strip()
                machines[gid] = hashlib.sha256(normalized.encode()).hexdigest()
            for gid in groups:
                result[f'{name}:{gid}'] = machines[gid]
        # Detect new applications of the effects outside the recognized machines.
        effects = []
        for path in sorted(pathlib.Path(directory).glob('t*.esd.txt')):
            gid = sid = None
            for line in path.read_text(encoding='utf-8').splitlines():
                if line.startswith('MACHINE '): gid = int(line.split()[1])
                if line.startswith('  STATE '): sid = int(line.split()[1])
                if re.search(r'GiveSpEffectToPlayer\((49|9658)\)', line):
                    effects.append([path.name, gid, sid, line.strip()])
        result['effects'] = effects
        result['bytecode'] = bytecode_signatures(raw)
        return result


def patch(original):
    raw=zlib.decompress(original[0x4c:])
    patched=bytearray(raw)
    changes=[]
    effect_id=62
    expected_effect_states={('t000001000.esd',1,44),('t000001300.esd',2147483646,10)}
    def constant(b):
        assert b[-1]==0xa1
        if len(b)==2 and b[0]<0x80: return b[0]-64
        assert len(b)==6 and b[0]==0x82,b.hex()
        return struct.unpack_from('<i',b,1)[0]
    def edit(off,data,why):
        before=bytes(patched[off:off+len(data)])
        if before==data:return
        changes.append(dict(offset=off,before=before.hex(),after=data.hex(),reason=why))
        patched[off:off+len(data)]=data

    entries=[]
    for index in range(struct.unpack_from('<i',raw,12)[0]):
        h=0x40+index*36
        size=struct.unpack_from('<q',raw,h+8)[0]
        start,eid,nameoff=struct.unpack_from('<III',raw,h+24)
        end=nameoff
        while raw[end:end+2]!=b'\0\0':end+=2
        name=raw[nameoff:end].decode('utf-16le').replace('\\','/').split('/')[-1]
        assert raw[start:start+4]==b'fsSL'
        base=start+0x6c
        def q(off,n):return struct.unpack_from('<'+'q'*n,raw,base+off)
        go,gn=q(24,2)
        groups={}
        for j in range(gn):
            gid,so,sn,so2=q(go+j*32,4)
            assert so==so2
            states={q(so+k*72,1)[0]:so+k*72 for k in range(sn)}
            groups[gid]=(states,so+sn*72 if sn>1 else None)
        def commands(state):
            fields=q(state,9); off,n=fields[3:5]
            result=[]
            for k in range(n):
                cp=off+k*24
                bank,cid,ao,an=struct.unpack_from('<iiqq',raw,base+cp)
                args=[]
                for a in range(an):
                    p,l=q(ao+a*16,2);args.append(raw[base+p:base+p+l])
                result.append((cp,bank,cid,args))
            return result
        def modify_state(gid,sid,newfields,why):
            states,dummy=groups[gid]
            data=struct.pack('<9q',*newfields)
            edit(base+states[sid],data,f'{name}: machine {gid}, state {sid}: {why}')
            if sid==min(states) and dummy is not None:
                assert raw[base+dummy:base+dummy+72]==raw[base+states[sid]:base+states[sid]+72]
                edit(base+dummy,data,f'{name}: duplicate initial state: {why}')
        if name in ('t000001000.esd','t000001010.esd','t000004000.esd'):
            flag=1042307500 if name=='t000001000.esd' else 1043267500
            for gid in (2147483536,2147483537):
                states,dummy=groups[gid]
                s0=q(states[0],9)
                assert s0[4]==7
                # Reuse an existing unconditional return-zero condition list from this machine.
                returns=[]
                for sid,sp in states.items():
                    sf=q(sp,9)
                    if sf[2]!=1:continue
                    co=q(sf[1],1)[0]
                    target,po,pn,sub,subn,eo,en=q(co,7)
                    if target!=-1 or subn or pn!=1:continue
                    if raw[base+eo:base+eo+en]!=b'\x41\xa1':continue
                    bank,cid,ao,an=struct.unpack_from('<iiqq',raw,base+po)
                    if (bank,cid,an)!=(7,-1,1):continue
                    p,l=q(ao,2)
                    if constant(raw[base+p:base+p+l])==0:returns.append(sf)
                assert returns
                sf=list(s0);sf[1:3]=returns[-1][1:3]
                if gid==2147483536:
                    wanted={}
                    for sp in states.values():
                        for cp,bank,cid,args in commands(sp):
                            if (bank,cid)!=(1,11):continue
                            try: pair=tuple(map(constant,args))
                            except (AssertionError,IndexError):continue
                            if pair in ((flag,1),(flag+1,0)):
                                wanted[pair]=raw[base+cp:base+cp+24]
                    assert len(wanted)==2
                    edit(base+s0[3],wanted[flag,1]+wanted[flag+1,0],f'{name}: eligibility=true; custom affordability indicator=false')
                    sf[4]=2
                else:
                    sf[3:5]=[-1,0]
                modify_state(gid,0,sf,'return immediately; bypass cap/cost-table logic')
        # Remove only requested effects, preserving other commands in each affected state.
        for gid,(states,dummy) in groups.items():
            for sid,sp in states.items():
                cs=commands(sp); remove=[]
                for cp,bank,cid,args in cs:
                    # Resolve effect command from the installed documentation below.
                    if bank==1 and cid==effect_id and len(args)==1:
                        try: effect=constant(args[0])
                        except AssertionError: continue
                        if effect in (9658,49):remove.append(cp)
                if not remove:continue
                assert (name,gid,sid) in expected_effect_states,(name,gid,sid)
                keep=[raw[base+cp:base+cp+24] for cp,_,_,_ in cs if cp not in remove]
                sf=list(q(sp,9))
                if keep:
                    edit(base+sf[3],b''.join(keep),f'{name}: remove level-triggered effect 49; preserve other effects')
                    sf[4]=len(keep)
                else:sf[3:5]=[-1,0]
                modify_state(gid,sid,sf,'remove level-triggered effects 9658/49')
        entries.append((name,start,size))


    # Apply the confirmed menu fix to the first-stage result.
    raw=bytes(patched)
    for index in range(struct.unpack_from('<i',raw,12)[0]):
        start,_,np=struct.unpack_from('<III',raw,64+index*36+24)
        end=np
        while raw[end:end+2]!=b'\0\0':end+=2
        name=raw[np:end].decode('utf-16le').replace('\\','/').split('/')[-1]
        if name not in ('t000001000.esd','t000001010.esd','t000004000.esd'):continue
        base=start+108
        def q(off,n):return struct.unpack_from('<'+'q'*n,raw,base+off)
        go,gn=q(24,2)
        for i in range(gn):
            gid,so,sn,so2=q(go+i*32,4)
            if gid!=2147483613:continue
            assert so==so2
            states={q(so+j*72,1)[0]:so+j*72 for j in range(sn)}
            f=list(q(states[0],9)); direct=q(states[3],9); screen=q(states[4],9)
            assert f[4]==1 and screen[4]==1 and direct[2]==1
            assert struct.unpack_from('<ii',raw,base+f[3])==(6,2147483537)
            assert struct.unpack_from('<ii',raw,base+screen[3])==(1,31)
            cond=q(direct[1],1)[0]
            target,po,pn,sub,subn,eo,en=q(cond,7)
            assert target==states[4] and pn==subn==0 and raw[base+eo:base+eo+en]==b'\x41\xa1'
            f[1:3]=direct[1:3]; f[3:5]=[-1,0]
            data=struct.pack('<9q',*f)
            duplicate=so+sn*72
            assert raw[base+duplicate:base+duplicate+72]==raw[base+states[0]:base+states[0]+72]
            for offset in (base+states[0],base+duplicate):
                changes.append(dict(offset=offset,before=raw[offset:offset+72].hex(),after=data.hex(),reason=f'{name}: direct OpenSoul handoff'))
                patched[offset:offset+72]=data

    payload=zlib.compress(patched,9)
    header=bytearray(original[:76])
    struct.pack_into('>I',header,32,len(payload))
    result=bytes(header)+payload
    if zlib.decompress(result[76:]) != patched:
        raise ValueError('Compression verification failed')
    return result, changes


def ask_experimental_check(args):
    if args.experimental:
        return True
    if not sys.stdin.isatty():
        raise ValueError('Unknown structure. Use --experimental --check for read-only analysis, or run interactively.')
    if not args.check:
        return True
    try:
        answer = input('Try an experimental pattern check? It does not establish in-game compatibility. [y/N]: ')
    except EOFError:
        answer = ''
    if answer.strip().lower() in ('y', 'yes'):
        return True
    print('Cancelled. No changes made.')
    return False


def stage_file(path, data, mode=None):
    fd, temporary = tempfile.mkstemp(prefix=path.name+'.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
        return pathlib.Path(temporary)
    except BaseException:
        pathlib.Path(temporary).unlink(missing_ok=True)
        raise


def write_bundle(items, report_path, report, in_place):
    """Preflight/stage everything; back up originals before replacing either file."""
    changed = [i for i in items if i['result'] != i['original']] if in_place else items
    staged, committed = [], []
    report_created = False
    try:
        for item in changed:
            source, destination = item['source'], item['destination']
            mode = (source.stat().st_mode & 0o777) if in_place else None
            staged.append((item, stage_file(destination, item['result'], mode)))
        for item in items:
            if item['source'].read_bytes() != item['original']:
                raise ValueError('An input changed during processing. No files replaced.')
        if in_place:
            stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
            for item in changed:
                backup = item['source'].with_name(item['source'].name+'.before-uncap-'+stamp+'.bak')
                with backup.open('xb') as stream:
                    stream.write(item['original'])
                item['report']['backup'] = str(backup)
        for item, temporary in staged:
            if in_place:
                os.replace(temporary, item['destination'])
                committed.append(item)
            else:
                with item['destination'].open('xb') as stream:
                    committed.append(item)
                    stream.write(item['result'])
        with report_path.open('x', encoding='utf-8') as stream:
            report_created = True
            json.dump(report, stream, indent=2)
    except BaseException:
        failures = []
        for item in reversed(committed):
            try:
                if in_place:
                    restore = stage_file(item['source'], item['original'], item['source'].stat().st_mode & 0o777)
                    os.replace(restore, item['source'])
                else:
                    item['destination'].unlink()
            except OSError as error:
                failures.append(str(error))
        if report_created:
            report_path.unlink(missing_ok=True)
        if failures:
            raise ValueError('Write failed and rollback was incomplete. Restore the .before-uncap backups. '+ '; '.join(failures))
        raise
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)


def finish_bundle(items, args, experimental):
    destination = items[0]['destination']
    if args.check:
        print(('Experimental candidate passed structural checks; in-game behavior is unverified.' if experimental else 'Compatible.')+' No changes made.')
        return
    if all(i['result'] == i['original'] for i in items):
        print('Already patched. No changes made.')
        return
    paths = [i['destination'].resolve() for i in items]
    if len(set(paths)) != len(paths):
        raise ValueError('Output paths must be different')
    for i in items:
        if i['source'].read_bytes() != i['original']:
            raise ValueError('An input changed during processing. No changes made.')
        if not args.in_place and i['destination'].exists():
            raise ValueError('Output already exists: '+str(i['destination']))
        if not i['destination'].parent.is_dir():
            raise ValueError('Output directory does not exist: '+str(i['destination'].parent))
    report_path = destination.with_name(destination.name+'.patch.json')
    if report_path.exists():
        stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
        report_path = destination.with_name(destination.name+'.patch-'+stamp+'.json')
    report = dict(method='experimental-patterns' if experimental else 'known-signatures', files=[])
    for i in items:
        i['report'] = dict(source=str(i['source']), output=str(i['destination']), method=i['method'],
                           original_sha256=hashlib.sha256(i['original']).hexdigest(),
                           patched_sha256=hashlib.sha256(i['result']).hexdigest(), changes=i['changes'],
                           findings=i['findings'])
        report['files'].append(i['report'])
    if experimental:
        for i in items:
            print(f"Proposed output: {i['destination']} ({len(i['changes'])} edits)")
        print('Original-file backups will be created.' if args.in_place else 'Original inputs will be preserved.')
        try:
            answer = input('Apply experimental patching? It may or may not work in-game. [y/N]: ')
        except EOFError:
            answer = ''
        if answer.strip().lower() not in ('y', 'yes'):
            print('Cancelled. No changes made.')
            return
    write_bundle(items, report_path, report, args.in_place)
    for i in items:
        print(f"Patched file: {i['destination']}")
        if 'backup' in i['report']:
            print('Backup: '+i['report']['backup'])
    print(f'Change report: {report_path}')


def weapon_scaling_only(args):
    from hks_patch import plan_weapon
    source = (args.hks or args.source).resolve(strict=True)
    if source.is_dir():
        choices = [source/'action/script/c0000.hks', source/'mod/action/script/c0000.hks']
        found = [p for p in choices if p.is_file()]
        if len(found) != 1:
            raise ValueError('Select the Reforged/mod folder containing action/script/c0000.hks, or c0000.hks itself')
        source = found[0].resolve(strict=True)
    elif source.name != 'c0000.hks' and source.parent.name.lower() == 'talk' and source.parent.parent.name.lower() == 'script':
        source = (source.parents[2]/'action/script/c0000.hks').resolve(strict=True)
    original = source.read_bytes()
    profiles = json.loads((ROOT/'uncap-signatures.json').read_text(encoding='utf-8'))
    result, changes, finding = plan_weapon(original, profiles)
    experimental = finding['method'] == 'experimental-hks-pattern'
    if experimental and not ask_experimental_check(args):
        return
    print('Weapon-level enemy scaling: '+('already disabled.' if not changes else 'will be disabled.'))
    destination = source if args.in_place else (args.hks_output or args.output or source.with_name('c0000.no-weapon-scaling.hks')).resolve()
    items = [dict(source=source, original=original, result=result, destination=destination,
                  method=finding['method'], changes=changes, findings=finding)]
    finish_bundle(items, args, experimental)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=pathlib.Path, help='Reforged folder, mod folder, or talk archive')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--output', type=pathlib.Path, help='Separate ESD output; c0000.hks is copied beside it unless --hks-output is given')
    mode.add_argument('--in-place', action='store_true', help='Patch both inputs with backups')
    mode.add_argument('--check', action='store_true', help='Check both files without writing')
    parser.add_argument('--hks', type=pathlib.Path, help='Explicit c0000.hks location when it cannot be inferred')
    parser.add_argument('--hks-output', type=pathlib.Path, help='Separate HKS output location')
    parser.add_argument('--weapon-scaling-only', action='store_true', help='Only disable weapon-level enemy scaling; do not patch the level cap or read the talk archive')
    parser.add_argument('--disable-enemy-scaling', action='store_true', help='Optional: disable enemy level scaling from weapon level via ERR_WeaponLevel')
    parser.add_argument('--esd-only', action='store_true', help='Explicitly perform the legacy talk-archive-only operation')
    parser.add_argument('--experimental', action='store_true', help='Allow unknown-pattern analysis; experimental writes still ask')
    args = parser.parse_args()
    if args.esd_only and (args.hks or args.hks_output or args.disable_enemy_scaling or args.weapon_scaling_only):
        parser.error('--esd-only cannot be combined with HKS options')
    if args.hks_output and args.in_place:
        parser.error('--hks-output cannot be combined with --in-place')
    if args.weapon_scaling_only:
        weapon_scaling_only(args)
        return
    source = args.source.resolve(strict=True)
    if source.is_dir():
        relative = pathlib.Path('script/talk/m00_00_00_00.talkesdbnd.dcx')
        choices = [source/relative, source/'mod'/relative]
        found = [p for p in choices if p.is_file()]
        if len(found) != 1:
            raise ValueError('Select a Reforged folder or mod folder containing script/talk/m00_00_00_00.talkesdbnd.dcx')
        source = found[0].resolve(strict=True)
    hks_source = None
    if not args.esd_only:
        if args.hks:
            hks_source = args.hks.resolve(strict=True)
        elif source.parent.name.lower() == 'talk' and source.parent.parent.name.lower() == 'script':
            hks_source = (source.parents[2]/'action/script/c0000.hks').resolve(strict=True)
        else:
            raise ValueError('Cannot locate c0000.hks. Select the Reforged/mod folder, supply --hks PATH, or explicitly use --esd-only.')
        if hks_source == source:
            raise ValueError('The talk archive and HKS input must be different files')
    original = source.read_bytes()
    hks_original = hks_source.read_bytes() if hks_source else None
    profiles = json.loads((ROOT/'uncap-signatures.json').read_text(encoding='utf-8'))
    try:
        sig = signatures(source)
    except (ValueError, KeyError, FileNotFoundError):
        sig = None
    already = sig in [p['patched'] for p in profiles]
    matches = [p for p in profiles if p['original'] == sig]
    esd_experimental = not already and not matches
    findings, changes = [], []
    if already:
        result = original
        print('ESD: already patched with the recognized cap removal and menu fix.')
    elif esd_experimental:
        print('ESD: no known analyzed patch matches this archive.')
        if not ask_experimental_check(args):
            return
        from experimental_patterns import patch_experimental
        result, changes, findings = patch_experimental(original)
        print(f'ESD EXPERIMENTAL: recognized {len(findings)} linked cap/cost/menu families.')
    else:
        print('Recognized cap/menu structure: ' + ', '.join(p['label'] for p in matches))
        result, changes = patch(original)
        with tempfile.TemporaryDirectory(prefix='err-uncap-verify-') as directory:
            candidate = pathlib.Path(directory, source.name)
            candidate.write_bytes(result)
            if signatures(candidate) != matches[0]['patched']:
                raise ValueError('Patched script verification failed. No changes made.')
    destination = source if args.in_place else (args.output or source.with_name(source.name+'.uncapped.dcx')).resolve()
    items = [dict(source=source, original=original, result=result, destination=destination,
                  method='experimental-patterns' if esd_experimental else 'known-signatures',
                  changes=changes, findings=findings)]
    hks_experimental = False
    if hks_source:
        from hks_patch import plan_hks
        hks_result, hks_changes, hks_finding = plan_hks(hks_original, profiles, args.disable_enemy_scaling)
        hks_experimental = hks_finding['method'] == 'experimental-hks-pattern'
        if hks_experimental and not esd_experimental and not ask_experimental_check(args):
            return
        if args.in_place:
            hks_destination = hks_source
        elif args.hks_output:
            hks_destination = args.hks_output.resolve()
        elif args.output:
            hks_destination = destination.parent/'c0000.hks'
        else:
            hks_destination = hks_source.with_name('c0000.uncapped.hks')
        items.append(dict(source=hks_source, original=hks_original, result=hks_result,
                          destination=hks_destination, method=hks_finding['method'],
                          changes=hks_changes, findings=hks_finding))
        print('HKS: '+('already has the cap branch disabled' if hks_finding['cap_already_patched'] else 'will disable the stat-total branch applying effect 9658')+
              (' (experimental pattern).' if hks_experimental else ' (known analyzed pattern).'))
        if args.disable_enemy_scaling:
            weapon = hks_finding['weapon_scaling']
            print('HKS enemy level scaling (weapon-level component): '+
                  ('already disabled.' if weapon['already_patched'] else 'will be disabled (effect 109800).'))
    finish_bundle(items, args, esd_experimental or hks_experimental)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, AssertionError, OSError, KeyError, SyntaxError, struct.error, zlib.error) as error:
        sys.exit(f'Refused/failed: {error or "structure assertion failed"}')
