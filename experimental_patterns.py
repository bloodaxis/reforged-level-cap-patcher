"""Opt-in structural recognition of the Reforged cap/cost/menu relationship.

No release fingerprints or fixed script, machine, state, or event-flag IDs.
Engine opcodes, stat IDs, Binding Rune item 807000, and effects 49/9658 are
intentional semantic anchors. Unknown/ambiguous relationships are refused.
"""
import functools
import struct
import zlib


def require(ok, message):
    if not ok:
        raise ValueError('Experimental recognition: ' + message)


def F(fid, *args):
    return ('f', fid, *args)


@functools.lru_cache(maxsize=65536)
def expression(data):
    """Decode only understood ESD expression semantics; never skip unknown ops."""
    stack = []
    ops = {0x8c: '+', 0x8e: '-', 0x8f: '*', 0x90: '/', 0x91: '<=',
           0x92: '>=', 0x93: '<', 0x94: '>', 0x95: '==', 0x96: '!=',
           0x98: 'and', 0x99: 'or'}
    i = 0
    try:
        while i < len(data):
            op = data[i]
            i += 1
            if op < 0x80:
                stack.append(op-64)
            elif op == 0x82:
                stack.append(struct.unpack_from('<i', data, i)[0])
                i += 4
            elif 0x84 <= op <= 0x8a:
                n = op-0x84
                args = stack[-n:] if n else []
                if n:
                    del stack[-n:]
                fid = stack.pop()
                if not isinstance(fid, int):
                    raise ValueError()
                stack.append(F(fid, *args))
            elif op in ops:
                right, left = stack.pop(), stack.pop()
                stack.append((ops[op], left, right))
            elif op == 0xb8:
                stack.append(('arg', stack.pop()))
            elif op in (0xb9, 0xba):
                stack.append(('call-result' if op == 0xb9 else 'call-ongoing',))
            elif op == 0xa1 and i == len(data) and len(stack) == 1:
                return stack[0]
            else:
                raise ValueError()
    except (IndexError, ValueError, struct.error):
        pass
    return ('opaque', data.hex())


def unwrap(e):
    return e[1] if isinstance(e, tuple) and len(e) == 3 and e[0] == '==' and e[2] == 1 else e


def nodes(e):
    yield e
    if isinstance(e, tuple):
        for child in e[1:]:
            yield from nodes(child)


def work(e):
    return isinstance(e, tuple) and len(e) == 3 and e[:2] == ('f', 100) and isinstance(e[2], int)


class Command:
    def __init__(self, esd, offset):
        self.offset = offset
        self.bank, self.cid, ao, an = esd.unpack('<iiqq', offset)
        self.rawargs = [esd.slice(*esd.q(ao+i*16, 2)) for i in esd.count(an, 16)]
        self.args = tuple(expression(x) for x in self.rawargs)
        self.key = (self.bank, self.cid, self.args)


class Condition:
    def __init__(self, esd, offset, seen):
        require(offset not in seen and len(seen) < 100, 'cyclic/deep condition tree')
        self.offset = offset
        self.target, po, pn, so, sn, eo, en = esd.q(offset, 7)
        self.rawexpr = esd.slice(eo, en)
        self.expr = expression(self.rawexpr)
        self.commands = esd.commands(po, pn)
        self.children = [Condition(esd, c, seen | {offset}) for c in esd.q(so, sn)]

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()


class State:
    def __init__(self, esd, offset):
        self.offset = offset
        self.fields = list(esd.q(offset, 9))
        self.sid, co, cn, en, enc, ex, exc, wh, whc = self.fields
        self.entry = esd.commands(en, enc)
        self.exit = esd.commands(ex, exc)
        self.while_ = esd.commands(wh, whc)
        self.conditions = [Condition(esd, c, set()) for c in esd.q(co, cn)]

    def conditions_flat(self):
        return [c for root in self.conditions for c in root.walk()]

    def all_commands(self):
        return self.entry + self.exit + self.while_ + [cmd for c in self.conditions_flat() for cmd in c.commands]


class Machine:
    def __init__(self, esd, gid, so, sn):
        self.esd, self.gid = esd, gid
        self.states = [State(esd, so+i*72) for i in esd.count(sn, 72)]
        require(bool(self.states), 'empty machine')
        self.by_offset = {s.offset: s for s in self.states}
        require(len({s.sid for s in self.states}) == len(self.states), 'duplicate state IDs')
        self.initial = min(self.states, key=lambda s: s.sid)
        self.duplicate = so+sn*72 if sn > 1 else None
        for s in self.states:
            for c in s.conditions_flat():
                require(c.target == -1 or c.target in self.by_offset, 'condition target outside its machine')

    def commands(self):
        return [c for s in self.states for c in s.all_commands()]


class ESD:
    def __init__(self, raw, start, size, name):
        self.raw, self.start, self.size, self.name = raw, start, size, name
        self.base = start+108
        require(raw[start:start+4] == b'fsSL', 'unsupported ESD format')
        go, gn = self.q(24, 2)
        self.machines = []
        for i in self.count(gn, 32):
            gid, so, sn, so2 = self.q(go+i*32, 4)
            require(so == so2, 'unsupported ESD state-table layout')
            self.machines.append(Machine(self, gid, so, sn))
        require(len({m.gid for m in self.machines}) == len(self.machines), 'duplicate machine IDs')

    def count(self, n, width):
        require(0 <= n <= self.size//width, 'invalid record count')
        return range(n)

    def slice(self, off, size):
        require(size >= 0 and (size == 0 or off >= 0) and
                (size == 0 or self.base+off+size <= self.start+self.size), 'out-of-range ESD record')
        return self.raw[self.base+off:self.base+off+size] if size else b''

    def unpack(self, fmt, off):
        return struct.unpack(fmt, self.slice(off, struct.calcsize(fmt)))

    def q(self, off, n):
        self.count(n, 8)
        return self.unpack('<'+'q'*n, off) if n else ()

    def commands(self, off, n):
        return [Command(self, off+i*24) for i in self.count(n, 24)]


class Archive:
    def __init__(self, data):
        require(len(data) >= 76 and data[:4] == b'DCX\0' and data[40:44] == b'DFLT', 'unsupported DCX format')
        self.data = data
        self.raw = zlib.decompress(data[76:])
        r = self.raw
        require(len(r) >= 64 and r[:4] == b'BND4' and r[48:52] == bytes.fromhex('01740400') and
                struct.unpack_from('<Q', r, 32)[0] == 36, 'unsupported BND4 layout')
        require(struct.unpack_from('>I', data, 28)[0] == len(r) and
                struct.unpack_from('>I', data, 32)[0] == len(data)-76, 'invalid DCX sizes')
        n = struct.unpack_from('<i', r, 12)[0]
        require(0 < n <= (len(r)-64)//36, 'invalid entry count')
        self.esds = []
        ranges = []
        for i in range(n):
            h = 64+i*36
            size = struct.unpack_from('<q', r, h+8)[0]
            start, _, np = struct.unpack_from('<III', r, h+24)
            require(size >= 108 and start >= 64+n*36 and start+size <= len(r), 'invalid entry bounds')
            require(not any(start < b and a < start+size for a, b in ranges), 'overlapping entries')
            ranges.append((start, start+size))
            end = np
            while end+2 <= len(r) and r[end:end+2] != b'\0\0':
                end += 2
            require(end+2 <= len(r), 'invalid archive name')
            name = r[np:end].decode('utf-16le').replace('\\', '/').split('/')[-1]
            self.esds.append(ESD(r, start, size, name))
        require(len({e.name for e in self.esds}) == len(self.esds), 'ambiguous duplicate script names')


def plain_return(state):
    if len(state.conditions) != 1:
        return False
    c = state.conditions[0]
    return c.target == -1 and c.expr == 1 and not c.children and [x.key for x in c.commands] == [(7, -1, (0,))]


def flag_set(state, value):
    flags = [c.args[0] for c in state.entry if c.bank == 1 and c.cid == 11 and
             len(c.args) == 2 and isinstance(c.args[0], int) and c.args[1] == value]
    return flags[0] if len(flags) == 1 else None


def cap_gate(m):
    """Find upper-level rejection plus counter+cap eligibility in the same gate."""
    found = []
    for s in m.states:
        if len(s.conditions) != 3:
            continue
        upper, relative, fallback = s.conditions
        a, b = unwrap(upper.expr), unwrap(relative.expr)
        if not (isinstance(a, tuple) and len(a) == 3 and a[0] == '>' and work(a[1]) and isinstance(a[2], int)):
            continue
        if not (isinstance(b, tuple) and len(b) == 3 and b[0] == '>' and b[2] == a[1] and
                isinstance(b[1], tuple) and len(b[1]) == 3 and b[1][0] == '+' and
                work(b[1][1]) and isinstance(b[1][2], int)):
            continue
        base = b[1][2]+1
        if not (1 < base <= a[2] < 714):
            continue
        require(all(not c.commands and not c.children and c.target in m.by_offset for c in s.conditions), 'cap gate has extra actions')
        require(fallback.expr == 1, 'unrecognized cap fallback')
        off, on, other = [m.by_offset[c.target] for c in s.conditions]
        flag = flag_set(on, 1)
        require(flag is not None and flag_set(off, 0) == flag and flag_set(other, 0) == flag,
                'cap branches do not share an eligibility flag')
        require(plain_return(off) and plain_return(other), 'cap rejection does not return')
        found.append(dict(machine=m, level=a[1][2], counter=b[1][1][2], base=base, flag=flag, on=on))
    require(len(found) <= 1, 'multiple cap gates in one machine')
    return found[0] if found else None


def cost_tail(m):
    found = []
    for s in m.states:
        cs = s.entry
        if len(cs) != 4 or [c.cid for c in cs] != [100, 47, 147, 11] or any(c.bank != 1 for c in cs):
            continue
        hold = F(100, ('arg', 1))
        if (cs[0].args == (('arg', 1), ('-', F(104, 8), F(100, ('arg', 0)))) and
                cs[1].args == (8, 1, hold) and len(cs[2].args) == 3 and
                isinstance(cs[2].args[0], int) and cs[2].args[1:] == (32, hold) and
                len(cs[3].args) == 2 and isinstance(cs[3].args[0], int) and cs[3].args[1] == 1 and plain_return(s)):
            found.append((cs[2].args[0], cs[3].args[0]))
    require(len(found) <= 1, 'ambiguous rune-withholding tail')
    return found[0] if found else None


def initialization(gate, storage, indicator, role):
    m = gate['machine']
    s = m.initial
    patched = [(1, 11, (gate['flag'], 1)), (1, 11, (indicator, 0))] if role == 'eligibility' else []
    if plain_return(s) and [c.key for c in s.entry] == patched and not s.exit and not s.while_:
        return 'patched'
    cs = s.entry
    required = [(1, 147, (storage, 32, 0)), (1, 100, (gate['counter'], 0)),
                (1, 100, (gate['level'], F(104, 33))),
                (1, 100, (('arg', 0), 0)), (1, 11, (indicator, 0))]
    keys = [c.key for c in cs]
    for key in required:
        require(key in keys, 'unrecognized cap initialization')
        keys.remove(key)
    require(len(keys) == 2 and sum(k[:2] == (1, 100) and isinstance(k[2][0], int) and k[2][1] == F(104, 8) for k in keys) == 1 and
            sum(k[:2] == (1, 100) and isinstance(k[2][0], int) and k[2][1] == 0 for k in keys) == 1,
            'initialization has unexpected side effects')
    require(len(s.conditions) == 1 and s.conditions[0].expr == 1 and not s.conditions[0].commands and
            not s.conditions[0].children and s.conditions[0].target in m.by_offset, 'unrecognized initial transition')
    return 'original'


def find_menu(esd, cost, storage):
    found = []
    for m in esd.machines:
        screens = [s for s in m.states if [c.key for c in s.entry] == [(1, 31, ())]]
        if not screens:
            continue
        restore_keys = [(1, 47, (8, 0, F(101, storage, 32))), (1, 147, (storage, 32, 0))]
        restores = [s for s in m.states if [c.key for c in s.entry] == restore_keys and plain_return(s)]
        if not restores:
            continue
        require(len(screens) == len(restores) == 1, 'ambiguous menu/restore states')
        screen, restore = screens[0], restores[0]
        expected_wait = ('==', ('and', ('==', F(59, 10, 0), 1), ('==', F(58, 0), 0)), 0)
        require(len(screen.conditions) == 1 and screen.conditions[0].expr == expected_wait and
                screen.conditions[0].target == restore.offset and not screen.conditions[0].commands and
                not screen.conditions[0].children, 'unrecognized level-menu close/restore flow')
        directs = [s for s in m.states if len(s.conditions) == 1 and s.conditions[0].expr == 1 and
                   s.conditions[0].target == screen.offset and not s.conditions[0].commands and
                   not s.conditions[0].children and not s.entry and not s.exit and not s.while_]
        require(bool(directs), 'no existing unconditional OpenSoul transition')
        initial = m.initial
        if initial in directs:
            status = 'patched'
        else:
            require(len(initial.entry) == 1 and initial.entry[0].bank == 6 and initial.entry[0].cid == cost.gid and
                    initial.entry[0].args == (1, 2), 'menu does not call the discovered cost routine')
            status = 'original'
        for s in m.states:
            require(not s.exit and not s.while_, 'menu contains exit/while side effects')
            for c in s.all_commands():
                allowed = c.key in restore_keys + [(1, 31, ()), (7, -1, (0,)), (6, cost.gid, (1, 2))]
                allowed |= c.bank == 1 and c.cid == 11 and len(c.args) == 2 and isinstance(c.args[0], int) and c.args[1] in (0, 1)
                allowed |= c.bank == 1 and c.cid == 100 and len(c.args) == 2 and isinstance(c.args[0], int) and c.args[1] == 0
                require(allowed, 'menu contains unrecognized side effects')
        found.append(dict(machine=m, direct=directs[-1], status=status))
    require(len(found) == 1, 'missing or ambiguous menu linked to the rune-storage flag')
    return found[0]


def analyze(archive):
    families = []
    for esd in archive.esds:
        gates = [g for m in esd.machines for g in [cap_gate(m)] if g]
        if not gates:
            continue
        # A pair must agree on its dynamically discovered flags, registers and cap.
        costs = [(g, cost_tail(g['machine'])) for g in gates]
        costs = [(g, tail) for g, tail in costs if tail]
        used = set()
        for cost, (storage, indicator) in costs:
            peers = [g for g in gates if g is not cost and
                     all(g[k] == cost[k] for k in ('flag', 'base', 'level', 'counter')) and
                     any(isinstance(n, tuple) and len(n) >= 4 and n[:4] == ('f', 47, 3, 807000)
                         for s in g['machine'].states for c in s.conditions_flat() for n in nodes(c.expr))]
            require(len(peers) == 1, 'missing or ambiguous Binding Rune eligibility routine')
            eligibility = peers[0]
            require(eligibility['machine'].gid not in used and cost['machine'].gid not in used, 'overlapping cap families')
            for g in (eligibility, cost):
                used.add(g['machine'].gid)
                for s in g['machine'].states:
                    require(not s.exit and not s.while_, 'cap routine has exit/while actions')
                    for c in s.all_commands():
                        allowed = c.key == (7, -1, (0,)) or (c.bank == 1 and c.cid == 100)
                        allowed |= c.bank == 1 and c.cid == 11 and len(c.args) == 2 and c.args[0] in (g['flag'], indicator) and c.args[1] in (0, 1)
                        allowed |= c.bank == 1 and c.cid == 147 and len(c.args) == 3 and c.args[:2] == (storage, 32)
                        allowed |= g is cost and c.bank == 1 and c.cid == 47 and c.args == (8, 1, F(100, ('arg', 1)))
                        require(allowed, 'cap routine has unrecognized side effects')
                        require(not any(isinstance(n, tuple) and n and n[0] == 'opaque' for a in c.args for n in nodes(a)), 'unsupported cap command expression')
                    require(not any(isinstance(n, tuple) and n and n[0] == 'opaque' for c in s.conditions_flat() for n in nodes(c.expr)), 'unsupported cap condition expression')
            require(any(unwrap(c.expr) == F(45, 8, 4, F(100, ('arg', 0))) and
                        c.target in eligibility['machine'].by_offset and
                        flag_set(eligibility['machine'].by_offset[c.target], 1) == indicator
                        for s in eligibility['machine'].states for c in s.conditions_flat()), 'missing affordability flag relationship')
            menu = find_menu(esd, cost['machine'], storage)
            statuses = [initialization(g, storage, indicator, role) for g, role in [(eligibility, 'eligibility'), (cost, 'cost')]] + [menu['status']]
            require(len(set(statuses)) == 1, 'partially patched cap/menu family')
            families.append(dict(esd=esd, eligibility=eligibility, cost=cost, menu=menu,
                                 storage=storage, indicator=indicator, status=statuses[0]))
        require(used == {g['machine'].gid for g in gates}, 'an unmatched cap-like routine remains')
    require(bool(families), 'no complete cap/cost/menu patterns found')
    require(len({f['status'] for f in families}) == 1, 'mixture of patched and original families')
    claimed_menus = {(f['esd'].name, f['menu']['machine'].gid) for f in families}
    for esd in archive.esds:
        for m in esd.machines:
            commands = m.commands()
            has_screen = any(c.key == (1, 31, ()) for c in commands)
            has_saved_runes = any(c.bank == 1 and c.cid == 47 and len(c.args) == 3 and
                                  c.args[:2] == (8, 0) and isinstance(c.args[2], tuple) and
                                  c.args[2][:2] == ('f', 101) for c in commands)
            require(not (has_screen and has_saved_runes) or (esd.name, m.gid) in claimed_menus,
                    'an unmatched rune-restoring level menu remains')
    bases = {f['cost']['base'] for f in families}
    effects = []
    for esd in archive.esds:
        for m in esd.machines:
            for s in m.states:
                remove = [c for c in s.entry if c.bank == 1 and c.cid == 62 and c.args in [(49,), (9658,)]]
                if not remove:
                    continue
                incoming = [c for other in m.states for c in other.conditions_flat() if c.target == s.offset]
                level_guards = [c for c in incoming if isinstance(unwrap(c.expr), tuple) and
                                unwrap(c.expr)[:4] == ('f', 45, 33, 4)]
                guards = [c for c in incoming if any(unwrap(c.expr) == F(45, 33, 4, base+1) for base in bases)]
                require(not level_guards or len(level_guards) == len(guards),
                        'effect threshold differs from the discovered level cap')
                # Same effect IDs can have unrelated uses; those are left alone.
                if not guards:
                    continue
                require(len(guards) == len(incoming) and all(not c.commands and not c.children for c in guards),
                        'effect state has an alternative, non-level entry path')
                require(s is not m.initial and not s.exit and not s.while_ and all(c.bank == 1 and c.cid == 62 for c in s.entry),
                        'level-triggered effect state has additional behavior')
                effects.append((m, s, remove))
    status = families[0]['status']
    require(status != 'patched' or not effects, 'cap bypass exists but level-triggered effects remain')
    return families, effects, status


def state_semantics(s):
    def cs(commands):
        return [(c.bank, c.cid, c.rawargs) for c in commands]
    def cond(c):
        return (c.target, c.rawexpr, cs(c.commands), [cond(x) for x in c.children])
    return (cs(s.entry), cs(s.exit), cs(s.while_), [cond(c) for c in s.conditions])


def patch_experimental(original):
    archive = Archive(original)
    families, effects, status = analyze(archive)
    findings = [dict(script=f['esd'].name, eligibility_machine=f['eligibility']['machine'].gid,
                     cost_machine=f['cost']['machine'].gid, menu_machine=f['menu']['machine'].gid,
                     eligibility_flag=f['cost']['flag'], affordability_flag=f['indicator'],
                     rune_storage_flag=f['storage'], cap_base=f['cost']['base']) for f in families]
    if status == 'patched':
        return original, [], findings
    patched = bytearray(archive.raw)
    changes, modified = [], set()

    def edit(off, data, reason):
        before = bytes(patched[off:off+len(data)])
        if before != data:
            changes.append(dict(offset=off, before=before.hex(), after=data.hex(), reason=reason))
            patched[off:off+len(data)] = data

    def change_state(m, s, fields, reason):
        esd = m.esd
        data = struct.pack('<9q', *fields)
        edit(esd.base+s.offset, data, f'{esd.name}: machine {m.gid}, state {s.sid}: {reason}')
        modified.add((esd.name, m.gid, s.sid))
        if s is m.initial and m.duplicate is not None:
            require(esd.slice(m.duplicate, 72) == esd.slice(s.offset, 72), 'initial-state duplicate mismatch')
            edit(esd.base+m.duplicate, data, f'{esd.name}: duplicate initial state: {reason}')

    for f in families:
        esd = f['esd']
        for role in ('eligibility', 'cost'):
            m = f[role]['machine']
            s = m.initial
            returns = [x for x in m.states if plain_return(x)]
            require(bool(returns), 'no reusable return-zero transition')
            fields = s.fields.copy()
            fields[1:3] = returns[-1].fields[1:3]
            if role == 'eligibility':
                wanted = [(1, 11, (f[role]['flag'], 1)), (1, 11, (f['indicator'], 0))]
                commands = []
                for key in wanted:
                    matches = [c for c in m.commands() if c.key == key]
                    require(bool(matches), 'missing eligibility flag command')
                    commands.append(esd.slice(matches[-1].offset, 24))
                require(fields[4] >= 2, 'insufficient command space')
                edit(esd.base+fields[3], b''.join(commands), f'{esd.name}: enable eligibility; disable custom affordability')
                fields[4] = 2
            else:
                fields[3:5] = [-1, 0]
            change_state(m, s, fields, 'bypass recognized cap/cost routine')
        m = f['menu']['machine']
        fields = m.initial.fields.copy()
        fields[1:3] = f['menu']['direct'].fields[1:3]
        fields[3:5] = [-1, 0]
        change_state(m, m.initial, fields, 'route directly to existing OpenSoul flow')
    for m, s, remove in effects:
        fields = s.fields.copy()
        keep = [m.esd.slice(c.offset, 24) for c in s.entry if c not in remove]
        if keep:
            edit(m.esd.base+fields[3], b''.join(keep), f'{m.esd.name}: preserve other level-triggered effects')
            fields[4] = len(keep)
        else:
            fields[3:5] = [-1, 0]
        change_state(m, s, fields, 'remove level-guarded effects 49/9658')
    payload = zlib.compress(patched, 9)
    header = bytearray(original[:76])
    struct.pack_into('>I', header, 32, len(payload))
    result = bytes(header)+payload
    after = Archive(result)
    new_families, _, new_status = analyze(after)
    require(new_status == 'patched' and len(new_families) == len(families), 'post-patch pattern verification failed')
    # Catch shared command-table aliases and any unexpected effects on other states.
    for before_esd, after_esd in zip(archive.esds, after.esds):
        for bm, am in zip(before_esd.machines, after_esd.machines):
            for bs, ass in zip(bm.states, am.states):
                if (before_esd.name, bm.gid, bs.sid) not in modified:
                    require(state_semantics(bs) == state_semantics(ass), 'an unrelated state changed')
    return result, changes, findings
