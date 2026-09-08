"""Recognize and disable the previously edited HKS stat-total cap branch.

Only parses text and integer arithmetic; never executes the HKS/Lua input.
"""
import ast
import hashlib
import re

ARITH = r'[-+0-9()\s]+'
GUARD = re.compile(
    r'\bif\s+(?P<total>[A-Za-z_]\w*)\s*>=\s*(?P<threshold>'+ARITH+r'?)\s*and\s+'
    r'env\s*\(\s*GetEventFlag\s*,\s*(?P<flag>'+ARITH+r'?)\)\s*==\s*FALSE\s+then\s+'
    r'act\s*\(\s*AddSpEffect\s*,\s*(?P<effect>'+ARITH+r'?)\)\s*end\b')
STATS = {'VIGOR', 'MIND', 'ENDURANCE', 'STRENGTH', 'DEXTERITY', 'INTELLIGENCE', 'FAITH', 'ARCANE'}
LEX = re.compile(r'--\[(=*)\[|--[^\r\n]*|\[(=*)\[|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)


def mask_lua(text):
    """Blank strings/comments while preserving offsets; retain long-comment spans."""
    pieces, comments, pos = [], [], 0
    while True:
        m = LEX.search(text, pos)
        if not m:
            pieces.append(text[pos:])
            break
        pieces.append(text[pos:m.start()])
        end = m.end()
        if m.group(1) is not None or m.group(2) is not None:
            equals = m.group(1) if m.group(1) is not None else m.group(2)
            closing = ']'+equals+']'
            close = text.find(closing, end)
            if close < 0:
                raise ValueError('HKS: unterminated long string/comment')
            end = close+len(closing)
            if m.group(1) is not None:
                comments.append((m.start(), m.end(), close, end))
        pieces.append(' '* (end-m.start()))
        pos = end
    return ''.join(pieces), comments


def integer(text):
    tree = ast.parse(text.strip(), mode='eval')
    def calc(node):
        if isinstance(node, ast.Expression): return calc(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int: return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            n = calc(node.operand)
            return -n if isinstance(node.op, ast.USub) else n
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
            a, b = calc(node.left), calc(node.right)
            return a+b if isinstance(node.op, ast.Add) else a-b
        raise ValueError('HKS: unsupported arithmetic')
    return calc(tree)


def sum_names(text):
    def walk(node):
        if isinstance(node, ast.Expression): return walk(node.body)
        if isinstance(node, ast.Name): return [node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return walk(node.left)+walk(node.right)
        raise ValueError('HKS: stat total is not a simple sum')
    return walk(ast.parse(text.strip(), mode='eval'))


def plan_cap(data, profiles):
    text = data.decode('latin-1')  # Round-trip every original byte unchanged.
    masked, comments = mask_lua(text)
    candidates = [(m, m.start(), m.end(), False) for m in GUARD.finditer(masked)]
    for begin, body, end, finish in comments:
        m = GUARD.fullmatch(text[body:end].strip())
        if m:
            candidates.append((m, begin, finish, True))
    valid = []
    for m, start, end, commented in candidates:
        if tuple(integer(m.group(k)) for k in ('threshold', 'flag', 'effect')) != (356, 9969, 9658):
            continue
        functions = list(re.finditer(r'\bfunction\s+([A-Za-z_][\w.:]*)\s*\(', masked[:start]))
        if not functions:
            continue
        function = functions[-1]
        prefix = masked[function.start():start]
        assign = re.search(r'\b'+re.escape(m.group('total'))+r'\s*=\s*([A-Za-z_0-9()+\s]+)$', prefix)
        if not assign:
            continue
        names = sum_names(assign.group(1))
        attrs = []
        for name in names:
            if name.startswith('STAT_') and name[5:] in STATS:
                attrs.append(name[5:])
            else:
                bindings = list(re.finditer(r'\b'+re.escape(name)+r'\s*=\s*GetPlayerStatPoints\s*\(\s*([A-Z]+)\s*\)', prefix[:assign.start()]))
                if bindings:
                    attrs.append(bindings[-1].group(1))
        if len(names) != 8 or len(attrs) != 8 or set(attrs) != STATS:
            continue
        guard = m.group(0) if commented else text[start:end]
        normalized = re.sub(r'\s+', '', assign.group(1)+'|'+guard)
        signature = hashlib.sha256(normalized.encode('latin-1')).hexdigest()
        known = any(p.get('hks_cap', {}).get('signature') == signature for p in profiles)
        valid.append(dict(start=start, end=end, commented=commented, signature=signature,
                          method='known-hks-cap' if known else 'experimental-hks-pattern',
                          function=function.group(1), effect=9658, stat_total_threshold=356, guard=guard))
    if len(valid) != 1:
        raise ValueError('HKS: expected one unambiguous eight-stat cap branch applying effect 9658; found '+str(len(valid)))
    finding = valid[0]
    if finding['commented']:
        return data, [], {k:v for k,v in finding.items() if k != 'guard'}
    start, end = finding['start'], finding['end']
    guard = text[start:end]
    equals = ''
    while ']'+equals+']' in guard:
        equals += '='
    replacement = '--['+equals+'['+guard+']'+equals+']'
    result = (text[:start]+replacement+text[end:]).encode('latin-1')
    change = dict(offset=start, before=data[start:end].hex(), after=replacement.encode('latin-1').hex(),
                  reason='Disable stat-total cap branch applying effect 9658')
    # Only the validated branch is commented out; all surrounding bytes stay identical.
    check, edits, _ = plan_cap(result, profiles)
    if edits or check != result:
        raise ValueError('HKS: post-patch verification failed')
    return result, [change], {k:v for k,v in finding.items() if k != 'guard'}


def function_span(masked, name):
    matches = list(re.finditer(r'\bfunction\s+'+re.escape(name)+r'\s*\(\s*\)', masked))
    if len(matches) != 1:
        raise ValueError('HKS: missing or ambiguous '+name+' function')
    start = matches[0].start()
    depth = 0
    for token in re.finditer(r'\b(function|if|do|repeat|end|until)\b', masked[start:]):
        if token.group() in ('function', 'if', 'do', 'repeat'):
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return start, start+token.end()
    raise ValueError('HKS: unbalanced '+name+' function')


def plan_weapon(data, profiles):
    text = data.decode('latin-1')
    masked, _ = mask_lua(text)
    start, end = function_span(masked, 'ERR_WeaponLevel')
    body = masked[start:end]
    # This is the same single terminal AddSpEffect call edited previously.
    calls = list(re.finditer(r'\bact\s*\(\s*AddSpEffect\s*,', body))
    if len(calls) != 1:
        raise ValueError('HKS: weapon-level function must have one effect application')
    call = calls[0]
    argument_start = call.end()
    depth, pos = 1, argument_start
    while pos < len(body) and depth:
        if body[pos] == '(': depth += 1
        elif body[pos] == ')': depth -= 1
        pos += 1
    if depth or not re.fullmatch(r'\s*end\s*', body[pos:]):
        raise ValueError('HKS: weapon-level effect is not the final function action')
    arg = body[argument_start:pos-1].strip()
    already = False
    try:
        already = integer(arg) == 109800
    except (SyntaxError, ValueError):
        pass
    variable = None
    if not already:
        match = re.fullmatch(r'([A-Za-z_]\w*)\s*\+\s*('+ARITH+r')', arg)
        if not match or integer(match.group(2)) != 109800:
            raise ValueError('HKS: unrecognized weapon-level effect expression')
        variable = match.group(1)
        if not re.search(r'\blocal\s+'+re.escape(variable)+r'\s*=', body):
            raise ValueError('HKS: missing weapon-level accumulator')
    # Require the weapon-level state tests and assignments, not just effect 109800.
    if not re.search(r'\benv\s*\(\s*GetStateChangeType\s*,', body):
        raise ValueError('HKS: missing weapon-level state checks')
    assignments = re.findall(r'\b([A-Za-z_]\w*)\s*=\s*('+ARITH+r')', body)
    values = {}
    for name, value in assignments:
        try:
            values.setdefault(name, set()).add(integer(value))
        except (ValueError, SyntaxError):
            continue
    accumulators = [name for name, numbers in values.items() if set(range(26)) <= numbers]
    if len(accumulators) != 1 or (variable is not None and variable != accumulators[0]):
        raise ValueError('HKS: expected one weapon-level accumulator covering levels 0 through 25')
    a, b = start+argument_start, start+pos-1
    # Normalize just the edited argument so original and patched forms share a key.
    normalized = re.sub(r'\s+', '', body[:argument_start]+'WEAPON_LEVEL_EFFECT'+body[pos-1:])
    signature = hashlib.sha256(normalized.encode('latin-1')).hexdigest()
    known = any(p.get('hks_weapon', {}).get('signature') == signature for p in profiles)
    finding = dict(signature=signature, method='known-hks-weapon' if known else 'experimental-hks-pattern',
                   function='ERR_WeaponLevel', effect=109800, already_patched=already,
                   purpose='Disable enemy level scaling from weapon level')
    if already:
        return data, [], finding
    result = data[:a]+b'109800'+data[b:]
    change = dict(offset=a, before=data[a:b].hex(), after=b'109800'.hex(),
                  reason='Disable weapon-level enemy scaling: apply neutral effect 109800')
    check, edits, _ = plan_weapon(result, profiles)
    if edits or check != result:
        raise ValueError('HKS: weapon-level patch verification failed')
    return result, [change], finding


def plan_hks(data, profiles, disable_enemy_scaling=False):
    result, changes, cap = plan_cap(data, profiles)
    finding = dict(cap)
    finding['cap_already_patched'] = not changes
    finding['disable_enemy_scaling'] = disable_enemy_scaling
    if disable_enemy_scaling:
        result, weapon_changes, weapon = plan_weapon(result, profiles)
        # Edits are recorded in application order; offsets refer to each step's input.
        changes += weapon_changes
        finding['weapon_scaling'] = weapon
        if weapon['method'] == 'experimental-hks-pattern':
            finding['method'] = 'experimental-hks-pattern'
    return result, changes, finding
