"""Guarded ERR 2.3.4.1 common-event prevention patch."""
import ctypes
import hashlib
import pathlib
import struct
import sys
import zlib

ORIGINAL_SHA256 = 'f9551eef9b6709729651e2554502a89304be8a0a720fac3b0db64e571cb66d08'
RAW_SIZE = 1904936
INSTRUCTION = 980896
BEFORE = bytes.fromhex('d3 07 00 00 42 00 00 00 0c 00 00 00 00 00 00 00')
AFTER = bytes.fromhex('e8 03 00 00 04 00 00 00 04 00 00 00 00 00 00 00')


def _oodle(source):
    candidates = [source.parents[2]/'internals/launcher/liboo2corelinux64.so.9',
                  source.parents[2]/'mod/menu/deploy/liboo2corelinux64.so.9',
                  source.parents[2]/'mod/menu/deploy/oo2core_6_win64.dll']
    candidates = [p for p in candidates if p.is_file()]
    if not candidates:
        raise ValueError('KRAK common event needs the Reforged Oodle library beside the mod folder')
    library = ctypes.WinDLL(str(candidates[-1])) if sys.platform == 'win32' else ctypes.CDLL(str(candidates[0]))
    fn = library.OodleLZ_Decompress
    integer = ctypes.c_ssize_t
    fn.argtypes = [ctypes.c_void_p, integer, ctypes.c_void_p, integer,
                   ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
                   integer, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                   integer, ctypes.c_int]
    fn.restype = integer
    return fn


def _decode(data, source):
    if data[:4] == b'EVD\0':
        return data
    if data[:4] != b'DCX\0' or len(data) < 76:
        raise ValueError('Expected common.emevd.dcx or decompressed EVD')
    size, compressed = struct.unpack_from('>II', data, 28)
    if size != RAW_SIZE or compressed > len(data)-76:
        raise ValueError('Unrecognized common event DCX lengths')
    payload = data[76:76+compressed]
    if data[40:44] == b'DFLT':
        raw = zlib.decompress(payload)
    elif data[40:44] == b'KRAK':
        fn = _oodle(source)
        output = ctypes.create_string_buffer(size)
        encoded = ctypes.create_string_buffer(payload)
        written = fn(encoded, len(payload), output, size, 1, 0, 0,
                     None, 0, None, None, None, 0, 3)
        if written != size:
            raise ValueError('Oodle decompression failed')
        raw = output.raw
    else:
        raise ValueError('Unsupported common event DCX compression')
    if len(raw) != size or raw[:4] != b'EVD\0':
        raise ValueError('Invalid decompressed common event')
    return raw


def plan_event(data, source):
    raw = _decode(data, source)
    digest = hashlib.sha256(raw).hexdigest()
    if digest == ORIGINAL_SHA256:
        if raw[INSTRUCTION:INSTRUCTION+16] != BEFORE:
            raise ValueError('Unexpected event 1049632091 instruction')
        patched = raw[:INSTRUCTION]+AFTER+raw[INSTRUCTION+16:]
        changes = [dict(offset=INSTRUCTION, before=BEFORE.hex(), after=AFTER.hex(),
                        reason='End common event 1049632091 at entry')]
    else:
        candidate = raw[:INSTRUCTION]+BEFORE+raw[INSTRUCTION+16:]
        if raw[INSTRUCTION:INSTRUCTION+16] == AFTER and hashlib.sha256(candidate).hexdigest() == ORIGINAL_SHA256:
            return data, [], {'method':'exact-ERR-2.3.4.1-common', 'already_patched':True,
                              'scope':'common event 1049632091 only'}
        raise ValueError('Unrecognized common event; exact ERR 2.3.4.1 buffer required')
    # The game's DCX reader accepts DFLT as well as KRAK. Repacking with DFLT
    # keeps the patcher independent of Oodle compression and changes no EVD
    # bytes outside the guarded 16-byte instruction header.
    header = bytearray(bytes.fromhex(
        '44 43 58 00 00 01 10 00 00 00 00 18 00 00 00 24 '
        '00 00 00 44 00 00 00 4c 44 43 53 00 00 00 00 00 '
        '00 00 00 00 44 43 50 00 44 46 4c 54 00 00 00 20 '
        '09 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
        '00 01 01 00 44 43 41 00 00 00 00 08'))
    # Use the existing, known-good DFLT header from the bundled talk patcher
    # layout; fields at 28 and 32 are the uncompressed/compressed byte counts.
    payload = zlib.compress(patched, 9)
    struct.pack_into('>II', header, 28, len(patched), len(payload))
    result = bytes(header)+payload
    if _decode(result, source) != patched:
        raise ValueError('Event archive round-trip failed')
    return result, changes, {'method':'exact-ERR-2.3.4.1-common', 'already_patched':False,
                             'scope':'common event 1049632091 only'}
