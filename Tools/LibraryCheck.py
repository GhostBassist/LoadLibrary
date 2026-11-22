#!/usr/bin/env python3
# Static check of a DLL for LoadLibrary: what the exports you need actually reach
#
#   LibraryCheck.py <dll> [export ...]
#
# Without exports, all exports are checked. The script walks the call graph from the exports over direct calls
# (objdump of binutils or LLVM disassembles), and lists what is reached:
#   - imports through the IAT, each one implemented by Kernel32.c, resolved by another DLL or missing,
#   - accesses to the TEB through gs: and to the PEB, against the fields PrepareLibraryThread() fills.
# Indirect calls through registers and tables of pointers are not followed: the result is a lower bound.
# loadlibrary-check tells whether the DLL loads at all; this script tells whether the needed path is covered.

import os
import re
import struct
import subprocess
import sys
import bisect

HERE = os.path.dirname(os.path.abspath(__file__))

# Fields of the TEB filled by PrepareLibraryThread() (see LoadLibrary.c), and the slots of TlsAlloc
TEB_FIELDS = {0x08: 'StackBase', 0x10: 'StackLimit', 0x30: 'Self', 0x40: 'ClientId.UniqueProcess',
              0x48: 'ClientId.UniqueThread', 0x58: 'ThreadLocalStoragePointer', 0x60: 'ProcessEnvironmentBlock',
              0x68: 'LastErrorValue'}
TEB_TLS_SLOTS = (0x1480, 0x1480 + 64 * 8)

DYNAMIC_CRT = ('vcruntime', 'msvcp', 'msvcr', 'ucrtbase', 'api-ms-win-crt-', 'concrt')
EXCEPTIONS = ('RaiseException', 'RtlUnwind', 'RtlUnwindEx', 'RtlVirtualUnwind', 'RtlLookupFunctionEntry',
              'RtlCaptureContext', '_CxxThrowException')


def read_pe(path):
    data = open(path, 'rb').read()
    if data[:2] != b'MZ':
        raise SystemExit('%s: not a PE image' % path)
    offset = struct.unpack_from('<I', data, 0x3c)[0]
    if data[offset:offset + 4] != b'PE\0\0' or struct.unpack_from('<H', data, offset + 4)[0] != 0x8664:
        raise SystemExit('%s: not an x86-64 PE image' % path)
    count, optional_size = struct.unpack_from('<H', data, offset + 6)[0], struct.unpack_from('<H', data, offset + 20)[0]
    optional = offset + 24
    if struct.unpack_from('<H', data, optional)[0] != 0x20b:
        raise SystemExit('%s: not PE32+' % path)
    base = struct.unpack_from('<Q', data, optional + 24)[0]
    directories = [struct.unpack_from('<II', data, optional + 112 + 8 * index) for index in range(16)]
    sections = []
    for index in range(count):
        entry = optional + optional_size + 40 * index
        name, virtual_size, address, raw_size, raw = struct.unpack_from('<8sIIII', data, entry)
        sections.append((address, max(virtual_size, raw_size), raw, raw_size))

    def file_offset(rva):
        for address, size, raw, raw_size in sections:
            if address <= rva < address + size and rva - address < raw_size:
                return raw + rva - address
        return None

    def string(rva):
        position = file_offset(rva)
        if position is None:
            return None
        return data[position:data.index(b'\0', position)].decode('latin-1')

    # Exports: name -> RVA (forwarded ones are strings)
    exports = {}
    address, size = directories[0]
    if size:
        position = file_offset(address)
        ordinal_base, total, named, functions, names, ordinals = struct.unpack_from('<IIIIII', data, position + 16)
        for index in range(named):
            name = string(struct.unpack_from('<I', data, file_offset(names) + 4 * index)[0])
            number = struct.unpack_from('<H', data, file_offset(ordinals) + 2 * index)[0]
            target = struct.unpack_from('<I', data, file_offset(functions) + 4 * number)[0]
            exports[name] = string(target) if address <= target < address + size else target

    # Imports (regular and delayed): VA of the IAT slot -> (DLL, function or #ordinal)
    imports = {}

    def walk(table_rva, lookup_rva, module):
        index = 0
        while True:
            value = struct.unpack_from('<Q', data, file_offset(lookup_rva) + 8 * index)[0]
            if value == 0:
                break
            name = '#%d' % (value & 0xffff) if value >> 63 else string((value & 0x7fffffff) + 2)
            imports[base + table_rva + 8 * index] = (module, name)
            index += 1

    address, size = directories[1]
    position = file_offset(address) if size else None
    while position is not None:
        lookup, _, _, name, table = struct.unpack_from('<IIIII', data, position)
        if name == 0 and table == 0:
            break
        walk(table, lookup or table, string(name))
        position += 20

    address, size = directories[13]
    position = file_offset(address) if size else None
    while position is not None:
        attributes, name, handle, table, lookup = struct.unpack_from('<IIIII', data, position)
        if name == 0:
            break
        if attributes & 1:
            walk(table, lookup, string(name))
        position += 32

    return base, exports, imports


def implemented_functions():
    # Functions of the KERNEL32.dll provider: LIBRARY_IMPORT(Name) and { "Name", ... } entries of Kernel32.c
    candidates = [os.path.join(HERE, 'Kernel32.c'), os.path.join(HERE, '..', 'Loader', 'Kernel32.c')]
    existing = [path for path in candidates if os.path.exists(path)]
    if not existing:
        return set()
    path = existing[0]
    text = open(path).read()
    names = set(re.findall(r'LIBRARY_IMPORT\((\w+)\)', text))
    names |= set(re.findall(r'\{\s*"(\w+)",\s*\(void\*\)\w+\s*\}', text))
    return names


def disassemble(path):
    for tool in ('objdump', 'llvm-objdump', 'x86_64-w64-mingw32-objdump'):
        try:
            result = subprocess.run([tool, '-d', '--no-show-raw-insn', path], capture_output=True, text=True)
        except FileNotFoundError:
            continue
        if result.returncode == 0 and ':' in result.stdout:
            return result.stdout
    raise SystemExit('No objdump that understands PE x86-64 (binutils or LLVM) was found')


def main():
    if len(sys.argv) < 2:
        raise SystemExit('usage: LibraryCheck.py <dll> [export ...]')

    path = sys.argv[1]
    base, exports, imports = read_pe(path)
    wanted = sys.argv[2:] or sorted(name for name, target in exports.items() if isinstance(target, int))
    provided = implemented_functions()
    folder = os.path.dirname(os.path.abspath(path))
    dependencies = {}

    def exported_by(module, function):
        # A real DLL next to this one: does it export the function (by name or ordinal)?
        for name in (module, module.lower()):
            candidate = os.path.join(folder, name)
            if os.path.exists(candidate):
                if candidate not in dependencies:
                    dependencies[candidate] = read_pe(candidate)
                _, names, _ = dependencies[candidate]
                if function.startswith('#'):
                    return int(function[1:]) <= len(names)
                return function in names
        return None

    instructions = []
    starts = set()
    for line in disassemble(path).splitlines():
        match = re.match(r'\s*([0-9a-f]+):\s+(.*)', line)
        if not match:
            continue
        address, text = int(match.group(1), 16), match.group(2)
        instructions.append((address, text))
        call = re.match(r'call[q]?\s+(?:0x)?([0-9a-f]+)\b', text)
        if call:
            starts.add(int(call.group(1), 16))

    roots = {}
    for name in wanted:
        target = exports.get(name)
        if target is None:
            print('%s: no such export' % name)
        elif isinstance(target, str):
            print('%s: forwarded to %s, check that DLL' % (name, target))
        else:
            roots[name] = base + target
    # Every export starts a function (bounds of bodies), only the wanted ones are walked
    starts |= set(roots.values())
    starts |= set(base + target for target in exports.values() if isinstance(target, int))

    index = {address: position for position, (address, text) in enumerate(instructions)}
    ordered = sorted(starts)

    def body(start):
        position = index.get(start)
        if position is None:
            return []
        following = bisect.bisect_right(ordered, start)
        limit = ordered[following] if following < len(ordered) else 1 << 64
        result = []
        while position < len(instructions) and instructions[position][0] < limit:
            result.append(instructions[position])
            position += 1
        return result

    print('DLL: %s, %d exports checked, the walk follows direct calls only' % (path, len(roots)))
    verdicts = []

    for name, root in sorted(roots.items()):
        seen, todo = set(), [root]
        reached, segments = {}, {}
        while todo:
            function = todo.pop()
            if function in seen:
                continue
            seen.add(function)
            for address, text in body(function):
                call = re.match(r'call[q]?\s+(?:0x)?([0-9a-f]+)\b', text)
                if call:
                    todo.append(int(call.group(1), 16))
                slot = re.search(r'\*-?0x[0-9a-f]+\(%rip\)\s*#\s*0x([0-9a-f]+)', text)
                if slot and int(slot.group(1), 16) in imports:
                    reached.setdefault(imports[int(slot.group(1), 16)], function)
                # Absolute offsets only: TEB fields; with a base register (or in data decoded as code) it is not
                segment = re.search(r'%([gf]s):(-?0x[0-9a-f]+|\d+)(?![0-9a-fx]*\()', text)
                if segment:
                    segments.setdefault((segment.group(1), int(segment.group(2), 0)), address)

        missing, beyond = [], []
        print('\n%s: %d functions reached' % (name, len(seen)))
        for (module, function), caller in sorted(reached.items()):
            lower = module.lower()
            if lower.startswith(DYNAMIC_CRT):
                state = 'dynamic CRT: beyond the line (Wine)'
                beyond.append(function)
            elif lower in ('kernel32.dll', 'kernel32') and function in provided:
                state = 'implemented in Kernel32.c'
            elif function in EXCEPTIONS:
                state = 'exceptions: beyond the line (Wine), unless only an error path reaches it'
                missing.append(function)
            elif exported_by(module, function) is True:
                state = 'exported by %s next to the DLL' % module
            elif exported_by(module, function) is False:
                state = 'MISSING: %s next to the DLL does not export it' % module
                missing.append(function)
            else:
                state = 'MISSING: aborts when called'
                missing.append(function)
            print('  import %s!%s (in the function at 0x%x): %s' % (module, function, caller, state))
        for (register, offset), address in sorted(segments.items()):
            if register == 'fs':
                state = 'fs: is not used by x64 Windows code, suspicious'
            elif offset in TEB_FIELDS:
                state = 'TEB %s, filled' % TEB_FIELDS[offset]
            elif TEB_TLS_SLOTS[0] <= offset < TEB_TLS_SLOTS[1]:
                state = 'TEB TlsSlots, filled by TlsAlloc'
            else:
                state = 'TEB field not filled (reads zero): MISSING'
                missing.append('%s:0x%x' % (register, offset))
            print('  %s:[0x%x] at 0x%x: %s' % (register, offset, address, state))

        if beyond:
            verdicts.append('%s: beyond the line, use Wine' % name)
        elif missing:
            verdicts.append('%s: reaches %d missing (%s); check whether only error paths reach them (the functions above)'
                            % (name, len(missing), ', '.join(missing)))
        else:
            verdicts.append('%s: covered' % name)

    print('\nVerdict:')
    for verdict in verdicts:
        print('  ' + verdict)


if __name__ == '__main__':
    main()
