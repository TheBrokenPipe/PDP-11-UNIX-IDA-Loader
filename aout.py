# WIP

from enum import Enum

import ida_loader
import ida_kernwin
import ida_segment
import ida_bytes
import ida_name
import ida_lines

def read_file(fp, off, count):
    fp.seek(off)
    result = fp.read(count)
    if len(result) != count:
        raise IOError("Failed to read the selected file or invalid format.")
    return result

def get_str(fp, off, len):
    return str(read_file(fp, off, len).decode()).rstrip("\0")

def get_word(fp, off):
    return int.from_bytes(read_file(fp, off, 2), "little")

class SymbolType(Enum):
    OBJECT = 0x1F
    UNDEFINED = 0
    ABS_SYM = 1
    TEXT_SYM = 2
    DATA_SYM = 3
    BSS_SYM = 4
    IMPORT_SYM = 0x20
    ABS_EXT_SYM = 0x21
    TEXT_EXT_SYM = 0x22
    DATA_EXT_SYM = 0x23
    BSS_EXT_SYM = 0x24

class SymbolEntry:
    def __init__(this, name, type, value):
        this._name = name
        this._type = SymbolType(type)
        this._value = value
        this._is_static = False

    def get_name(this):
        return this._name
    def get_type(this):
        return this._type
    def get_value(this):
        return this._value
    def set_name(this, name):
        this._name = name
    def is_static(this):
        return this._is_static
    def make_static(this):
        this._is_static = True

class ExecFile:
    def __init__(this, fp):
        this._text_base = 0
        this._text_off = 0
        this._text_size = 0
        this._data_base = 0
        this._data_off = 0
        this._data_size = 0
        this._bss_base = 0
        this._bss_size = 0
        this._reloc_off = 0
        this._reloc_size = 0
        this._sym_off = 0
        this._sym_size = 0
        this._entry = 0
        this._stack_size = 0
        this._has_reloc = False
        this._has_syms = False
        this._has_mmu = False
        this._base_address = 0
        this._text_data = None
        this._data_data = None
        this._symbols = []

        magic = get_word(fp, 0)
        if magic == 0x105:
            # V1 binary
            this._text_off = 0
            this._text_size = get_word(fp, 2)
            # TODO finish it
        elif magic == 0x107:
            this._text_off = 0x10
            this._text_size = get_word(fp, 2)
            this._data_off = 0x10 + this._text_size
            this._data_size = get_word(fp, 4)
            this._bss_size = get_word(fp, 6)
            this._sym_size = get_word(fp, 8)
            this._entry = get_word(fp, 10)
            this._stack_size = get_word(fp, 12)
            this._has_reloc = get_word(fp, 14) == 0
            
            if this._has_reloc:
                this._reloc_off = 0x10 + this._text_size + this._data_size
                this._reloc_size = this._text_size + this._data_size

            if this._sym_size != 0:
                this._has_syms = True
                this._sym_off = 0x10 + this._text_size + this._data_size + this._reloc_size

            this._has_mmu = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Is this executable intended for machines with relocation hardware (MMU)?") == ida_kernwin.ASKBTN_YES
            if not this._has_mmu:
                this._base_address = 0x4000
            this._text_base = this._base_address
            this._data_base = this._text_base + this._text_size
            this._bss_base = this._data_base + this._data_size

            this._text_data = read_file(fp, this._text_off, this._text_size)
            this._data_data = read_file(fp, this._data_off, this._data_size)

            if this._has_syms:
                for i in range(0, this._sym_size // 12):
                    name = get_str(fp, this._sym_off + i * 12, 8)
                    type = get_word(fp, this._sym_off + i * 12 + 8)
                    value = get_word(fp, this._sym_off + i * 12 + 10)
                    this._symbols.append(SymbolEntry(name, type, value))

    def get_origin(this):
        return this._base_address

    def get_text_seg(this):
        return (this._text_base, this._text_size, this._text_data)

    def get_data_seg(this):
        return (this._data_base, this._data_size, this._data_data)

    def get_bss_seg(this):
        return (this._bss_base, this._bss_size)

    def has_symbols(this):
        return this._has_syms

    def get_symbols(this):
        return this._symbols.copy()

    def get_program_size(this):
        return this._text_size + this._data_size + this._bss_size

def accept_file(f, path):
    magic = get_word(f, 0)
    if magic == 0x105:
        return {
            "format": "UNIX V1 a.out Executable",
            "processor": "PDP11"
        }
    elif magic == 0x107:
        return {
            "format": "UNIX V2+ a.out Executable",
            "processor": "PDP11"
        }
    return 0

def get_objects(syms, length):
    objsyms = get_object_syms(syms)
    sorted_syms = sorted(objsyms, key=lambda sym: sym.get_value()) + [SymbolEntry("", 0x1F, length)]
    result = []
    for i in range(len(sorted_syms) - 1):
        result.append((sorted_syms[i].get_name(), sorted_syms[i].get_value(), sorted_syms[i + 1].get_value() - sorted_syms[i].get_value()))
    return result

def get_object_syms(syms):
    return [sym for sym in syms if (sym.get_type() == SymbolType.OBJECT)]

def get_static_syms(syms):
    result = [sym for sym in syms if (sym.get_type() == SymbolType.TEXT_SYM or sym.get_type() == SymbolType.DATA_SYM or sym.get_type() == SymbolType.BSS_SYM)]
    for sym in result:
        sym.make_static()
    return result

def get_global_syms(syms):
    return [sym for sym in syms if (sym.get_type() == SymbolType.TEXT_EXT_SYM or sym.get_type() == SymbolType.DATA_EXT_SYM or sym.get_type() == SymbolType.BSS_EXT_SYM)]

def get_import_syms(syms):
    return [sym for sym in syms if (sym.get_type() == SymbolType.IMPORT_SYM)]

def rename_symbol(sym, objects):
    for objname, start, _ in reversed(objects):
        if sym.get_value() >= start:
            sym.set_name(sym.get_name() + "@" + objname)
            break

def rename_static_syms(syms, globals, objects):
    name_to_syms = {}
    for sym in syms:
        if sym.get_name() not in name_to_syms:
            name_to_syms[sym.get_name()] = []
        name_to_syms[sym.get_name()].append(sym)

    for name, syms_list in name_to_syms.items():
        if len(syms_list) > 1:
            for sym in syms_list:
                rename_symbol(sym, objects)

    global_names = [g.get_name() for g in globals]
    for sym in syms:
        if sym.get_name() in global_names:
            rename_symbol(sym, objects)

def load_file(f, neflags, format_string):
    file = ExecFile(f)

    text_base, text_size, text_data = file.get_text_seg()
    data_base, data_size, data_data = file.get_data_seg()
    bss_base, bss_size = file.get_bss_seg()

    if text_size != 0:
        ida_segment.add_segm(0, text_base, text_base + text_size, ".text", "CODE")
        ida_bytes.put_bytes(text_base, text_data)
        ida_segment.get_segm_by_name(".text").perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_EXEC

    # Technically data and bss segments are also executable, but let's pretend they're not.

    if data_size != 0:
        ida_segment.add_segm(0, data_base, data_base + data_size, ".data", "DATA")
        ida_bytes.put_bytes(data_base, data_data)
        ida_segment.get_segm_by_name(".data").perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE

    if bss_size != 0:
        ida_segment.add_segm(0, bss_base, bss_base + bss_size, ".bss", "BSS")
        ida_segment.get_segm_by_name(".bss").perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE

    if file.has_symbols():
        syms = file.get_symbols()
        obj_syms = get_object_syms(syms)
        objs = get_objects(obj_syms, file.get_program_size())
        maxlen = 0
        for objname, _, _ in objs:
            maxlen = len(objname) if len(objname) > maxlen else maxlen
        for objname, start, length in objs:
            ida_lines.add_pgm_cmt(f"{objname:<{maxlen}} : {file.get_origin() + start:06o}-{file.get_origin() + start + length:06o} ({length} bytes)")
        static_syms = get_static_syms(syms)
        global_syms = get_global_syms(syms)
        rename_static_syms(static_syms, global_syms, objs)
        for sym in syms:
            #TODO absolute symbols
            if sym.get_type() == SymbolType.TEXT_SYM or sym.get_type() == SymbolType.TEXT_EXT_SYM:
                ida_name.set_name(text_base + sym.get_value(), sym.get_name(), ida_name.SN_NON_PUBLIC if sym.is_static() else ida_name.SN_PUBLIC)
            elif sym.get_type() == SymbolType.DATA_SYM or sym.get_type() == SymbolType.DATA_EXT_SYM:
                ida_name.set_name(data_base + sym.get_value(), sym.get_name(), ida_name.SN_NON_PUBLIC if sym.is_static() else ida_name.SN_PUBLIC)
            elif sym.get_type() == SymbolType.BSS_SYM or sym.get_type() == SymbolType.BSS_EXT_SYM:
                ida_name.set_name(bss_base + sym.get_value(), sym.get_name(), ida_name.SN_NON_PUBLIC if sym.is_static() else ida_name.SN_PUBLIC)
    return 1
