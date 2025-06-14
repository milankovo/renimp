import idaapi
import idc


def rename_pointers(ea1: int, ea2: int):
    if ea1 == idaapi.BADADDR:
        idaapi.warning(
            "Please select the import table before running the renimp script"
        )
        return

    match idc.get_segm_attr(ea1, idc.SEGATTR_BITNESS):
        case 0:
            ptrsz = 2
            DeRef = idaapi.get_word
        case 1:
            ptrsz = 4
            DeRef = idaapi.get_wide_dword
        case 2:
            ptrsz = 8
            DeRef = idaapi.get_qword
        case _:
            idaapi.warning("Unsupported segment bitness!")
            return

    for ea in range(ea1, ea2, ptrsz):
        name = idaapi.get_ea_name(DeRef(ea))
        if not name:
            continue

        idx = name.find("_")
        dllname = name[:idx]

        if dllname == "ws2":
            idx += 3

        func_name = name[idx + 1 :]
        idaapi.set_name(ea1, func_name, idaapi.SN_NOCHECK | idaapi.SN_FORCE)


class renimp_action(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx: idaapi.action_ctx_base_t):
        sel_start = ctx.cur_sel._from.at
        sel_end = ctx.cur_sel.to.at
        if sel_start == idaapi.BADADDR or sel_end == idaapi.BADADDR:
            idaapi.warning("No selection found.")
            return 0
        rename_pointers(sel_start, sel_end)

        return 1

    def update(self, ctx: idaapi.action_ctx_base_t):
        if ctx.widget_type != idaapi.BWN_DISASM:
            return idaapi.AST_DISABLE_FOR_WIDGET
        if not ctx.has_flag(idaapi.ACF_HAS_SELECTION):
            return idaapi.AST_DISABLE
        return idaapi.AST_ENABLE


class RenimpPluginModule(idaapi.plugin_t):
    flags = 0
    comment = "Rename Imports Plugin"
    help = "This plugin renames dynamically built import table entries."
    wanted_name = "Rename Imports"
    wanted_hotkey = "Alt-F8"

    def init(self):
        addon = idaapi.addon_info_t()
        addon.id = "milankovo.renimp"
        addon.name = "renimp"
        addon.producer = "Milankovo"
        addon.url = "https://github.com/milankovo/renimp"
        addon.version = "1.0"
        idaapi.register_addon(addon)
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg: int):
        self.rename_imports()

    def rename_imports(self):
        ok, ea1, ea2 = idaapi.read_range_selection(None)
        if not ok:
            print("No selection found.")
            return

        if ea1 == idaapi.BADADDR or ea2 == idaapi.BADADDR:
            print("No selection found.")
            return

        rename_pointers(ea1, ea2)


def PLUGIN_ENTRY():
    return RenimpPluginModule()
