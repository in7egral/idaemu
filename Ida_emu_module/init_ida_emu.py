"""
          \
           \
            \\
             \\
              >\\/7
          _.-(6'  \
         (=___._/` \
              )  \\ |
             /   / |
            /    > /
           j    < _\
       _.-' :      ``.
       \\ r=._\\        `.
      <`\\_  \\         .`-.
       \\ r-7  `-. ._  ' .  `\
        \\`,      `-.`7  7)   )
         \\/         \\|  \'  / `-._
                    ||    .'
                     \\  (
                      >\\  >
                    ,.-' >.'
                   <.'_.''
                     <'
"""
import os
import sys
import idaapi
import idc
import importlib


def PLUGIN_ENTRY():
    return VTable_plugin_vis()


class VTable_plugin_vision(idaapi.plugin_t):
    flags = 0
    comment = "Welcome to Ida_emu_module"
    help = ""
    wanted_name = "Ida_emu_module"
    wanted_hotkey = "Ctrl-Alt-E"

    def __init__(self):
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.plugin_dir = os.path.join(self.script_dir, 'Ida_emu_module')
        sys.path.append(self.plugin_dir)

    def init(self):
        print("Ida_emu_module initialized")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        import ida_emu_module
        importlib.reload(vtableargs)

        from vtableargs import args_extractor
        a = args_extractor()
        a.main()

    def term(self):
        print("Ida_emu_module is completed")


class VTablePluginActionHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        idaapi.run_plugin("Ida_emu_module", 0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


action_desc = idaapi.action_desc_t(
    "Ida_emu_module:run",
    "Run Ida_emu_module",
    VTablePluginActionHandler(),
    "Shift-Alt-V",
    "Run Ida_emu_module",
    199
)

idaapi.register_action(action_desc)
idaapi.attach_action_to_menu(
    "Edit/Plugins/",
    "Ida_emu_module:run",
    idaapi.SETMENU_APP)
