"""
          \
           \
            \\
             \\
              >\/7
          _.-(6'  \
         (=___._/` \
              )  \ |
             /   / |
            /    > /
           j    < _\
       _.-' :      ``.
       \ r=._\        `.
      <`\\_  \         .`-.
       \ r-7  `-. ._  ' .  `\
        \`,      `-.`7  7)   )
         \/         \|  \'  / `-._
                    ||    .'
                     \\  (
                      >\  >
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
    return Ida_emu_module()

class Ida_emu_module(idaapi.plugin_t):

    flags = 0
    comment = "Ida_emu_module"
    help = ""
    wanted_name = "Ida_emu_module"
    wanted_hotkey = "Ctrl-Alt-E"
    
    def __init__(self): 
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.plugin_dir = os.path.join(self.script_dir, 'Ida_emu_module')
        sys.path.append(self.plugin_dir)

    def init(self):
        print("Ida_emu_module initialized")
        import ida_emu_module
        importlib.reload(ida_emu_module)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        print("Ida_emu_module is running")
        import ida_emu_module
        importlib.reload(ida_emu_module)       

    def term(self):
        print("Ida_emu_module completed")

class Ida_emu_module_ActionHandler(idaapi.action_handler_t):
    
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
    Ida_emu_module_ActionHandler(),
    "Shift-Alt-E",
    "Run Ida_emu_module",
    200  
)

idaapi.register_action(action_desc)
idaapi.attach_action_to_menu(
    "Edit/Plugins/",  
    "Ida_emu_module:run", 
    idaapi.SETMENU_APP)