idaemu
==============

idaemu is an IDA Pro Plugin - use for emulating code in IDA Pro. It is based on [unicorn-engine](http://www.unicorn-engine.org).  

Support architecture:
- X86 (16, 32, 64-bit) 
- ARM 
- ARM64 (ARMv8)
- MIPS (developing)

Install
-------


1. Install Unicorn Engine
If you want to use idaemu, you have to install [unicorn-engine](http://www.unicorn-engine.org) and unicorn's python binding first with pip install unicorn. Then use the `ida_emu_module` as the idapython script.  
Windows: Install Unicorn using pip:
```
pip install unicorn
```
Linux: Install Unicorn from source:
```
git clone https://github.com/unicorn-engine/unicorn.git
cd unicorn
./make.sh
sudo ./make.sh install
```
macOS: Install Unicorn using Homebrew:
```
brew install unicorn
```

2. Install Python Bindings
Ensure you have the correct version of Python installed. Use the idapyswitch tool to select the appropriate Python version for IDA Pro. For example:

```
/Applications/IDA\ Professional\ 9.0.app/Contents/MacOS/idapyswitch 0
The following Python installations were found:
    #0: 3.13.0 ('') (/opt/homebrew/Cellar/python@3.13/3.13.1/Frameworks/Python.framework/Versions/3.13/Python)
    #1: 3.13.0 ('') (/opt/homebrew/Cellar/python@3.13/3.13.2/Frameworks/Python.framework/Versions/3.13/Python)
    #2: 3.12.0 ('') (/opt/homebrew/Cellar/python@3.12/3.12.8/Frameworks/Python.framework/Versions/3.12/Python)
    #3: 3.11.0 ('') (/opt/homebrew/Cellar/python@3.11/3.11.11/Frameworks/Python.framework/Versions/3.11/Python)
    #4: 3.10.0 ('') (/opt/homebrew/Cellar/python@3.10/3.10.16/Frameworks/Python.framework/Versions/3.10/Python)
    #5: 3.9.0 ('') (/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/Python3)
    #6: 3.9.0 ('') (/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Python3)
    #7: 3.9.0 ('') (/opt/homebrew/Cellar/python@3.9/3.9.21/Frameworks/Python.framework/Versions/3.9/Python)
Please pick a number between 0 and 7 (default: 0)
0
Applying version 3.13.0 ('')
```


3. Install idaemu Plugin
Place the Ida_emu_init.py file and the Ida_emu_module folder into the plugins directory of your IDA Pro installation.

Windows/Linux: Copy the files to "IDA Professional 9.0/plugins"

macOS: Move the files to "/Applications/IDA\ Professional\ 9.0.app/Contents/MacOS/plugins"

License
-------
This project is released under the [GPL license](COPYING).


Docs of classes
-------
In the IDA Pro Python console, you can use magic methods to explore the documentation of various classes available for emulating processes
``` python
  python>>> from ida_emu_module import *
  python>>> Emu.__doc__
  python>>> Helper.__doc__
  python>>> QString.__doc__
  python>>> QList.__doc__
  python>>> EmulatedQtHelpers.__doc__
  python>>> QBitArray.__doc__
  python>>> Conv.__doc__
  python>>> EmulatedMath.__doc__
  python>>> Registers.__doc__
  python>>> StdLib_Ops.__doc__
```

Example0
-------
You can also find example of using idaemu in the Ida_emu_module folder

Example1
-------

This is easy function for add. 
```
.text:000000000040052D                 public myadd
.text:000000000040052D myadd           proc near               ; CODE XREF: main+1Bp
.text:000000000040052D
.text:000000000040052D var_4           = dword ptr -4
.text:000000000040052D
.text:000000000040052D                 push    rbp
.text:000000000040052E                 mov     rbp, rsp
.text:0000000000400531                 mov     [rbp+var_4], edi
.text:0000000000400534                 mov     edx, cs:magic	; magic dd 64h 
.text:000000000040053A                 mov     eax, [rbp+var_4]
.text:000000000040053D                 add     eax, edx
.text:000000000040053F                 pop     rbp
.text:0000000000400540                 retn
.text:0000000000400540 myadd           endp
```

Running the idapython script:
``` python
from ida_emu_module import *
a = Emu(UC_ARCH_X86, UC_MODE_64)
print a.eFunc(0x040052D, None, [7])
```

Get the function result:
```
107
```


Example2
-------

If there is a library function call inside the function, we couldn't call it directly. We should use `alt` to hook the library function first.
``` asm
.text:0000000000400560                 public myadd
.text:0000000000400560 myadd           proc near               ; CODE XREF: main+27p
.text:0000000000400560
.text:0000000000400560 var_8           = dword ptr -8
.text:0000000000400560 var_4           = dword ptr -4
.text:0000000000400560
.text:0000000000400560                 push    rbp
.text:0000000000400561                 mov     rbp, rsp
.text:0000000000400564                 sub     rsp, 10h
.text:0000000000400568                 mov     [rbp+var_4], edi
.text:000000000040056B                 mov     [rbp+var_8], esi
.text:000000000040056E                 mov     eax, [rbp+var_8]
.text:0000000000400571                 mov     edx, [rbp+var_4]
.text:0000000000400574                 add     eax, edx
.text:0000000000400576                 mov     esi, eax
.text:0000000000400578                 mov     edi, offset format ; "a+b=%d\n"
.text:000000000040057D                 mov     eax, 0
.text:0000000000400582                 call    _printf
.text:0000000000400587                 leave
.text:0000000000400588                 retn
.text:0000000000400588 myadd           endp
```

Running the idapython scritp:
``` python
from ida_emu_module import *

a = Emu(UC_ARCH_X86, UC_MODE_64)

def myprint(uc, out, args):
    out.append("this is hook output: %d" % args[1])
    return 0

myadd_addr = 0x00400560
printf_addr = 0x00400410 
a.alt(printf_addr, myprint, 2, False)
a.eFunc(myadd_addr, None, [1, 7])
print("---- below is the trace ----")
a.showTrace()
```

Get the result:
```
---- below is the trace ----
this is hook output: 8
```
Well Done. We can alter every function in this way.


Example3
-------

Sometimes it emulates fail with some abort:
``` python
Python>from ida_emu_module import *
Python>a = Emu(UC_ARCH_ARM, UC_MODE_THUMB)
Python>print a.eFunc(here(), 0xbeae, [4])
#ERROR: Invalid instruction (UC_ERR_INSN_INVALID)
1048576
```

Then we can use `setTrace` and `showTrace` for debugging.

``` python
Python>from ida_emu_module import *
Python>a = Emu(UC_ARCH_ARM, UC_MODE_THUMB)
Python>a.setTrace(TRACE_CODE)
Python>a.eFunc(here(), 0xbeae, [4])
#ERROR: Invalid instruction (UC_ERR_INSN_INVALID)
1048576
Python>a.showTrace()
### Trace Instruction at 0x13dc, size = 2
### Trace Instruction at 0x13de, size = 2
### Trace Instruction at 0x13e0, size = 2
......
### Trace Instruction at 0x19c6, size = 2
### Trace Instruction at 0x19c8, size = 2
### Trace Instruction at 0x19ca, size = 2
### Trace Instruction at 0xbeae, size = 2
```
So we found the abort reason (the RA is wrong)
