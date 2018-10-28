from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from struct import unpack, pack, unpack_from, calcsize
import idc
import idaapi
import idautils
import os

PAGE_ALIGN = 0x1000  # 4k

COMPILE_GCC = 1
COMPILE_MSVC = 2

TRACE_OFF = 0
TRACE_DATA_READ = 1
TRACE_DATA_WRITE = 2
TRACE_CODE = 4

NO_EXTENSIONS = 0
VFP_ENABLED = 1

# support for old IDA versions
if idaapi.IDA_SDK_VERSION < 700:
    IDAAPI_GetBytes = idc.get_many_bytes
    IDAAPI_get_qword = Qword
else:
    IDAAPI_GetBytes = idc.get_bytes
    IDAAPI_get_qword = idc.get_qword

class Emu(object):
    def __init__(self, arch, mode, compiler=COMPILE_GCC, stack=0xf000000, \
                 ssize=3):
        assert (arch in [UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64])
        self.arch = arch
        self.mode = mode
        self.compiler = compiler
        self.stack = self._alignAddr(stack)
        self.ssize = ssize
        self.data = []
        self.dataFiles = []
        self.regs = []
        self.curUC = None
        self.traceOption = TRACE_OFF
        self.extensionsSupport = NO_EXTENSIONS
        self.logBuffer = []
        self.altFunc = {}
        self.disalePatchedBytes = False
        self._init()

    def _addTrace(self, logInfo):
        self.logBuffer.append(logInfo)

    # callback for tracing invalid memory access (READ or WRITE, FETCH)
    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        addr = self._alignAddr(address)
        uc.mem_map(addr, PAGE_ALIGN)
        data = self._getOriginData(addr, PAGE_ALIGN)
        uc.mem_write(addr, data)
        return True

    def _hook_mem_access(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE and self.traceOption & TRACE_DATA_WRITE:
            self._addTrace("### Memory WRITE at 0x%x, data size = %u, data value = 0x%x" \
                           % (address, size, value))
        elif access == UC_MEM_READ and self.traceOption & TRACE_DATA_READ:
            self._addTrace("### Memory READ at 0x%x, data size = %u" \
                           % (address, size))

    def _hook_code(self, uc, address, size, user_data):
        if self.traceOption & TRACE_CODE:
            self._addTrace("### Trace Instruction at 0x%x, size = %u" % (address, size))
        if address in self.altFunc.keys():
            func, argc, balance = self.altFunc[address]
            try:
                sp = uc.reg_read(self.REG_SP)
                if self.REG_RA == 0:
                    RA = unpack(self.pack_fmt, str(uc.mem_read(sp, self.step)))[0]
                    sp += self.step
                else:
                    RA = uc.reg_read(self.REG_RA)

                args = []
                i = 0
                while i < argc and i < len(self.REG_ARGS):
                    args.append(uc.reg_read(self.REG_ARGS[i]))
                    i += 1
                sp2 = sp
                while i < argc:
                    args.append(unpack(self.pack_fmt, str(uc.mem_read(sp2, self.step)))[0])
                    sp2 += self.step
                    i += 1

                res = func(uc, self.logBuffer, args)
                if type(res) not in (int,long): res = 0
                uc.reg_write(self.REG_RES, res)
                uc.reg_write(self.REG_PC, RA)
                if balance:
                    uc.reg_write(self.REG_SP, sp2)
                else:
                    uc.reg_write(self.REG_SP, sp)
            except Exception as e:
                self._addTrace("alt exception: %s" % e)

    def _alignAddr(self, addr):
        return addr // PAGE_ALIGN * PAGE_ALIGN

    def _bytes_unpatcher(self, ea, fpos, org_val, patch_val):
        if fpos != -1:
            if type(self.unp_tmp) == tuple:
                self.unp_tmp[ea - self.unp_from_ea] = org_val
            elif type(self.unp_tmp) == long:
                shift = (ea - self.unp_from_ea) * 8
                mask = ~(0xFF << shift)
                self.unp_tmp = (self.unp_tmp  & mask) | (org_val << shift)

    def _unpatch(self, from_ea, to_ea):
        if self.disalePatchedBytes:
            self.unp_from_ea = from_ea
            idaapi.visit_patched_bytes(from_ea, to_ea, self._bytes_unpatcher)

    def _get_unpatched_qword(self, ea):
        self.unp_tmp = IDAAPI_get_qword(ea)
        self._unpatch(ea, ea + 8)
        return self.unp_tmp

    def _getOriginData(self, address, size):
        res = []
        for offset in xrange(0, size, 64):
            self.unp_tmp = IDAAPI_GetBytes(address + offset, 64)
            if self.unp_tmp == None:
                res.extend([pack("<Q", self._get_unpatched_qword(address + offset + i)) for i in range(0, 64, 8)])
            else:
                self._unpatch(address + offset, address + offset + 64)
                res.append(self.unp_tmp)
        res = "".join(res)
        return res[:size]

    def _init(self):
        if self.arch == UC_ARCH_X86:
            if self.mode == UC_MODE_16:
                self.step = 2
                self.pack_fmt = '<H'
                self.REG_PC = UC_X86_REG_IP
                self.REG_SP = UC_X86_REG_SP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_AX
                self.REG_ARGS = []
            elif self.mode == UC_MODE_32:
                self.step = 4
                self.pack_fmt = '<I'
                self.REG_PC = UC_X86_REG_EIP
                self.REG_SP = UC_X86_REG_ESP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_EAX
                self.REG_ARGS = []
            elif self.mode == UC_MODE_64:
                self.step = 8
                self.pack_fmt = '<Q'
                self.REG_PC = UC_X86_REG_RIP
                self.REG_SP = UC_X86_REG_RSP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_RAX
                if self.compiler == COMPILE_GCC:
                    self.REG_ARGS = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
                                     UC_X86_REG_R8, UC_X86_REG_R9]
                elif self.compiler == COMPILE_MSVC:
                    self.REG_ARGS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        elif self.arch == UC_ARCH_ARM:
            if self.mode == UC_MODE_ARM:
                self.step = 4
                self.pack_fmt = '<I'
            elif self.mode == UC_MODE_THUMB:
                self.step = 2
                self.pack_fmt = '<H'
            self.REG_PC = UC_ARM_REG_PC
            self.REG_SP = UC_ARM_REG_SP
            self.REG_RA = UC_ARM_REG_LR
            self.REG_RES = UC_ARM_REG_R0
            self.REG_ARGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        elif self.arch == UC_ARCH_ARM64:
            self.step = 8
            self.pack_fmt = '<Q'
            self.REG_PC = UC_ARM64_REG_PC
            self.REG_SP = UC_ARM64_REG_SP
            self.REG_RA = UC_ARM64_REG_LR
            self.REG_RES = UC_ARM64_REG_X0
            self.REG_ARGS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                             UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]

    def _initStackAndArgs(self, uc, RA, args, DisablePatchRA):
        uc.mem_map(self.stack, (self.ssize + 1) * PAGE_ALIGN)
        sp = self.stack + self.ssize * PAGE_ALIGN
        uc.reg_write(self.REG_SP, sp)

        if not DisablePatchRA:
            if self.REG_RA == 0:
                uc.mem_write(sp, pack(self.pack_fmt, RA))
            else:
                uc.reg_write(self.REG_RA, RA)

        ## init the arguments
        i = 0
        while i < len(self.REG_ARGS) and i < len(args):
            uc.reg_write(self.REG_ARGS[i], args[i])
            i += 1

        while i < len(args):
            sp += self.step
            uc.mem_write(sp, pack(self.pack_fmt, args[i]))
            i += 1

    def _getBit(self, value, offset):
        mask = 1 << offset
        return 1 if (value & mask) > 0 else 0

    def _showRegs(self, uc):
        print(">>> regs:")
        try:
            if self.arch == UC_ARCH_ARM:
                R0 = uc.reg_read(UC_ARM_REG_R0)
                R1 = uc.reg_read(UC_ARM_REG_R1)
                R2 = uc.reg_read(UC_ARM_REG_R2)
                R3 = uc.reg_read(UC_ARM_REG_R3)
                R4 = uc.reg_read(UC_ARM_REG_R4)
                R5 = uc.reg_read(UC_ARM_REG_R5)
                R6 = uc.reg_read(UC_ARM_REG_R6)
                R7 = uc.reg_read(UC_ARM_REG_R7)
                R8 = uc.reg_read(UC_ARM_REG_R8)
                R9 = uc.reg_read(UC_ARM_REG_R9)
                R10 = uc.reg_read(UC_ARM_REG_R10)
                R11 = uc.reg_read(UC_ARM_REG_R11)
                R12 = uc.reg_read(UC_ARM_REG_R12)
                SP = uc.reg_read(UC_ARM_REG_SP) # R13
                PC = uc.reg_read(UC_ARM_REG_PC)
                LR = uc.reg_read(UC_ARM_REG_LR)
                print("    R0 = 0x%x, R1 = 0x%x, R2 = 0x%x" % (R0, R1, R2))
                print("    R3 = 0x%x, R4 = 0x%x, R5 = 0x%x" % (R3, R4, R5))
                print("    R6 = 0x%x, R7 = 0x%x, R8 = 0x%x" % (R6, R7, R8))
                print("    R9 = 0x%x, R10 = 0x%x, R11 = 0x%x" % (R9, R10, R11))
                print("    R12 = 0x%x" % R12)
                print("    SP = 0x%x" % SP)
                print("    PC = 0x%x, LR = 0x%x" % (PC, LR))
            elif self.arch == UC_ARCH_ARM64:
                X0 = uc.reg_read(UC_ARM64_REG_X0)
                X1 = uc.reg_read(UC_ARM64_REG_X1)
                X2 = uc.reg_read(UC_ARM64_REG_X2)
                X3 = uc.reg_read(UC_ARM64_REG_X3)
                X4 = uc.reg_read(UC_ARM64_REG_X4)
                X5 = uc.reg_read(UC_ARM64_REG_X5)
                X6 = uc.reg_read(UC_ARM64_REG_X6)
                X7 = uc.reg_read(UC_ARM64_REG_X7)
                X8 = uc.reg_read(UC_ARM64_REG_X8)
                X9 = uc.reg_read(UC_ARM64_REG_X9)
                X10 = uc.reg_read(UC_ARM64_REG_X10)
                X11 = uc.reg_read(UC_ARM64_REG_X11)
                X12 = uc.reg_read(UC_ARM64_REG_X12)
                X13 = uc.reg_read(UC_ARM64_REG_X13)
                X14 = uc.reg_read(UC_ARM64_REG_X14)
                X15 = uc.reg_read(UC_ARM64_REG_X15)
                X16 = uc.reg_read(UC_ARM64_REG_X16)
                X17 = uc.reg_read(UC_ARM64_REG_X17)
                X18 = uc.reg_read(UC_ARM64_REG_X18)
                X19 = uc.reg_read(UC_ARM64_REG_X19)
                X20 = uc.reg_read(UC_ARM64_REG_X20)
                X21 = uc.reg_read(UC_ARM64_REG_X21)
                X22 = uc.reg_read(UC_ARM64_REG_X22)
                X23 = uc.reg_read(UC_ARM64_REG_X23)
                X24 = uc.reg_read(UC_ARM64_REG_X24)
                X25 = uc.reg_read(UC_ARM64_REG_X25)
                X26 = uc.reg_read(UC_ARM64_REG_X26)
                X27 = uc.reg_read(UC_ARM64_REG_X27)
                X28 = uc.reg_read(UC_ARM64_REG_X28)
                X29 = uc.reg_read(UC_ARM64_REG_X29)
                SP = uc.reg_read(UC_ARM64_REG_SP) # X30
                PC = uc.reg_read(UC_ARM64_REG_PC)
                LR = uc.reg_read(UC_ARM64_REG_LR)
                print("    X0 = 0x%x, X1 = 0x%x, X2 = 0x%x" % (X0, X1, X2))
                print("    X3 = 0x%x, X4 = 0x%x, X5 = 0x%x" % (X3, X4, X5))
                print("    X6 = 0x%x, X7 = 0x%x, X8 = 0x%x" % (X6, X7, X8))
                print("    X9 = 0x%x, X10 = 0x%x, X11 = 0x%x" % (X9, X10, X11))
                print("    X12 = 0x%x, X13 = 0x%x, X14 = 0x%x" % (X12, X13, X14))
                print("    X15 = 0x%x, X16 = 0x%x, X17 = 0x%x" % (X15, X16, X17))
                print("    X18 = 0x%x, X19 = 0x%x, X20 = 0x%x" % (X18, X19, X20))
                print("    X21 = 0x%x, X22 = 0x%x, X23 = 0x%x" % (X21, X22, X23))
                print("    X24 = 0x%x, X25 = 0x%x, X26 = 0x%x" % (X24, X25, X26))
                print("    X27 = 0x%x, X28 = 0x%x, X29 = 0x%x" % (X27, X28, X29))
                print("    SP = 0x%x" % SP)
                print("    PC = 0x%x, LR = 0x%x" % (PC, LR))
            elif self.arch == UC_ARCH_X86:
                eflags = None
                if self.mode == UC_MODE_16:
                    ax = uc.reg_read(UC_X86_REG_AX)
                    bx = uc.reg_read(UC_X86_REG_BX)
                    cx = uc.reg_read(UC_X86_REG_CX)
                    dx = uc.reg_read(UC_X86_REG_DX)
                    di = uc.reg_read(UC_X86_REG_SI)
                    si = uc.reg_read(UC_X86_REG_DI)
                    bp = uc.reg_read(UC_X86_REG_BP)
                    sp = uc.reg_read(UC_X86_REG_SP)
                    ip = uc.reg_read(UC_X86_REG_IP)
                    eflags = uc.reg_read(UC_X86_REG_EFLAGS)

                    print("    AX = 0x%x BX = 0x%x CX = 0x%x DX = 0x%x" % (ax, bx, cx, dx))
                    print("    DI = 0x%x SI = 0x%x BP = 0x%x SP = 0x%x" % (di, si, bp, sp))
                    print("    IP = 0x%x" % ip)
                elif self.mode == UC_MODE_32:
                    eax = uc.reg_read(UC_X86_REG_EAX)
                    ebx = uc.reg_read(UC_X86_REG_EBX)
                    ecx = uc.reg_read(UC_X86_REG_ECX)
                    edx = uc.reg_read(UC_X86_REG_EDX)
                    edi = uc.reg_read(UC_X86_REG_ESI)
                    esi = uc.reg_read(UC_X86_REG_EDI)
                    ebp = uc.reg_read(UC_X86_REG_EBP)
                    esp = uc.reg_read(UC_X86_REG_ESP)
                    eip = uc.reg_read(UC_X86_REG_EIP)
                    eflags = uc.reg_read(UC_X86_REG_EFLAGS)

                    print("    EAX = 0x%x EBX = 0x%x ECX = 0x%x EDX = 0x%x" % (eax, ebx, ecx, edx))
                    print("    EDI = 0x%x ESI = 0x%x EBP = 0x%x ESP = 0x%x" % (edi, esi, ebp, esp))
                    print("    EIP = 0x%x" % eip)
                elif self.mode == UC_MODE_64:
                    rax = uc.reg_read(UC_X86_REG_RAX)
                    rbx = uc.reg_read(UC_X86_REG_RBX)
                    rcx = uc.reg_read(UC_X86_REG_RCX)
                    rdx = uc.reg_read(UC_X86_REG_RDX)
                    rdi = uc.reg_read(UC_X86_REG_RSI)
                    rsi = uc.reg_read(UC_X86_REG_RDI)
                    rbp = uc.reg_read(UC_X86_REG_RBP)
                    rsp = uc.reg_read(UC_X86_REG_RSP)
                    rip = uc.reg_read(UC_X86_REG_RIP)
                    r8 = uc.reg_read(UC_X86_REG_R8)
                    r9 = uc.reg_read(UC_X86_REG_R9)
                    r10 = uc.reg_read(UC_X86_REG_R10)
                    r11 = uc.reg_read(UC_X86_REG_R11)
                    r12 = uc.reg_read(UC_X86_REG_R12)
                    r13 = uc.reg_read(UC_X86_REG_R13)
                    r14 = uc.reg_read(UC_X86_REG_R14)
                    r15 = uc.reg_read(UC_X86_REG_R15)
                    eflags = uc.reg_read(UC_X86_REG_EFLAGS)

                    print("    RAX = 0x%x RBX = 0x%x RCX = 0x%x RDX = 0x%x" % (rax, rbx, rcx, rdx))
                    print("    RDI = 0x%x RSI = 0x%x RBP = 0x%x RSP = 0x%x" % (rdi, rsi, rbp, rsp))
                    print("    R8 = 0x%x R9 = 0x%x R10 = 0x%x R11 = 0x%x R12 = 0x%x " \
                          "R13 = 0x%x R14 = 0x%x R15 = 0x%x" % (r8, r9, r10, r11, r12, r13, r14, r15))
                    print("    RIP = 0x%x" % rip)
                if eflags:
                    print("    EFLAGS:")
                    print("    CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d " \
                          "NT=%d RF=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d"
                          % (self._getBit(eflags, 0),
                             self._getBit(eflags, 2),
                             self._getBit(eflags, 4),
                             self._getBit(eflags, 6),
                             self._getBit(eflags, 7),
                             self._getBit(eflags, 8),
                             self._getBit(eflags, 9),
                             self._getBit(eflags, 10),
                             self._getBit(eflags, 11),
                             self._getBit(eflags, 12) + self._getBit(eflags, 13) * 2,
                             self._getBit(eflags, 14),
                             self._getBit(eflags, 16),
                             self._getBit(eflags, 17),
                             self._getBit(eflags, 18),
                             self._getBit(eflags, 19),
                             self._getBit(eflags, 20),
                             self._getBit(eflags, 21)))
        except UcError as e:
            print("#ERROR: %s" % e)

    def _initData(self):
        # data by values
        for address, data, init in self.data:
            addr = self._alignAddr(address)
            size = PAGE_ALIGN
            while size < len(data): size += PAGE_ALIGN
            self.curUC.mem_map(addr, size)
            if init: self.curUC.mem_write(addr, self._getOriginData(addr, size))
            self.curUC.mem_write(address, data)
        # data by memory dumps
        for filename, address, filesize in self.dataFiles:
            # read data
            f = open(filename, "r+b")
            data = f.read()
            # map data
            addr = self._alignAddr(address)
            size = PAGE_ALIGN
            while addr + size < address + filesize: size += PAGE_ALIGN
            self.curUC.mem_map(addr, size)
            self.curUC.mem_write(address, data)

    def _initRegs(self):
        for reg, value in self.regs:
            self.curUC.reg_write(reg, value)
        if self.arch == UC_ARCH_ARM:
            if self.extensionsSupport & VFP_ENABLED:
                regval = self.curUC.reg_read(UC_ARM_REG_C1_C0_2)
                regval |= (0xF << 20)
                self.curUC.reg_write(UC_ARM_REG_C1_C0_2, regval)
                self.curUC.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        elif self.arch == UC_ARCH_ARM64:
            if self.extensionsSupport & VFP_ENABLED:
                regval = self.curUC.reg_read(UC_ARM64_REG_CPACR_EL1)
                regval |= (1 << 18) | (3 << 20)
                self.curUC.reg_write(UC_ARM64_REG_CPACR_EL1, regval)

    def _initUnicorneUngine(self):
        if self.curUC:
            return
        
        # create Unicorne engine and save 
        uc = Uc(self.arch, self.mode)
        self.curUC = uc

        self._initData()
        self._initRegs()

    def _emulate(self, startAddr, stopAddr, args=[], TimeOut=0, Count=0, DisablePatchRA=False):
        try:
            # reset trace buffer
            self.logBuffer = []
            if self.curUC == None:
                self._initUnicorneUngine()

            uc = self.curUC

            # process arguments passing
            self._initStackAndArgs(uc, stopAddr, args, DisablePatchRA)

            # add the invalid memory access hook
            uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | \
                        UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_invalid)

            # add the trace hook
            if self.traceOption & (TRACE_DATA_READ | TRACE_DATA_WRITE):
                uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._hook_mem_access)
            uc.hook_add(UC_HOOK_CODE, self._hook_code)

            # start emulate
            uc.emu_start(startAddr, stopAddr, timeout=TimeOut, count=Count)
        except UcError as e:
            print("#ERROR: %s (PC = %x)" % (e, self.curUC.reg_read(self.REG_PC)))

    def _is_thumb_ea(self, ea):
        if idaapi.ph.id == idaapi.PLFM_ARM and not idaapi.ph.flag & idaapi.PR_USE64:
            if idaapi.IDA_SDK_VERSION >= 700:
                t = idc.get_sreg(ea, "T") # get T flag
            else:
                t = get_segreg(ea, 20) # get T flag
            return t is not idc.BADSEL and t is not 0
        else:
            return False

    # force Unicorne object to be created before emulating,
    # e.g. to have abilty access data
    def silentStart(self):
        if self.curUC == None:
            self._initUnicorneUngine()

    def reset(self):
        if self.curUC:
            self.curUC = None

    def setMemoryFileData(self, filename, base):
        size = os.path.getsize(filename)
        if size == 0:
            print("file size is zero or file is not found")
            return 0
        self.dataFiles.append((filename, base, size))
        return size

    # set the data before emulation
    def setData(self, address, data, init=False):
        self.data.append((address, data, init))

    def setReg(self, reg, value):
        self.regs.append((reg, value))

    def getReg(self, reg):
        if self.curUC == None:
            print("current uc is none.")
            return
        return self.curUC.reg_read(reg)

    def showRegs(self, *regs):
        if self.curUC == None:
            print("current uc is none.")
            return
        for reg in regs:
            print("0x%x" % self.curUC.reg_read(reg))

    def readStack(self, fmt, count):
        if self.curUC == None:
            print("current uc is none.")
            return
        stackData = []
        stackPointer = self.curUC.reg_read(self.REG_SP)
        for i in range(count):
            dataSize = calcsize(fmt)
            data = self.curUC.mem_read(stackPointer + i * dataSize, dataSize)
            st = unpack_from(fmt, data)
            stackData.append((stackPointer + i * dataSize, st[0]))
        return stackData

    def getData(self, fmt, addr, count=1):
        if self.curUC == None:
            print("current uc is none.")
            return None
        dataSize = calcsize(fmt)
        if dataSize == 0:
            return None
        if count == 1:
            return unpack_from(fmt, self.curUC.mem_read(addr, dataSize))
        res = '['
        for i in range(count):
            st = unpack_from(fmt, self.curUC.mem_read(addr + i * dataSize, dataSize))
            if i < count - 1: res += ' ' * 4
            res += ''.join(str(i) for i in st) if type(st) == tuple else ''.join(st)
            if i < count - 1: res += ','
        res += ']'
        return res

    def showData(self, fmt, addr, count=1):
        if self.curUC == None:
            print("current uc is none.")
            return
        data = self.getData(fmt, addr, count)
        if type(data) == tuple:
            data = ''.join(data)
        print(data)

    def showDump(self, addr, count=1):
        if self.curUC == None:
            print("current uc is none.")
            return
        data = self.curUC.mem_read(addr, count)
        print('[')
        q = ''
        for c in data:
            q += '%02x ' % c
        print(q)
        print(']')

    def setTrace(self, opt):
        if opt != TRACE_OFF:
            self.traceOption |= opt
        else:
            self.traceOption = TRACE_OFF

    def setExtensionEnabled(self, vfp):
        if vfp != VFP_ENABLED:
            self.extensionsSupport &= ~VFP_ENABLED
        else:
            self.extensionsSupport = VFP_ENABLED

    def disablePatchedBytes(self, isDisable=True):
        self.disalePatchedBytes = isDisable

    def showTrace(self):
        logs = "\n".join(self.logBuffer)
        print(logs)

    def alt(self, address, func, argc, balance=False):
        """
        If call the address, will call the func instead.
        the arguments of func : func(uc, consoleouput, args)
        """
        assert (callable(func))
        self.altFunc[address] = (func, argc, balance)

    def eFunc(self, address=None, retAddr=None, args=[], force=False):
        if address == None: address = idc.here()
        func = idaapi.get_func(address)
        if retAddr == None:
            refs = [ref.frm for ref in idautils.XrefsTo(func.start_ea, 0)]
            if len(refs) != 0:
                retAddr = refs[0] + idc.ItemSize(refs[0])
            else:
                print("Please offer the return address.")
                return
        if not force:
            address = func.start_ea
        address = address | 1 if self._is_thumb_ea(address) else address
        self._emulate(address, retAddr, args)
        res = self.curUC.reg_read(self.REG_RES)
        return res

    def eBlock(self, codeStart=None, codeEnd=None):
        if codeStart == None: codeStart = idc.SelStart()
        if codeEnd == None: codeEnd = idc.SelEnd()
        codeStart = codeStart | 1 if self._is_thumb_ea(codeStart) else codeStart
        self._emulate(startAddr=codeStart, stopAddr=codeEnd, args=[], TimeOut=0, Count=0, DisablePatchRA=True)
        self._showRegs(self.curUC)

    def eUntilAddress(self, startAddr, stopAddr, args=[], TimeOut=0, Count=0):
        startAddr = startAddr | 1 if self._is_thumb_ea(startAddr) else startAddr
        self._emulate(startAddr=startAddr, stopAddr=stopAddr, args=args, TimeOut=TimeOut, Count=Count, DisablePatchRA=True)
        self._showRegs(self.curUC)
