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


en
The module idaemu.py

This module provides functionality for code emulation using the Unicorn Engine
in integration with IDA Pro. It includes classes and methods for configuring emulation, working with memory,
registers, tracing, and data processing.

Classes:
- - Emu Exception: An exception used to handle emulation errors.
    - Emu: The main class for managing emulation.

Constants:
- PAGE_ALIGN: The size of the memory page (4 KB).
    - COMPILE_GCC: A constant to specify the GCC compiler.
    - TRACE_OFF, TRACE_DATA_READ, TRACE_DATA_WRITE, TRACE_CODE: Tracing options.
    - NO_EXTENSIONS, VFP_ENABLED: Extension options for ARM/ARM64.
ru
Модуль idaemu.py

Этот модуль предоставляет функциональность для эмуляции кода с использованием Unicorn Engine
в интеграции с IDA Pro. Он включает классы и методы для настройки эмуляции, работы с памятью,
регистрами, трассировкой и обработкой данных.

Классы:
    - EmuException: Исключение, используемое для обработки ошибок эмуляции.
    - Emu: Основной класс для управления эмуляцией.

Константы:
    - PAGE_ALIGN: Размер страницы памяти (4 KB).
    - COMPILE_GCC: Константа для указания компилятора GCC.
    - TRACE_OFF, TRACE_DATA_READ, TRACE_DATA_WRITE, TRACE_CODE: Опции трассировки.
    - NO_EXTENSIONS, VFP_ENABLED: Опции расширений для ARM/ARM64.
"""
from __future__ import print_function
from unicorn import *

from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

from struct import unpack, pack, unpack_from, calcsize
import idc
import idaapi
import idautils
import ida_bytes
import os
import sys
from idaemu_qt import *
from idaapi import get_name_ea
from registers import Registers

PAGE_ALIGN = 0x1000  # 4k

COMPILE_GCC = 1
# COMPILE_MSVC = 2

TRACE_OFF = 0
TRACE_DATA_READ = 1
TRACE_DATA_WRITE = 2
TRACE_CODE = 4

NO_EXTENSIONS = 0
VFP_ENABLED = 1

# support for old IDA versions
if idaapi.IDA_SDK_VERSION < 740:
    IDAAPI_SelStart = idc.SelStart
    IDAAPI_SelEnD = idc.SelEnd
    IDAAPI_ItemSize = idc.ItemSize
else:
    IDAAPI_SelStart = idc.read_selection_start
    IDAAPI_SelEnD = idc.read_selection_end
    IDAAPI_ItemSize = idc.get_item_size

if idaapi.IDA_SDK_VERSION < 700:
    IDAAPI_GetBytes = idc.get_many_bytes
    IDAAPI_get_qword = Qword
    IDAAPI_IsLoaded = isLoaded
else:
    IDAAPI_GetBytes = idc.get_bytes
    IDAAPI_get_qword = idc.get_qword
    IDAAPI_IsLoaded = idc.is_loaded


class EmuException(Exception):
    """
    en
    An exception used to handle emulation errors.
    ru
    Исключение, используемое для обработки ошибок эмуляции.
    """
    pass


class Emu(object):
    """
    en
    The Emu class provides functionality for emulating code using the Unicorn Engine
    in integration with IDA Pro. This class allows you to configure emulation and work with memory.,
    registers, tracing, and also perform emulation of functions and code blocks.

    Main features:
- Setting up emulation for various architectures (x86, ARM, ARM64).
- Working with memory: reading, writing, downloading data and files.
        - Register management: reading, writing, displaying values.
        - Tracing code execution, reading/writing data.
        - Emulation of functions, code blocks and execution to a specific address.
        - Support for alternative functions for emulation.

    Attributes:
        - arch (int): Processor architecture (for example, UC_ARCH_X86, UC_ARCH_ARM).
        - mode (int): Processor operating mode (for example, UC_MODE_32, UC_MODE_64).
- compiler (int): The type of compiler (for example, COMPILE_GCC).
        - stack (int): The stack address.
        - ssize (int): The stack size in pages.
        - data (list): A list of data to initialize the memory.
        - dataFiles (list): A list of files to load into memory.
        - regs (list): A list of registers and their values.
        - curUC (Uc): The current Unicorn Engine object.
        - traceOption (int): Tracing options (for example, TRACE_CODE, TRACE_DATA_READ).
        - patchOption (bool): A flag for enabling memory patches.
        - extensionsSupport (int): Extension options (for example, VFP_ENABLED).
        - logBuffer (list): A buffer for storing trace logs.
        - altFunc (dict): A dictionary of alternative functions for emulation.
        - disablePatchedBytes (bool): A flag for disabling byte patches.
        - imports_list (dict): A list of imported functions.

    Methods:
        - __init__: Constructor of the class. Initializes the architecture, registers, and emulation parameters.
        - silentStart: Creates a Unicorn Engine object without running emulation.
        - reset: Resets the state of the emulator.
        - setMemoryFileData: Loads the file into memory.
        - setData: Sets data to memory.
        - setReg: Sets the register value.
        - getReg: Gets the register value.
        - showAllRegs: Outputs the values of all registers.
        - showRegs: Outputs the values of the specified registers.
        - readStack: Reads data from the stack.
        - getData: Retrieves data from memory.
        - showData: Outputs data from memory.
        - showDump: Outputs a memory dump.
        - setTrace: Sets the tracing options.
        - setPatch: Enables or disables memory patches.
        - setExtensionEnabled: Enables or disables extensions (for example, VFP).
        - disablePatchedBytes: Disables byte patches.
        - showTrace: Outputs trace logs.
        - alt: Sets an alternative function for the specified address.
        - eFunc: Performs function emulation.
        - eBlock: Performs code block emulation.
        - eUntilAddress: Performs emulation to the specified address.
        - altQt5: Installs alternative functions for Qt5.
    ru
    Класс Emu предоставляет функциональность для эмуляции кода с использованием Unicorn Engine
    в интеграции с IDA Pro. Этот класс позволяет настраивать эмуляцию, работать с памятью,
    регистрами, трассировкой, а также выполнять эмуляцию функций и блоков кода.

    Основные возможности:
        - Настройка эмуляции для различных архитектур (x86, ARM, ARM64).
        - Работа с памятью: чтение, запись, загрузка данных и файлов.
        - Управление регистрами: чтение, запись, отображение значений.
        - Трассировка выполнения кода, чтения/записи данных.
        - Эмуляция функций, блоков кода и выполнение до определенного адреса.
        - Поддержка альтернативных функций для эмуляции.

    Атрибуты:
        - arch (int): Архитектура процессора (например, UC_ARCH_X86, UC_ARCH_ARM).
        - mode (int): Режим работы процессора (например, UC_MODE_32, UC_MODE_64).
        - compiler (int): Тип компилятора (например, COMPILE_GCC).
        - stack (int): Адрес стека.
        - ssize (int): Размер стека в страницах.
        - data (list): Список данных для инициализации памяти.
        - dataFiles (list): Список файлов для загрузки в память.
        - regs (list): Список регистров и их значений.
        - curUC (Uc): Текущий объект Unicorn Engine.
        - traceOption (int): Опции трассировки (например, TRACE_CODE, TRACE_DATA_READ).
        - patchOption (bool): Флаг включения патчей памяти.
        - extensionsSupport (int): Опции расширений (например, VFP_ENABLED).
        - logBuffer (list): Буфер для хранения логов трассировки.
        - altFunc (dict): Словарь альтернативных функций для эмуляции.
        - disablePatchedBytes (bool): Флаг отключения патчей байтов.
        - imports_list (dict): Список импортируемых функций.

    Методы:
        - __init__: Конструктор класса. Инициализирует архитектуру, регистры и параметры эмуляции.
        - silentStart: Создает объект Unicorn Engine без запуска эмуляции.
        - reset: Сбрасывает состояние эмулятора.
        - setMemoryFileData: Загружает файл в память.
        - setData: Устанавливает данные в память.
        - setReg: Устанавливает значение регистра.
        - getReg: Получает значение регистра.
        - showAllRegs: Выводит значения всех регистров.
        - showRegs: Выводит значения указанных регистров.
        - readStack: Читает данные из стека.
        - getData: Получает данные из памяти.
        - showData: Выводит данные из памяти.
        - showDump: Выводит дамп памяти.
        - setTrace: Устанавливает опции трассировки.
        - setPatch: Включает или отключает патчи памяти.
        - setExtensionEnabled: Включает или отключает расширения (например, VFP).
        - disablePatchedBytes: Отключает патчи байтов.
        - showTrace: Выводит логи трассировки.
        - alt: Устанавливает альтернативную функцию для указанного адреса.
        - eFunc: Выполняет эмуляцию функции.
        - eBlock: Выполняет эмуляцию блока кода.
        - eUntilAddress: Выполняет эмуляцию до указанного адреса.
        - altQt5: Устанавливает альтернативные функции для Qt5.
    """

    def __init__(
            self,
            arch,
            mode,
            compiler=COMPILE_GCC,
            stack=0xf000000,
            ssize=3):
        """
        en
        Constructor of the Emu class.

        Arguments:
            - arch: Processor architecture (UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64).
            - mode: Processor operating mode (UC_MODE_16, UC_MODE_32, UC_MODE_64).
            - compiler: Compiler type (default COMPILE_GCC).
            - stack: Stack address (default is 0xf000000).
            - - size: Stack size (3 pages by default).
        ru
        Конструктор класса Emu.

        Аргументы:
            - arch: Архитектура процессора (UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64).
            - mode: Режим работы процессора (UC_MODE_16, UC_MODE_32, UC_MODE_64).
            - compiler: Тип компилятора (по умолчанию COMPILE_GCC).
            - stack: Адрес стека (по умолчанию 0xf000000).
            - ssize: Размер стека (по умолчанию 3 страницы).
        """
        assert (arch in [UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64])
        self.arch = arch
        self.mode = mode
        self.compiler = compiler
        self.stack = self._align_address(stack)
        self.ssize = ssize
        self.data = []
        self.dataFiles = []
        self.regs = []
        self.curUC = None
        self.traceOption = TRACE_OFF
        self.patchOption = False
        self.extensionsSupport = NO_EXTENSIONS
        self.logBuffer = []
        self.altFunc = {}
        self.disablePatchedBytes = False
        self.imports_list = {}

        self.registers = Registers(
            arch=self.arch,
            mode=self.mode,
            compiler=self.compiler)
        self.registers._initialize_architecture()

        self.step = self.registers.step
        self.pack_fmt = self.registers.pack_fmt
        self.REG_PC = self.registers.REG_PC
        self.REG_SP = self.registers.REG_SP
        self.REG_RA = self.registers.REG_RA
        self.REG_RES = self.registers.REG_RES
        self.REG_ARGS = self.registers.REG_ARGS

        self.mapped_ranges = []

    def _add_trace_info(self, logInfo):
        self.logBuffer.append(logInfo)

    # callback for tracing invalid memory access (READ or WRITE, FETCH)
    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        addr = self._align_address(address)
        uc.mem_map(addr, PAGE_ALIGN)
        data = self._get_idb_data(addr, PAGE_ALIGN)
        uc.mem_write(addr, data)
        return True

    def _hook_mem_access(self, uc, access, address, size, value, user_data):
        if self.patchOption and access == UC_MEM_WRITE:
            if size == 1:
                ida_bytes.patch_byte(address, value)
            elif size == 2:
                ida_bytes.patch_word(address, value)
            elif size == 4:
                ida_bytes.patch_dword(address, value)
            elif size == 8:
                ida_bytes.patch_byte(address, value)
            else:
                tmp_value = value
                tmp_size = size
                tmp_address = address
                while size > 0:
                    ida_bytes.patch_byte(tmp_address, tmp_value & 0xFF)
                    tmp_value >>= 8
                    tmp_address += 1
                    size -= 1
        if access == UC_MEM_WRITE and self.traceOption & TRACE_DATA_WRITE:
            self._add_trace_info(
                "### Memory WRITE at 0x%x, data size = %u, data value = 0x%x" %
                (address, size, value))
        elif access == UC_MEM_READ and self.traceOption & TRACE_DATA_READ:
            self._add_trace_info("### Memory READ at 0x%x, data size = %u"
                                 % (address, size))

    def _parse_var_arg(self, uc, address):
        last_is_percent = False
        count = 0
        while True:
            ch = uc.mem_read(address, 1)
            if ch == 0:
                break
            if ch == '%':
                if last_is_percent:
                    last_is_percent = 0  # escaped '%%'
                else:
                    last_is_percent = 1
            else:
                count += 1
                last_is_percent = 0
            address += 1
        return count

    def _callback(self, ea, name, ordinal):
        # print(f'{ea:x} {name}')
        self.imports_list[ea] = {'name': name, 'ord': ordinal}
        return True

    def _process_iat(self):
        implist = idaapi.get_import_module_qty()
        for i in range(0, implist):
            # name = idaapi.get_import_module_name(i)
            # print(name)
            idaapi.enum_import_names(i, self._callback)

    def _hook_code(self, uc, address, size, user_data):
        if self.traceOption & TRACE_CODE:
            self._add_trace_info(
                "### Trace Instruction at 0x%x, size = %u" %
                (address, size))
        if address in self.altFunc.keys():
            func, argc, balance, force_ret = self.altFunc[address]
            try:
                sp = uc.reg_read(self.REG_SP)
                if self.REG_RA == 0:
                    if sys.version_info >= (3, 0):
                        RA = unpack(
                            self.pack_fmt, bytearray(
                                uc.mem_read(
                                    sp, self.step)))[0]
                    else:
                        RA = unpack(
                            self.pack_fmt, str(
                                uc.mem_read(
                                    sp, self.step)))[0]
                    sp += self.step
                else:
                    RA = uc.reg_read(self.REG_RA)
                if force_ret != 0:
                    RA = force_ret

                # process VAR_ARGS
                if argc < 0:
                    # extract format argument #
                    var_arg = -(1 + argc)  # -1 for 0, -2 for 1, ...
                    if var_arg < len(self.REG_ARGS):
                        var_arg_address = uc.reg_read(self.REG_ARGS[var_arg])
                    else:
                        var_arg_address = uc.mem_read(
                            sp + self.step * var_arg, self.step)
                    argc = var_arg + 1 + \
                        self._parse_var_arg(uc, var_arg_address)

                args = []
                i = 0
                while i < argc and i < len(self.REG_ARGS):
                    args.append(uc.reg_read(self.REG_ARGS[i]))
                    i += 1
                sp2 = sp
                while i < argc:
                    if sys.version_info >= (3, 0):
                        args.append(
                            unpack(
                                self.pack_fmt,
                                bytearray(
                                    uc.mem_read(
                                        sp2,
                                        self.step)))[0])
                    else:
                        args.append(
                            unpack(
                                self.pack_fmt, str(
                                    uc.mem_read(
                                        sp2, self.step)))[0])
                    sp2 += self.step
                    i += 1

                res = func(uc, self.logBuffer, args)
                if sys.version_info >= (3, 0):
                    if type(res) is not int:
                        res = 0
                else:
                    if type(res) not in (int, long):
                        res = 0
                uc.reg_write(self.REG_RES, res)
                uc.reg_write(self.REG_PC, RA)
                if balance:
                    uc.reg_write(self.REG_SP, sp2)
                else:
                    uc.reg_write(self.REG_SP, sp)
            except Exception as e:
                self._add_trace_info("alt exception: %s" % e)
                raise e
        elif address in self.imports_list.keys():
            RA = uc.reg_read(self.REG_RA)
            raise EmuException(
                f"Ea {address:x} (return to {RA:x}) is unhooked import {self.imports_list[address]['name']}, {self.imports_list[address]['ord']}")

    def _align_address(self, addr):
        return addr // PAGE_ALIGN * PAGE_ALIGN

    def _bytes_unpatcher(self, ea, fpos, org_val, patch_val):
        if fpos != -1:
            if isinstance(self.unp_tmp, tuple):
                self.unp_tmp[ea - self.unp_from_ea] = org_val
            elif isinstance(self.unp_tmp, long):
                shift = (ea - self.unp_from_ea) * 8
                mask = ~(0xFF << shift)
                self.unp_tmp = (self.unp_tmp & mask) | (org_val << shift)

    def _unpatch(self, from_ea, to_ea):
        if self.disablePatchedBytes:
            self.unp_from_ea = from_ea
            idaapi.visit_patched_bytes(from_ea, to_ea, self._bytes_unpatcher)

    def _get_unpatched_qword(self, ea):
        self.unp_tmp = IDAAPI_get_qword(ea)
        self._unpatch(ea, ea + 8)
        return self.unp_tmp

    def _get_idb_data(self, address, size):
        res = []
        for offset in range(0, size, 64):
            self.unp_tmp = IDAAPI_GetBytes(address + offset, 64)
            if self.unp_tmp is None:
                res.extend([pack("<Q", self._get_unpatched_qword(
                    address + offset + i)) for i in range(0, 64, 8)])
            else:
                self._unpatch(address + offset, address + offset + 64)
                res.append(self.unp_tmp)
        if sys.version_info >= (3, 0):
            res = b''.join(res)
        else:
            res = ''.join(res)
        return res[:size]

    def _init_stack_and_args(self, uc, RA, args, DisablePatchRA):
        uc.mem_map(self.stack, (self.ssize + 1) * PAGE_ALIGN)
        sp = self.stack + self.ssize * PAGE_ALIGN
        uc.reg_write(self.REG_SP, sp)

        if not DisablePatchRA:
            if self.REG_RA == 0:
                uc.mem_write(sp, pack(self.pack_fmt, RA))
            else:
                uc.reg_write(self.REG_RA, RA)

        # init the arguments
        i = 0
        while i < len(self.REG_ARGS) and i < len(args):
            uc.reg_write(self.REG_ARGS[i], args[i])
            i += 1

        while i < len(args):
            sp += self.step
            uc.mem_write(sp, pack(self.pack_fmt, args[i]))
            i += 1

    def _get_bit(self, value, offset):
        mask = 1 << offset
        return 1 if (value & mask) > 0 else 0

    def _show_registers(self, uc):
        self.registers._show_registers(uc=uc)

    def _is_range_mapped(self, addr, size):
        for page_start, page_end in self.mapped_ranges:
            if addr < page_end and addr + size > page_start:
                return True
        return False

    def _init_data(self):

        for address, data, init in self.data:
            addr = self._align_address(address)
            size = 0x1000
            while size < len(data):
                size += 0x1000

            if not self._is_range_mapped(addr, size):
                self.curUC.mem_map(addr, size)
                self.mapped_ranges.append((addr, addr + size))

            if init:
                self.curUC.mem_write(addr, self._get_idb_data(addr, size))

            self.curUC.mem_write(address, data)

        for filename, address, filesize in self.dataFiles:
            with open(filename, "r+b") as f:
                data = f.read()

            addr = self._align_address(address)
            size = 0x1000
            while addr + size < address + filesize:
                size += 0x1000

            if not self._is_range_mapped(addr, size):
                self.curUC.mem_map(addr, size)
                self.mapped_ranges.append((addr, addr + size))

            self.curUC.mem_write(address, data)

    def _init_registers(self):
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

    def _init_unicorne_engine(self):
        if self.curUC:
            return

        # create Unicorne engine and save
        uc = Uc(self.arch, self.mode)
        self.curUC = uc

        self._init_data()
        self._init_registers()

    def _emulate(
            self,
            startAddr,
            stopAddr,
            args=[],
            TimeOut=0,
            Count=0,
            DisablePatchRA=False):
        try:
            # reset trace buffer
            self.logBuffer = []
            if self.curUC is None:
                self._init_unicorne_engine()

            uc = self.curUC

            # process arguments passing
            self._init_stack_and_args(uc, stopAddr, args, DisablePatchRA)

            # add the invalid memory access hook
            uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                        UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_invalid)

            # add the trace hook
            if self.traceOption & (
                    TRACE_DATA_READ | TRACE_DATA_WRITE) or self.patchOption:
                uc.hook_add(
                    UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                    self._hook_mem_access)
            uc.hook_add(UC_HOOK_CODE, self._hook_code)

            # start emulate
            uc.emu_start(startAddr, stopAddr, timeout=TimeOut, count=Count)
        except UcError as e:
            print("#ERROR: %s (PC = %x)" %
                  (e, self.curUC.reg_read(self.REG_PC)))

    def _is_thumb_ea(self, ea):
        if idaapi.ph.id == idaapi.PLFM_ARM and not idaapi.ph.flag & idaapi.PR_USE64:
            if idaapi.IDA_SDK_VERSION >= 700:
                t = idc.get_sreg(ea, "T")  # get T flag
            else:
                t = get_segreg(ea, 20)  # get T flag
            if sys.version_info >= (3, 0):
                return (t != idc.BADSEL) and (t != 0)
            else:
                return (t != idc.BADSEL) and (t != 0)
        else:
            return False

    # force Unicorne object to be created before emulating,
    # e.g. to have ability access data
    def silentStart(self):
        """
        en
        Creates a Unicorn Engine object without running emulation.
        ru
        Создает объект Unicorn Engine без запуска эмуляции.
        """
        if self.curUC is None:
            self._init_unicorne_engine()

    def reset(self):
        """
        en
        Resets the status of the emulator.
        ru
        Сбрасывает состояние эмулятора.
        """
        if self.curUC:
            self.curUC = None

    def setMemoryFileData(self, filename, base):
        """
        en
        Loads the file into memory.

        Arguments:
            - filename: The file name.
            - base: The base address of the download.

        Returns:
            - int: File size.
        ru
        Загружает файл в память.

        Аргументы:
            - filename: Имя файла.
            - base: Базовый адрес загрузки.

        Возвращает:
            - int: Размер файла.
        """
        size = os.path.getsize(filename)
        if size == 0:
            print("file size is zero or file is not found")
            return 0
        self.dataFiles.append((filename, base, size))
        return size

    # set the data before emulation
    def setData(self, address, data, init=False):
        """
        en
        Sets the data to memory.

        Arguments:
            - address: The memory address.
            - data: Data for recording.
            - init: Initialization flag (False by default).
        ru
        Устанавливает данные в память.

        Аргументы:
            - address: Адрес памяти.
            - data: Данные для записи.
            - init: Флаг инициализации (по умолчанию False).
        """
        self.data.append((address, data, init))

    def setReg(self, reg, value):
        """
        en
        Sets the case value.

        Arguments:
            - reg: Register.
            - value: The value.
        ru
        Устанавливает значение регистра.

        Аргументы:
            - reg: Регистр.
            - value: Значение.
        """
        self.regs.append((reg, value))

    def getReg(self, reg):
        """
        en
        Gets the case value.

        Arguments:
            - reg: Register.

        Returns:
            - int: The value of the register.
        ru
        Получает значение регистра.

        Аргументы:
            - reg: Регистр.

        Возвращает:
            - int: Значение регистра.
        """
        if self.curUC is None:
            print("current uc is none.")
            return
        return self.curUC.reg_read(reg)

    def showAllRegs(self):
        """
        en
        Outputs the values of all registers.
        ru
        Выводит значения всех регистров.
        """
        if self.curUC is None:
            print("current uc is none.")
            return
        self._show_registers(self.curUC)

    def showRegs(self, *regs):
        """
        en
        Outputs the values of the specified registers.

        Arguments:
            - *regs: A list of registers.
        ru
        Выводит значения указанных регистров.

        Аргументы:
            - *regs: Список регистров.
        """
        if self.curUC is None:
            print("current uc is none.")
            return
        for reg in regs:
            print("0x%x" % self.curUC.reg_read(reg))

    def readStack(self, fmt, count):
        """
        en
        Reads data from the stack.

        Arguments:
            - fmt: Data format.
            - count: The number of items.

        Returns:
            - list: A list of data from the stack.
        ru
        Читает данные из стека.

        Аргументы:
            - fmt: Формат данных.
            - count: Количество элементов.

        Возвращает:
            - list: Список данных из стека.
        """
        if self.curUC is None:
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
        """
        en
        Reads data from the emulator's memory in the specified format.

        Description:
            - Uses the 'fmt` format to interpret data from memory.
            - If `count` is 1, it returns one value.
            - If `count` is greater than 1, it returns a list of values.

        Arguments:
            - fmt (str): Data format (for example, '<I', '<Q', '<f').
            - addr (int): The memory address to read the data from.
            - count (int): The number of items to read (1 by default).

        Returns:
            - tuple or bytes: Read data in the specified format.
            - None: If the Unicorn Engine is not initialized or the format is incorrect.

        Exceptions:
            - Occur if the memory cannot be read or the address is out of bounds.

        Example:
            data = self.getData('<I', 0x1000, 2)
            print(data)  # Output: (value 1, value 2)
        ru
        Читает данные из памяти эмулятора в указанном формате.

        Описание:
            - Использует формат `fmt` для интерпретации данных из памяти.
            - Если `count` равен 1, возвращает одно значение.
            - Если `count` больше 1, возвращает список значений.

        Аргументы:
            - fmt (str): Формат данных (например, '<I', '<Q', '<f').
            - addr (int): Адрес памяти, с которого нужно читать данные.
            - count (int): Количество элементов для чтения (по умолчанию 1).

        Возвращает:
            - tuple или bytes: Прочитанные данные в указанном формате.
            - None: Если Unicorn Engine не инициализирован или формат некорректен.

        Исключения:
            - Возникают, если чтение памяти невозможно или адрес выходит за пределы.

        Пример:
            data = self.getData('<I', 0x1000, 2)
            print(data)  # Вывод: (значение1, значение2)
        """
        if self.curUC is None:
            print("current uc is none.")
            return None
        dataSize = calcsize(fmt)
        if dataSize == 0:
            return None
        if count == 1:
            return unpack_from(fmt, self.curUC.mem_read(addr, dataSize))
        if sys.version_info < (3, 0):
            res = '['
        else:
            res = b''
        for i in range(count):
            st = unpack_from(
                fmt, self.curUC.mem_read(
                    addr + i * dataSize, dataSize))
            if sys.version_info >= (3, 0):
                res += b''.join(bytearray(i)
                                for i in st) if isinstance(st, tuple) else b''.join(st)
            else:
                if i < count - 1:
                    res += ' ' * 4
                res += ''.join(str(i)
                               for i in st) if isinstance(st, tuple) else ''.join(st)
                if i < count - 1:
                    res += ','
        if sys.version_info < (3, 0):
            res += ']'
        return res

    def showData(self, fmt, addr, count=1):
        """
        en
        Outputs data from the emulator's memory in the specified format.

        Description:
            - Uses the 'getData` method to read the data.
            - Converts data to a string or bytes for display.

        Arguments:
            - fmt (str): Data format (for example, '<I', '<Q', '<f').
            - addr (int): The memory address to read the data from.
            - count (int): The number of items to read (1 by default).

        Returns:
            - None

        Example:
            self.showData('<I', 0x1000, 2)
            # # Output: (value 1, value 2)
        ru
        Выводит данные из памяти эмулятора в указанном формате.

        Описание:
            - Использует метод `getData` для чтения данных.
            - Преобразует данные в строку или байты для отображения.

        Аргументы:
            - fmt (str): Формат данных (например, '<I', '<Q', '<f').
            - addr (int): Адрес памяти, с которого нужно читать данные.
            - count (int): Количество элементов для чтения (по умолчанию 1).

        Возвращает:
            - None

        Пример:
            self.showData('<I', 0x1000, 2)
            # Вывод: (значение1, значение2)
        """
        if self.curUC is None:
            print("current uc is none.")
            return
        data = self.getData(fmt, addr, count)
        if isinstance(data, tuple):
            if sys.version_info >= (3, 0):
                data = b''.join(data)
            else:
                data = ''.join(data)
        print(data)

    def _is_address_mapped(self, addr, size):

        for page_start, page_end in self.mapped_ranges:
            if addr >= page_start and addr + size <= page_end:
                return True
        return False

    def showDump(self, addr, count=1):
        """
        en
        Outputs a memory dump in the specified range.

        Description:
            - Checks whether the address is within the allocated memory.
            - Reads data from memory and outputs it as hexadecimal values.

        Arguments:
            - addr (int): The initial address.
            - count (int): The number of bytes to read.

        Returns:
            - None

        Example:
            self.showDump(0x1000, 16)
            # Output: [00 01 02 03 ...]
        ru
        Выводит дамп памяти в указанном диапазоне.

        Описание:
            - Проверяет, находится ли адрес в пределах выделенной памяти.
            - Читает данные из памяти и выводит их в виде шестнадцатеричных значений.

        Аргументы:
            - addr (int): Начальный адрес.
            - count (int): Количество байтов для чтения.

        Возвращает:
            - None

        Пример:
            self.showDump(0x1000, 16)
            # Вывод: [00 01 02 03 ...]
        """
        if self.curUC is None:
            print("current uc is none.")
            return

        if not self._is_address_mapped(addr, count):
            # print(f"Error: Address {hex(addr)} is not mapped or exceeds mapped range.")
            # pass
            return

        try:
            data = self.curUC.mem_read(addr, count)
            print('[')
            q = ''
            for c in data:
                q += '%02x ' % c
            print(q)
            print(']')
        except Exception as e:
            print(f"Error reading memory at {hex(addr)}: {e}")

    def setTrace(self, opt):
        """
        en
        Sets the tracing options.

        Arguments:
            - - opt (int): Tracing options (for example, TRACE_MODE, TRACE_DATA_READ).

        Returns:
            - None

        Example:
            self.set Trace(TRACE_CODE)
        ru
        Устанавливает опции трассировки.

        Аргументы:
            - opt (int): Опции трассировки (например, TRACE_CODE, TRACE_DATA_READ).

        Возвращает:
            - None

        Пример:
            self.setTrace(TRACE_CODE)
        """
        if opt != TRACE_OFF:
            self.traceOption |= opt
        else:
            self.traceOption = TRACE_OFF

    def setPatch(self, opt):
        """
        en
        Enables or disables memory patches.

        Arguments:
            - opt (bool): True for enabling patches, False for disabling.

        Returns:
            - None

        Example:
            self.setPatch(True)
        ru
        Включает или отключает патчи памяти.

        Аргументы:
            - opt (bool): True для включения патчей, False для отключения.

        Возвращает:
            - None

        Пример:
            self.setPatch(True)
        """
        if opt:
            self.patchOption = True
        else:
            self.patchOption = False

    def setExtensionEnabled(self, vfp):
        """
        en
        Enables or disables the placement (for example, VFP).

        Arguments:
            - vfp (int): Change option (parameter, VFP_ENABLED).

        Returns:
            "No," I said.

        Example:
            self.set Extension enabled(VFP_ENABLED)
        ru
        Включает или отключает расширения (например, VFP).

        Аргументы:
            - vfp (int): Опция расширения (например, VFP_ENABLED).

        Возвращает:
            - None

        Пример:
            self.setExtensionEnabled(VFP_ENABLED)
        """
        if vfp != VFP_ENABLED:
            self.extensionsSupport &= ~VFP_ENABLED
        else:
            self.extensionsSupport = VFP_ENABLED

    def disablePatchedBytes(self, isDisable=True):
        """
        en
        Disables byte patches.

        Arguments:
             isdisabled (bool): True to disable patches, False to enable.

        Returns:
            - None

        Example:
            self.disablePatchedBytes(True)
        ru

        Отключает патчи байтов.

        Аргументы:
            - isDisable (bool): True для отключения патчей, False для включения.

        Возвращает:
            - None

        Пример:
            self.disablePatchedBytes(True)
        """
        self.disablePatchedBytes = isDisable

    def showTrace(self):
        """
        en
        Outputs the trace logs.

        Returns:
            - None

        Example:
            self.showTrace()
        ru
        Выводит логи трассировки.

        Возвращает:
            - None

        Пример:
            self.showTrace()
        """
        logs = "\n".join(self.logBuffer)
        print(logs)

    def alt(self, address, func, argc, balance=False, force_ret=0):
        """
        en
        Sets an alternative function for the specified address.

        Arguments:
            - - Address (internal): Address Function.
            - function (called): Administrative addressfunction.
            - argc (int): The number of arguments.
            - balance (bool): balancing error (possibly false).
            - force_ret (int): The initial value of the call (total 0).

        Returns:
            "No," I said.

        Example:
            self.alt(0x1000, my_function, 2)

        If you call the address, the function will be called instead.
        function arguments : func(uc, console output, args)
        ru
        Устанавливает альтернативную функцию для указанного адреса.

        Аргументы:
            - address (int): Адрес функции.
            - func (callable): Альтернативная функция.
            - argc (int): Количество аргументов.
            - balance (bool): Флаг балансировки стека (по умолчанию False).
            - force_ret (int): Принудительное значение возврата (по умолчанию 0).

        Возвращает:
            - None

        Пример:
            self.alt(0x1000, my_function, 2)

        If call the address, will call the func instead.
        the arguments of func : func(uc, consoleouput, args)
        """
        assert (callable(func))
        self.altFunc[address] = (func, argc, balance, force_ret)

    def eFunc(self, address=None, retAddr=None, args=[], force=False):
        """
        en
        Performs function emulation starting from the specified address.

        Description:
            - If the function address (`address`) is not specified, the current cursor address in IDA Pro is used.
            - Determines the return address (`retAddr') from the function references, if it is not specified.
            - Performs function emulation using the Unicorn Engine.
            - Returns the result value from the result register (`REG_RES').

        Arguments:
            - address (int, optional): The address of the start of the function. If not specified, the current IDA address is used.
            - retAddr (int, optional): The return address. If not specified, it is detected automatically.
            - args (list, optional): A list of arguments for the function (by default, an empty list).
            - force (bool, optional): If `True', it forcibly uses the specified address, ignoring the beginning of the function (default is `False`).

        Returns:
            - int: The value of the result from the result register (`REG_RES').

        Exceptions:
            - If the return address cannot be determined, a message is displayed asking you to specify it manually.

        Example:
            result = self.eFunc(address=0x401000, args=[1, 2, 3])
print(f"Function result: {result}")
        ru
        Выполняет эмуляцию функции, начиная с указанного адреса.

        Описание:
            - Если адрес функции (`address`) не указан, используется текущий адрес курсора в IDA Pro.
            - Определяет адрес возврата (`retAddr`) из ссылок на функцию, если он не задан.
            - Выполняет эмуляцию функции с использованием Unicorn Engine.
            - Возвращает значение результата из регистра результата (`REG_RES`).

        Аргументы:
            - address (int, optional): Адрес начала функции. Если не указан, используется текущий адрес в IDA.
            - retAddr (int, optional): Адрес возврата. Если не указан, определяется автоматически.
            - args (list, optional): Список аргументов для функции (по умолчанию пустой список).
            - force (bool, optional): Если `True`, принудительно использует указанный адрес, игнорируя начало функции (по умолчанию `False`).

        Возвращает:
            - int: Значение результата из регистра результата (`REG_RES`).

        Исключения:
            - Если адрес возврата не может быть определен, выводится сообщение с просьбой указать его вручную.

        Пример:
            result = self.eFunc(address=0x401000, args=[1, 2, 3])
            print(f"Результат функции: {result}")
        """
        if address is None:
            address = idc.here()
        func = idaapi.get_func(address)
        if retAddr is None:
            refs = [ref.frm for ref in idautils.XrefsTo(func.start_ea, 0)]
            if len(refs) != 0:
                retAddr = refs[0] + IDAAPI_ItemSize(refs[0])
            else:
                print("Please offer the return address.")
                return
        if not force:
            address = func.start_ea
        address = address | 1 if self._is_thumb_ea(address) else address
        self._emulate(address, retAddr, args)
        res = self.curUC.reg_read(self.REG_RES)
        return res

    def eBlock(self, codeStart=None, codeEnd=None, silentMode=False):
        """
        en
        Performs code block emulation between the specified addresses.

        Description:
            - - Either initial ("code start") or final ("Code completion") without instructions, dedicated functions in IDA Pro are used.
            - Uses a modulating block of code using the Unicorn Engine.
            - If "silent mode" is set to "False", it means that registration is completed.

        Arguments:
            - - start of the code (int, optional): The starting address of the code block. If not, use the dedicated initial stage in the IDA.
             end of the code (int, optional): The end address of the code block. If not, use the dedicated destination address in the form.
             silent mode (boot mode, optional): either "True" or outputs the corresponding registry (or `False").

        Returns:
            "No," I said.

        Example:
            self.block(code start=0x401000, code end=0x401100)
        ru
        Выполняет эмуляцию блока кода между указанными адресами.

        Описание:
            - Если начальный (`codeStart`) или конечный (`codeEnd`) адрес не указаны, используются выделенные области в IDA Pro.
            - Выполняет эмуляцию блока кода с использованием Unicorn Engine.
            - Если `silentMode` равен `False`, выводит значения регистров после завершения эмуляции.

        Аргументы:
            - codeStart (int, optional): Начальный адрес блока кода. Если не указан, используется выделенный начальный адрес в IDA.
            - codeEnd (int, optional): Конечный адрес блока кода. Если не указан, используется выделенный конечный адрес в IDA.
            - silentMode (bool, optional): Если `True`, подавляет вывод значений регистров (по умолчанию `False`).

        Возвращает:
            - None

        Пример:
            self.eBlock(codeStart=0x401000, codeEnd=0x401100)
        """
        if codeStart is None:
            codeStart = IDAAPI_SelStart()
        if codeEnd is None:
            codeEnd = IDAAPI_SelEnD()
        codeStart = codeStart | 1 if self._is_thumb_ea(
            codeStart) else codeStart
        self._emulate(
            startAddr=codeStart,
            stopAddr=codeEnd,
            args=[],
            TimeOut=0,
            Count=0,
            DisablePatchRA=True)
        if not silentMode:
            self._show_registers(self.curUC)

    def eUntilAddress(self, startAddr, stopAddr, args=[], TimeOut=0, Count=0):
        """
        en
        Performs emulation to the specified address.

        Description:
            - Starts emulation with `startAddr` and stops at `stopAddr'.
            - Uses the Unicorn Engine to perform emulation.
            - Outputs the register values after the emulation is completed.

        Arguments:
            - - start Addr (int): The initial address of the emulation.
            - - stopkadr (int): The end address of the emulation.
            - args (list, optional): A list of arguments for emulation (by default, an empty list).
            - TimeOut (int, optional): Timeout for emulation (default is 0).
            - Count (int, optional): The maximum number of instructions to execute (0 by default).

        Returns:
            - None

        Example:
            self.eUntilAddress(startAddr=0x401000, stopAddr=0x401100)
        ru
        Выполняет эмуляцию до указанного адреса.

        Описание:
            - Начинает эмуляцию с `startAddr` и останавливается на `stopAddr`.
            - Использует Unicorn Engine для выполнения эмуляции.
            - После завершения эмуляции выводит значения регистров.

        Аргументы:
            - startAddr (int): Начальный адрес эмуляции.
            - stopAddr (int): Конечный адрес эмуляции.
            - args (list, optional): Список аргументов для эмуляции (по умолчанию пустой список).
            - TimeOut (int, optional): Тайм-аут для эмуляции (по умолчанию 0).
            - Count (int, optional): Максимальное количество инструкций для выполнения (по умолчанию 0).

        Возвращает:
            - None

        Пример:
            self.eUntilAddress(startAddr=0x401000, stopAddr=0x401100)
        """
        startAddr = startAddr | 1 if self._is_thumb_ea(
            startAddr) else startAddr
        self._emulate(
            startAddr=startAddr,
            stopAddr=stopAddr,
            args=args,
            TimeOut=TimeOut,
            Count=Count,
            DisablePatchRA=True)
        self._show_registers(self.curUC)

    def altQt5(self):
        """
        en
        Installs alternative functions for Qt5.

        Description:
            - Uses the `alt` method to replace standard Qt5 functions with custom ones.
            - Replaces the functions `QList.append` and `QDate' with emulated versions.

        Returns:
            - None

        Example:
            self.altQt5()
        ru
        Устанавливает альтернативные функции для Qt5.

        Описание:
            - Использует метод `alt` для замены стандартных функций Qt5 на пользовательские.
            - Заменяет функции `QList.append` и `QDate` на эмулированные версии.

        Возвращает:
            - None

        Пример:
            self.altQt5()
        """
        self.alt(
            get_name_ea(
                0,
                'j__ZN5QListIiE6appendERKi'),
            QList.my_qlist_append,
            2,
            False)
        self.alt(
            get_name_ea(
                0,
                'j__ZN5QListIhE6appendERKh'),
            QList.my_qlist_append2,
            2,
            False)
        self.alt(
            get_name_ea(
                0,
                '_ZN5QDateC1Eiii'),
            EmulatedQtHelpers.my_qtime_qtime,
            4,
            False)
