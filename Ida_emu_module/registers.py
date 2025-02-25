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
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *
COMPILE_GCC = 1
COMPILE_MSVC = 2


class Registers(object):
    """
    en
    The Registers class provides functionality for working with processor registers
    of various architectures (x86, ARM, ARM64) in the Unicorn Engine emulator. It allows you to
    initialize the architecture, configure registers, and output their values.

    Class Description:
Purpose:
            - Work with processor registers in an emulated environment.
        Features:
            - Supports x86, ARM, ARM64 architectures.
            - Register settings depending on architecture, mode, and compiler.
            - Output of register values for debugging.

    Attributes:
        - arch: Processor architecture (for example, UC_ARCH_X86, UC_ARCH_ARM).
        - mode: Processor operating mode (for example, UC_MODE_32, UC_MODE_64).
        - compiler: Compiler type (COMPILE_GCC or COMPILE_MSVC).
        - step: The step size for reading/writing data (in bytes).
        - pack_fmt: Data packing format (for example, '<I' for 32-bit data).
        - REG_PC: Command pointer register (Program Counter).
        - REG_SP: Stack Pointer register.
        - REG_RA: Return Address register.
        - REG_RES: A register for storing the result.
        - REG_ARGS: A list of registers for passing arguments.

    Methods of the class:

    1. __init__(self, arch, mode, compiler=COMPILE_GCC)
            Constructor of the Registers class.

        Description:
            - Initializes an object with the specified architecture, mode, and compiler.
            - Verifies that the architecture is supported.

        Arguments:
            - arch: Processor architecture (UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64).
            - mode: Processor operating mode (UC_MODE_16, UC_MODE_32, UC_MODE_64).
            - compiler: Compiler type (default is COMPILE_GCC).

    2. _initialize_architecture(self)
        Initializes the processor architecture.

        Description:
            - Depending on the architecture, it calls the appropriate configuration method:
        `_setup_x86`, `_setup_arm` or `_setup_arm64'.

        Exceptions:
            - ValueError: If the architecture is not supported.

    3. _setup_x86(self)
        Adjusts registers for the x86 architecture.

        Description:
            - Sets values for steps, packaging formats, and registers
              depending on the mode (16, 32 or 64 bits).
            - For 64-bit mode, it takes into account the compiler type (GCC or MSVC).

    4. _setup_arm(self)
        Adjusts registers for the ARM architecture.

        Description:
            - Sets values for steps, packaging formats, and registers
              depending on the mode (ARM or THUMB).

    5. _setup_arm64(self)
        Adjusts the registers for the ARM64 architecture.

        Description:
            - Sets values for steps, packaging formats, and registers.

    6. _get_bit(self, value, offset)
        Returns the value of a specific bit in a number.

        Description:
            - Used to analyze processor flags (for example, EFLAGS).

        Arguments:
            - value: The number to extract the bit from.
            - offset: Bit offset.

        Returns:
            - int: Bit value (0 or 1).

    7. _show_registers(self, uc)
        Outputs the register values for the current architecture.

        Description:
            - Reads register values depending on the architecture (x86, ARM, ARM64)
              from the Unicorn Engine emulator and outputs them to the console.
            - For x86, it also outputs the values of flags (EFLAGS).

        Arguments:
            - uc: The Unicorn Engine emulator object.

        Exceptions:
            - UcError: If an error occurred while reading registers.
    ru

    Класс Registers предоставляет функционал для работы с регистрами процессоров
    различных архитектур (x86, ARM, ARM64) в эмуляторе Unicorn Engine. Он позволяет
    инициализировать архитектуру, настраивать регистры, а также выводить их значения.

    Описание класса:
        Назначение:
            - Работа с регистрами процессоров в эмулированной среде.
        Особенности:
            - Поддержка архитектур x86, ARM, ARM64.
            - Настройка регистров в зависимости от архитектуры, режима и компилятора.
            - Вывод значений регистров для отладки.

    Атрибуты:
        - arch: Архитектура процессора (например, UC_ARCH_X86, UC_ARCH_ARM).
        - mode: Режим работы процессора (например, UC_MODE_32, UC_MODE_64).
        - compiler: Тип компилятора (COMPILE_GCC или COMPILE_MSVC).
        - step: Размер шага для чтения/записи данных (в байтах).
        - pack_fmt: Формат упаковки данных (например, '<I' для 32-битных данных).
        - REG_PC: Регистр указателя команд (Program Counter).
        - REG_SP: Регистр указателя стека (Stack Pointer).
        - REG_RA: Регистр возврата (Return Address).
        - REG_RES: Регистр для хранения результата.
        - REG_ARGS: Список регистров для передачи аргументов.

    Методы класса:

    1. __init__(self, arch, mode, compiler=COMPILE_GCC)
        Конструктор класса Registers.

        Описание:
            - Инициализирует объект с заданной архитектурой, режимом и компилятором.
            - Проверяет, что архитектура поддерживается.

        Аргументы:
            - arch: Архитектура процессора (UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64).
            - mode: Режим работы процессора (UC_MODE_16, UC_MODE_32, UC_MODE_64).
            - compiler: Тип компилятора (по умолчанию COMPILE_GCC).

    2. _initialize_architecture(self)
        Инициализирует архитектуру процессора.

        Описание:
            - В зависимости от архитектуры вызывает соответствующий метод настройки:
              `_setup_x86`, `_setup_arm` или `_setup_arm64`.

        Исключения:
            - ValueError: Если архитектура не поддерживается.

    3. _setup_x86(self)
        Настраивает регистры для архитектуры x86.

        Описание:
            - Устанавливает значения для шагов, форматов упаковки и регистров
              в зависимости от режима (16, 32 или 64 бита).
            - Для 64-битного режима учитывает тип компилятора (GCC или MSVC).

    4. _setup_arm(self)
        Настраивает регистры для архитектуры ARM.

        Описание:
            - Устанавливает значения для шагов, форматов упаковки и регистров
              в зависимости от режима (ARM или THUMB).

    5. _setup_arm64(self)
        Настраивает регистры для архитектуры ARM64.

        Описание:
            - Устанавливает значения для шагов, форматов упаковки и регистров.

    6. _get_bit(self, value, offset)
        Возвращает значение конкретного бита в числе.

        Описание:
            - Используется для анализа флагов процессора (например, EFLAGS).

        Аргументы:
            - value: Число, из которого нужно извлечь бит.
            - offset: Смещение бита.

        Возвращает:
            - int: Значение бита (0 или 1).

    7. _show_registers(self, uc)
        Выводит значения регистров для текущей архитектуры.

        Описание:
            - В зависимости от архитектуры (x86, ARM, ARM64) читает значения регистров
              из эмулятора Unicorn Engine и выводит их в консоль.
            - Для x86 также выводит значения флагов (EFLAGS).

        Аргументы:
            - uc: Объект эмулятора Unicorn Engine.

        Исключения:
            - UcError: Если произошла ошибка при чтении регистров.
    """

    def __init__(self, arch, mode, compiler=COMPILE_GCC):
        assert (arch in [UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64])
        self.arch = arch
        self.mode = mode
        self.compiler = compiler
        self.step = None
        self.pack_fmt = None
        self.REG_PC = None
        self.REG_SP = None
        self.REG_RA = None
        self.REG_RES = None
        self.REG_ARGS = None

    # какие архитектуры в единороге, потом вызывать этот метод для
    # инициализации arch
    def _initialize_architecture(self):
        if self.arch == UC_ARCH_X86:
            self._setup_x86()
        elif self.arch == UC_ARCH_ARM:
            self._setup_arm()
        elif self.arch == UC_ARCH_ARM64:
            self._setup_arm64()
        else:
            print(self.arch)
            raise ValueError("architecture not defined")

    def _setup_x86(self):
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
                self.REG_ARGS = [
                    UC_X86_REG_RDI,
                    UC_X86_REG_RSI,
                    UC_X86_REG_RDX,
                    UC_X86_REG_RCX,
                    UC_X86_REG_R8,
                    UC_X86_REG_R9]
            elif self.compiler == COMPILE_MSVC:
                self.REG_ARGS = [
                    UC_X86_REG_RCX,
                    UC_X86_REG_RDX,
                    UC_X86_REG_R8,
                    UC_X86_REG_R9]

    def _get_bit(self, value, offset):
        mask = 1 << offset
        return 1 if (value & mask) > 0 else 0

    def _setup_arm(self):
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
        self.REG_ARGS = [
            UC_ARM_REG_R0,
            UC_ARM_REG_R1,
            UC_ARM_REG_R2,
            UC_ARM_REG_R3]

    def _setup_arm64(self):
        self.step = 8
        self.pack_fmt = '<Q'
        self.REG_PC = UC_ARM64_REG_PC
        self.REG_SP = UC_ARM64_REG_SP
        self.REG_RA = UC_ARM64_REG_LR
        self.REG_RES = UC_ARM64_REG_X0
        self.REG_ARGS = [
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X3,
            UC_ARM64_REG_X4,
            UC_ARM64_REG_X5,
            UC_ARM64_REG_X6,
            UC_ARM64_REG_X7]

    """"
    def _show_registers(self, uc):

        print(">>> regs:")
        self._regs.show(uc)
    """

    def _show_registers(self, uc):
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
                SP = uc.reg_read(UC_ARM_REG_SP)  # R13
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
                SP = uc.reg_read(UC_ARM64_REG_SP)  # X30
                PC = uc.reg_read(UC_ARM64_REG_PC)
                LR = uc.reg_read(UC_ARM64_REG_LR)
                print("    X0 = 0x%x, X1 = 0x%x, X2 = 0x%x" % (X0, X1, X2))
                print("    X3 = 0x%x, X4 = 0x%x, X5 = 0x%x" % (X3, X4, X5))
                print("    X6 = 0x%x, X7 = 0x%x, X8 = 0x%x" % (X6, X7, X8))
                print("    X9 = 0x%x, X10 = 0x%x, X11 = 0x%x" % (X9, X10, X11))
                print(
                    "    X12 = 0x%x, X13 = 0x%x, X14 = 0x%x" %
                    (X12, X13, X14))
                print(
                    "    X15 = 0x%x, X16 = 0x%x, X17 = 0x%x" %
                    (X15, X16, X17))
                print(
                    "    X18 = 0x%x, X19 = 0x%x, X20 = 0x%x" %
                    (X18, X19, X20))
                print(
                    "    X21 = 0x%x, X22 = 0x%x, X23 = 0x%x" %
                    (X21, X22, X23))
                print(
                    "    X24 = 0x%x, X25 = 0x%x, X26 = 0x%x" %
                    (X24, X25, X26))
                print(
                    "    X27 = 0x%x, X28 = 0x%x, X29 = 0x%x" %
                    (X27, X28, X29))
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

                    print(
                        "    AX = 0x%x BX = 0x%x CX = 0x%x DX = 0x%x" %
                        (ax, bx, cx, dx))
                    print(
                        "    DI = 0x%x SI = 0x%x BP = 0x%x SP = 0x%x" %
                        (di, si, bp, sp))
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

                    print(
                        "    EAX = 0x%x EBX = 0x%x ECX = 0x%x EDX = 0x%x" %
                        (eax, ebx, ecx, edx))
                    print(
                        "    EDI = 0x%x ESI = 0x%x EBP = 0x%x ESP = 0x%x" %
                        (edi, esi, ebp, esp))
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

                    print(
                        "    RAX = 0x%x RBX = 0x%x RCX = 0x%x RDX = 0x%x" %
                        (rax, rbx, rcx, rdx))
                    print(
                        "    RDI = 0x%x RSI = 0x%x RBP = 0x%x RSP = 0x%x" %
                        (rdi, rsi, rbp, rsp))
                    print(
                        "    R8 = 0x%x R9 = 0x%x R10 = 0x%x R11 = 0x%x R12 = 0x%x "
                        "R13 = 0x%x R14 = 0x%x R15 = 0x%x" %
                        (r8, r9, r10, r11, r12, r13, r14, r15))
                    print("    RIP = 0x%x" % rip)
                if eflags:
                    print("    EFLAGS:")
                    print("    CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d "
                          "NT=%d RF=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d"
                          % (self._get_bit(eflags, 0),
                             self._get_bit(eflags, 2),
                             self._get_bit(eflags, 4),
                             self._get_bit(eflags, 6),
                             self._get_bit(eflags, 7),
                             self._get_bit(eflags, 8),
                             self._get_bit(eflags, 9),
                             self._get_bit(eflags, 10),
                             self._get_bit(eflags, 11),
                             self._get_bit(eflags, 12) + self._get_bit(eflags, 13) * 2,
                             self._get_bit(eflags, 14),
                             self._get_bit(eflags, 16),
                             self._get_bit(eflags, 17),
                             self._get_bit(eflags, 18),
                             self._get_bit(eflags, 19),
                             self._get_bit(eflags, 20),
                             self._get_bit(eflags, 21)))
        except UcError as e:
            print("#ERROR: %s" % e)
