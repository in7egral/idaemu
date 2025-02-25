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
The module elf_header.py

This module provides functionality for analyzing ELF headers and processing
dynamic sections of ELF files in IDA Pro using IDAPython. It includes
methods for working with symbol tables, symbol versions, import tables, and
other ELF structures.

Classes:
- Helper: The main class for analyzing ELF headers and processing dynamic sections.

Constants:
- DT_VERNEEDED: The type of dynamic tag for the version dependency table.
    - DT_VERNEEDNUM: A type of dynamic tag for the number of entries in the version dependency table.
     DT_VERSUM: The type of dynamic tag for the symbol version table.
    - DT_JMPREL: The type of dynamic tag for the PLT table.
    - DT_PLTRELZZ: The type of dynamic tag for the size of the PLT table.
    - - DT_RELAENT: The type of dynamic tag for the RELATED record size.
    - DT_STRTAB: The type of dynamic tag for the row table.
    - - DT_STR SZ: The type of dynamic tag for the row table size.
ru
Модуль elf_header.py

Этот модуль предоставляет функциональность для анализа ELF-заголовков и обработки
динамических секций ELF-файлов в IDA Pro с использованием IDAPython. Он включает
методы для работы с таблицами символов, версиями символов, таблицами импорта и
другими структурами ELF.

Классы:
    - Helper: Основной класс для анализа ELF-заголовков и обработки динамических секций.

Константы:
    - DT_VERNEEDED: Тип динамического тега для таблицы зависимостей версий.
    - DT_VERNEEDNUM: Тип динамического тега для количества записей в таблице зависимостей версий.
    - DT_VERSYM: Тип динамического тега для таблицы версий символов.
    - DT_JMPREL: Тип динамического тега для таблицы PLT.
    - DT_PLTRELSZ: Тип динамического тега для размера таблицы PLT.
    - DT_RELAENT: Тип динамического тега для размера записи RELA.
    - DT_STRTAB: Тип динамического тега для таблицы строк.
    - DT_STRSZ: Тип динамического тега для размера таблицы строк.
"""
import idaapi
import ida_bytes
import ida_name
import idc

DT_VERNEEDED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF
DT_VERSYM = 0x6FFFFFF0
DT_JMPREL = 0x17
DT_PLTRELSZ = 2
DT_RELAENT = 9
DT_STRTAB = 5
DT_STRSZ = 0xA


class Helper(object):

    """
    en
    The Helper class provides methods for analyzing ELF headers and processing
    dynamic sections of ELF files in IDA Pro.

    Attributes:
        - _is64 (bool): A flag indicating whether a 64-bit architecture is used.
        - _is_debug (int): A flag to enable debugging output.
        - imports_list (dict): Dictionary of imported functions.
        - _symbol_nums (dict): Dictionary of character numbers.
        - _symbol_ver_numbers (dict): Dictionary of character versions.
        - _module_ver_numbers (dict): Dictionary of module versions.

    Methods:
        - __init__(is64): Constructor of the class. Initializes the attributes and starts processing the IAT and dynamic section.
            Arguments:
                - is64 (bool): Indicates whether a 64-bit architecture is used.

        - resolve(ea): Resolves the name or library for the specified address.
            Arguments:
                - ea (int): The address for the resolution.
            Returns:
                - str: The name or library associated with the address.

        - _resolve_name(offset): Resolves a row by offset in the row table.
            Arguments:
                - offset (int): The offset in the row table.
            Returns:
                - str: Allowed string.

        - _process_verneeded(): Processes the ELF version dependency table.

        - _process_versym_table_elem(sym_index): Processes an element of the symbol version table.
            Arguments:
                - sym_index (int): The index of the symbol in the symbol table.

        - _process_plt(): Processes the PLT (Procedure Linkage Table).

        - _process_dyn(): Processes the dynamic ELF section.

        - _callback(ea, name, ordinary): Processes the imported function and saves it to the import list.
            Arguments:
                - ea (int): The address of the imported function.
                - name (str): The name of the imported function.
                - ordinal (int): The ordinal of the imported function.
            Returns:
                - bool: Always returns `True` to continue listing imports.

        - _process_iat(): Processes the import table (IAT) and stores information about imported functions.

        - _get_lib_or_desc(ea): Gets the library name or description for the specified address.
            Arguments:
                - ea (int): The address for which you want to get the library name or description.
            Returns:
                - str or dict: The name of the library, if the address is associated with a symbol table, or a dictionary with import information.
    ru
    Класс Helper предоставляет методы для анализа ELF-заголовков и обработки
    динамических секций ELF-файлов в IDA Pro.

    Атрибуты:
        - _is64 (bool): Флаг, указывающий, используется ли 64-битная архитектура.
        - _is_debug (int): Флаг для включения отладочного вывода.
        - imports_list (dict): Словарь импортируемых функций.
        - _symbol_nums (dict): Словарь номеров символов.
        - _symbol_ver_numbers (dict): Словарь версий символов.
        - _module_ver_numbers (dict): Словарь версий модулей.

    Методы:
        - __init__(is64): Конструктор класса. Инициализирует атрибуты и запускает обработку IAT и динамической секции.
            Аргументы:
                - is64 (bool): Указывает, используется ли 64-битная архитектура.

        - resolve(ea): Разрешает имя или библиотеку для указанного адреса.
            Аргументы:
                - ea (int): Адрес для разрешения.
            Возвращает:
                - str: Имя или библиотека, связанная с адресом.

        - _resolve_name(offset): Разрешает строку по смещению в таблице строк.
            Аргументы:
                - offset (int): Смещение в таблице строк.
            Возвращает:
                - str: Разрешенная строка.

        - _process_verneeded(): Обрабатывает таблицу зависимостей версий ELF.

        - _process_versym_table_elem(sym_index): Обрабатывает элемент таблицы версий символов.
            Аргументы:
                - sym_index (int): Индекс символа в таблице символов.

        - _process_plt(): Обрабатывает таблицу PLT (Procedure Linkage Table).

        - _process_dyn(): Обрабатывает динамическую секцию ELF.

        - _callback(ea, name, ordinal): Обрабатывает импортируемую функцию и сохраняет её в список импортов.
            Аргументы:
                - ea (int): Адрес импортируемой функции.
                - name (str): Имя импортируемой функции.
                - ordinal (int): Ординал импортируемой функции.
            Возвращает:
                - bool: Всегда возвращает `True`, чтобы продолжить перечисление импортов.

        - _process_iat(): Обрабатывает таблицу импорта (IAT) и сохраняет информацию об импортируемых функциях.

        - _get_lib_or_desc(ea): Получает имя библиотеки или описание для указанного адреса.
            Аргументы:
                - ea (int): Адрес, для которого нужно получить имя библиотеки или описание.
            Возвращает:
                - str или dict: Имя библиотеки, если адрес связан с таблицей символов, или словарь с информацией об импорте.
    """

    def __init__(self, is64):

        self._is64 = is64
        self._is_debug = 0
        self.imports_list = {}
        self._symbol_nums = {}
        self._symbol_ver_numbers = {}
        self._module_ver_numbers = {}
        self._process_iat()
        self._process_dyn()

    def _resolve_name(self, offset):
        """
        en
        Resolves a row by offset in the row table.

        Arguments:
            - offset (int): The offset in the row table.

        Returns:
            - str: Allowed string.
        ru
        Разрешает строку по смещению в таблице строк.

        Аргументы:
            - offset (int): Смещение в таблице строк.

        Возвращает:
            - str: Разрешенная строка.
        """
        if offset > self._strsz:
            raise
        ea = self._strtab + offset
        x = ida_bytes.get_strlit_contents(ea, -1, STRTYPE_C)
        if x is not None:
            s = x.decode('utf8')
            return s
        return ''

    def _process_verneeded(self):
        ea = self._verneeded
        k = 0
        while k < self._verneeded_num:
            vn_file = ida_bytes.get_dword(ea + 4)
            vn_cnt = ida_bytes.get_word(ea + 2)
            lib_name = self._resolve_name(vn_file)
            m = 0
            ea += 0x10
            while m < vn_cnt:
                vna_other = ida_bytes.get_word(ea + 6)
                self._module_ver_numbers[vna_other] = lib_name
                ea += 0x10
                m += 1
            k += 1

    def _process_versym_table_elem(self, sym_index):

        ea = self._versym + sym_index * 2
        ver_number = ida_bytes.get_word(ea)
        self._symbol_ver_numbers[sym_index] = ver_number

    def _process_plt(self):
        ea = self._jmprel
        ea_end = ea + self._pltsize
        while ea < ea_end:
            ea_api = ida_bytes.get_qword(ea) & 0xFFFFFFFF
            sym_index = ida_bytes.get_qword(ea + self._is64 * 4 + 4)
            ea_plt = ida_bytes.get_qword(ea_api)
            if self._is64:
                sym_index >>= 32
            else:
                sym_index >>= 8
            self._process_versym_table_elem(sym_index)
            ver = self._symbol_ver_numbers[sym_index]
            if self._is_debug != 0:
                print(f'func: {ea_plt:x}, {sym_index} {ver}')
            self._symbol_nums[ea_plt] = ver
            ea += self._rel_ent
        pass

    def _process_dyn(self):
        self._verneeded = 0
        self._verneeded_num = 0
        self._versym = 0
        self._jmprel = 0
        self._pltsize = 0
        self._rel_ent = 0
        self._strtab = 0
        self._strsz = 0
        ea_dyn = ida_name.get_name_ea(0, '_DYNAMIC')
        if ea_dyn == idc.BADADDR:
            print("Error: _DYNAMIC not found")
            return
        if self._is_debug != 0:
            print(f'_DYNAMIC: {ea_dyn:x}')
        while 1:
            value = ida_bytes.get_qword(ea_dyn) & 0xFFFFFFFF
            ea_dyn += self._is64 * 4 + 4
            if value == 0:
                break
            elif value == DT_VERNEEDED:
                self._verneeded = ida_bytes.get_qword(ea_dyn) & 0xFFFFFFFF
            elif value == DT_VERNEEDNUM:
                self._verneeded_num = ida_bytes.get_qword(ea_dyn) & 0xFFFFFFFF
            elif value == DT_VERSYM:
                self._versym = ida_bytes.get_qword(ea_dyn) & 0xFFFFFFFF
            elif value == DT_JMPREL:
                self._jmprel = ida_bytes.get_qword(ea_dyn) & 0xFFFFFFFF
            elif value == DT_PLTRELSZ:
                self._pltsize = ida_bytes.get_qword(ea_dyn) & 0xFFFFFFFF
            elif value == DT_RELAENT:
                self._rel_ent = ida_bytes.get_qword(ea_dyn) & 0xFFFFFFFF
            elif value == DT_STRTAB:
                self._strtab = ida_bytes.get_qword(ea_dyn) & 0xFFFFFFFF
            elif value == DT_STRSZ:
                self._strsz = ida_bytes.get_qword(ea_dyn) & 0xFFFFFFFF
            ea_dyn += self._is64 * 4 + 4
        if self._is_debug != 0:
            print(f'{self._verneeded:x}')
            print(f'{self._verneeded_num:x}')
            print(f'{self._versym:x}')
            print(f'{self._jmprel:x}')
            print(f'{self._pltsize:x}')
            print(f'{self._rel_ent:x}')
            print(f'{self._strtab:x}')
            print(f'{self._strsz:x}')
        self._process_plt()
        self._process_verneeded()

    def _callback(self, ea, name, ordinal):
        self.imports_list[ea] = {'name': name, 'ord': ordinal}
        return True

    def _process_iat(self):

        implist = idaapi.get_import_module_qty()
        for i in range(0, implist):
            idaapi.enum_import_names(i, self._callback)

    def _get_lib_or_desc(self, ea):

        if ea in self._symbol_nums:
            ver = self._symbol_nums[ea]
            if ver in self._module_ver_numbers:
                lib = self._module_ver_numbers[ver]
                return lib
        return self.imports_list[ea]

    def resolve(self, ea):
        """
        en
        Resolves the name or library for the specified address.

        Arguments:
            - ea (int): The address for the resolution.

        Returns:
            - str: The name or library associated with the address.
        ru
        Разрешает имя или библиотеку для указанного адреса.

        Аргументы:
            - ea (int): Адрес для разрешения.

        Возвращает:
            - str: Имя или библиотека, связанная с адресом.
        """
        if ea in self.imports_list:
            return self._get_lib_or_desc(ea)
        else:
            ea = ida_bytes.get_qword(ea)
            if ea in self.imports_list:
                return self._get_lib_or_desc(ea)
        return ''
