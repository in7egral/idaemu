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
The module ida_emu_module.py

Description:
This module provides functionality for integrating Unicorn Engine emulation with IDA Pro.
    It includes loading auxiliary modules such as `idaemu`, `idaemu_qt`, `elf_helper`,
    it also defines the addresses of standard functions and functions of Qt for their further emulation.

Goal:
- Simplify code emulation in IDA Pro.
    - Support for working with standard library functions (e.g. malloc, memcpy) and Qt functions.

Imported modules:
- Unicorn Engine (for emulation).
    - IDA Pro API (idaapi, idc).
    - Auxiliary modules: `idaemu`, `idaemu_qt', `elf_helper`, `q_math`, `stdlib_funcs'.

Classes:
- Helper: A class for working with ELF headers (imported from `elf_helper`).

Variables:
    - malloc_ea: The address of the `malloc` function.
    - memcpy_ea: The address of the `memcpy' function.
    - memset_ea: The address of the `memset' function.
    - system_ea: Address of the `system` function.
    - strchr_ea: The address of the `strchr` function.
    - strlen_ea: The address of the `strlen` function.
    - daemon_ea: The address of the `daemon' function.
    - sprintf_ea: Address of the `sprintf' function.
    - aeabi_idivmod: Address of the function `__aeabi_idivmod'.
    - pow_f: Address of the `pow` function.
    - QString_append: The address of the function `_ZN7QString6appendE5QChar'.
    - QString_remove_char: Address of the function `_ZN7QString6removeE5QCharN2Qt15CaseSensitivityE'.
    - QString_to_Upper: Address of the function `_zn7qstring14toupper_helperks_`.
    - Bit_Array: The address of the function `_ZN9QBitArrayC1Eib'.
    - Byte_Array_Realloc_Data: Address of the function `_ZN10QByteArray11reallocDataEj6QFlagsIN10QArrayData16AllocationOptionEE`.

Exceptions:
    - If the function address is not found, an error message is displayed.
ru
Модуль ida_emu_module.py

Описание:
    Этот модуль предоставляет функциональность для интеграции эмуляции Unicorn Engine с IDA Pro.
    Он включает в себя загрузку вспомогательных модулей, таких как `idaemu`, `idaemu_qt`, `elf_helper`,
    а также определяет адреса стандартных функций и функций Qt для их дальнейшей эмуляции.

Цель:
    - Упрощение эмуляции кода в IDA Pro.
    - Поддержка работы с функциями стандартной библиотеки (например, `malloc`, `memcpy`) и функциями Qt.

Импортируемые модули:
    - Unicorn Engine (для эмуляции).
    - IDA Pro API (idaapi, idc).
    - Вспомогательные модули: `idaemu`, `idaemu_qt`, `elf_helper`, `q_math`, `stdlib_funcs`.

Классы:
    - Helper: Класс для работы с ELF-заголовками (импортируется из `elf_helper`).

Переменные:
    - malloc_ea: Адрес функции `malloc`.
    - memcpy_ea: Адрес функции `memcpy`.
    - memset_ea: Адрес функции `memset`.
    - system_ea: Адрес функции `system`.
    - strchr_ea: Адрес функции `strchr`.
    - strlen_ea: Адрес функции `strlen`.
    - daemon_ea: Адрес функции `daemon`.
    - sprintf_ea: Адрес функции `sprintf`.
    - aeabi_idivmod: Адрес функции `__aeabi_idivmod`.
    - pow_f: Адрес функции `pow`.
    - QString_append: Адрес функции `_ZN7QString6appendE5QChar`.
    - QString_remove_char: Адрес функции `_ZN7QString6removeE5QCharN2Qt15CaseSensitivityE`.
    - QString_to_Upper: Адрес функции `_ZN7QString14toUpper_helperERKS_`.
    - Bit_Array: Адрес функции `_ZN9QBitArrayC1Eib`.
    - Byte_Array_Realloc_Data: Адрес функции `_ZN10QByteArray11reallocDataEj6QFlagsIN10QArrayData16AllocationOptionEE`.

Исключения:
    - Если адрес функции не найден, выводится сообщение об ошибке.
"""
from elf_helper import Helper
from idaemu_qt import *
from idaemu import *
import sys
import importlib
from unicorn import *
from idaapi import *
from registers import *
import idaemu
import idaemu_qt
from q_math import *
from stdlib_funcs import *

# importlib.reload(idaemu)
# importlib.reload(idaemu_qt)


try:
    malloc_ea = idaapi.get_name_ea(0, 'malloc')
except Exception as e:
    malloc_ea = None
    print(f"Error getting address for 'malloc': {e}")

try:
    memcpy_ea = idaapi.get_name_ea(0, 'memcpy')
except Exception as e:
    memcpy_ea = None
    print(f"Error getting address for 'memcpy': {e}")

try:
    memset_ea = idaapi.get_name_ea(0, 'memset')
except Exception as e:
    memset_ea = None
    print(f"Error getting address for 'memset': {e}")

try:
    system_ea = idaapi.get_name_ea(0, 'system')
except Exception as e:
    system_ea = None
    print(f"Error getting address for 'system': {e}")

try:
    strchr_ea = idaapi.get_name_ea(0, 'strchr')
except Exception as e:
    strchr_ea = None
    print(f"Error getting address for 'strchr': {e}")

try:
    strlen_ea = idaapi.get_name_ea(0, 'strlen')
except Exception as e:
    strlen_ea = None
    print(f"Error getting address for 'strlen': {e}")

try:
    daemon_ea = idaapi.get_name_ea(0, 'daemon')
except Exception as e:
    daemon_ea = None
    print(f"Error getting address for 'daemon': {e}")

try:
    sprintf_ea = idaapi.get_name_ea(0, 'sprintf')
except Exception as e:
    sprintf_ea = None
    print(f"Error getting address for 'sprintf': {e}")

try:
    aeabi_idivmod = get_name_ea(0, '__aeabi_idivmod')
except Exception as e:
    aeabi_idivmod = None
    print(f"Error getting address for '__aeabi_idivmod': {e}")

try:
    pow_f = get_name_ea(0, 'pow')
except Exception as e:
    pow_f = None
    print(f"Error getting address for 'pow': {e}")

try:
    QString_append = get_name_ea(0, '_ZN7QString6appendE5QChar')
except Exception as e:
    QString_append = None
    print(f"Error getting address for '_ZN7QString6appendE5QChar': {e}")

try:
    QString_remove_char = get_name_ea(
        0, '_ZN7QString6removeE5QCharN2Qt15CaseSensitivityE')
except Exception as e:
    QString_remove_char = None
    print(
        f"Error getting address for '_ZN7QString6removeE5QCharN2Qt15CaseSensitivityE': {e}")

try:
    QString_to_Upper = get_name_ea(0, '_ZN7QString14toUpper_helperERKS_')
except Exception as e:
    QString_to_Upper = None
    print(f"Error getting address for '_ZN7QString14toUpper_helperERKS_': {e}")

try:
    Bit_Array = get_name_ea(0, '_ZN9QBitArrayC1Eib')
except Exception as e:
    Bit_Array = None
    print(f"Error getting address for '_ZN9QBitArrayC1Eib': {e}")

try:
    Byte_Array_Realloc_Data = get_name_ea(
        0, '_ZN10QByteArray11reallocDataEj6QFlagsIN10QArrayData16AllocationOptionEE')
except Exception as e:
    Byte_Array_Realloc_Data = None
    print(
        f"Error getting address for '_ZN10QByteArray11reallocDataEj6QFlagsIN10QArrayData16AllocationOptionEE': {e}")
