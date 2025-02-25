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
The module idaemu_qt.py

Description:
This module provides auxiliary classes and methods for working with Qt structures
(for example, QString, Qbytearray, QList) in the Unicorn Engine emulation in IDA Pro.
    It includes functions for serializing data, working with memory, and emulating the behavior of Qt.

The authors:
    - - helmut
    - - integral

Version:
    - v0.1 (2024)

Supported Qt versions:
- Qt5

Classes:
- - QString: Implementation of a Qt string (QString) with sterilization methods.
     QBitArray: Implementation of a Qt bit array (Qbytearray) with serialization methods.
    - QList: A Qt list implementation (QList) with support for various data types.
    - EmulatedQtHelpers: Auxiliary methods for emulating the behavior of Qt in the Unicorn Engine.

Constants:
- MALLOC_CHUNK_NUM: The number of allocated memory blocks.
    - MALLOC_BASE: The base address for memory allocation.
ru
Модуль idaemu_qt.py

Описание:
    Этот модуль предоставляет вспомогательные классы и методы для работы с Qt-структурами
    (например, QString, QBitArray, QList) в эмуляции Unicorn Engine в IDA Pro.
    Он включает функции для сериализации данных, работы с памятью и эмуляции поведения Qt.

Авторы:
    - hellmut
    - in7egral

Версия:
    - v0.1 (2024)

Поддерживаемые версии Qt:
    - Qt5

Классы:
    - QString: Реализация строки Qt (QString) с методами сериализации.
    - QBitArray: Реализация битового массива Qt (QBitArray) с методами сериализации.
    - QList: Реализация списка Qt (QList) с поддержкой различных типов данных.
    - EmulatedQtHelpers: Вспомогательные методы для эмуляции поведения Qt в Unicorn Engine.

Константы:
    - MALLOC_CHUNK_NUM: Количество выделяемых блоков памяти.
    - MALLOC_BASE: Базовый адрес для выделения памяти.
"""
import ctypes
from struct import unpack, pack, unpack_from, calcsize
from unicorn import *
import idaapi
import importlib
from idaemu import *
# Purpose: idaemu Qt support mmodule
# Authors: hellmut, in7egral
# Version: v0.1 2024
# Supported Qt versions: qt5
#
# Qt is a registered trademark of The Qt Company Ltd. and its subsidiaries.
MALLOC_CHUNK_NUM = 20
MALLOC_BASE = 0x10000


class QString:
    """
    en
    The QString class implements a Qt string with methods for serializing and working with data.

    Attributes:
        - ref (int): The link counter.
        - size (int): The size of the string.
        - flags (int): Flags of the string.
        - data (list): The string data is in the form of a list of bytes.
        - capacity (int): Row capacity.

    Methods:
        - setData: Sets the row data.
        - serialize: Serializes a string into a byte array.
        - __iter__: Implements iteration over the row data.
        - __eq__: Compares two QString objects.
        - __repr__: Returns the string representation of the QString object.
    ru
    Класс QString реализует строку Qt с методами для сериализации и работы с данными.

    Атрибуты:
        - ref (int): Счетчик ссылок.
        - size (int): Размер строки.
        - flags (int): Флаги строки.
        - data (list): Данные строки в виде списка байтов.
        - capacity (int): Емкость строки.

    Методы:
        - setData: Устанавливает данные строки.
        - serialize: Сериализует строку в байтовый массив.
        - __iter__: Реализует итерацию по данным строки.
        - __eq__: Сравнивает два объекта QString.
        - __repr__: Возвращает строковое представление объекта QString.
    """

    def __init__(self):
        self.ref = 1
        # TODO: qt4
        # self.alloc = 32
        self.size = 0
        self.flags = 0
        self.data = []
        self.capacity = 0

    def setData(self, input_string):
        """
        en
        Sets the row data.

        Arguments:
            - input_string (str): Input string.
        ru
        Устанавливает данные строки.

        Аргументы:
            - input_string (str): Входная строка.
        """
        # self.data = [ord(c) for c in input_string]
        self.data = input_string.encode('utf-16')[2:]
        self.size = len(input_string)  # self.data)
        # self.alloc = max(self.alloc, self.size)

    def serialize(self):
        """
        en
        Serializes a string into a byte array.

        Returns:
            - bytes: Serialized string data.
        ru
        Сериализует строку в байтовый массив.

        Возвращает:
            - bytes: Сериализованные данные строки.
        """
        buffer = bytearray()
        buffer.extend((self.ref).to_bytes(4, byteorder='little'))
        # buffer.extend((self.alloc).to_bytes(4, byteorder='little'))
        buffer.extend((self.size).to_bytes(4, byteorder='little'))
        buffer.extend((self.flags).to_bytes(4, byteorder='little'))
        temp = 0x10
        buffer.extend((temp).to_bytes(4, byteorder='little'))
        buffer.extend(self.data)
        return bytes(buffer)

    def __iter__(self):
        # для итераторов
        return iter(self.data)

    def __eq__(self, other):
        if isinstance(other, QString):
            return (self._ref == other._ref and  # self._alloc == other._alloc and
                    self.data == other.data)
        return False

    def __repr__(self):
        return (f"QString(ref={self.ref}, "
                f"size={self.size}, flags={self.flags}, "
                f"data_length={len(self.data)})")
        # return (f"QString(ref={self.ref}, alloc={self.alloc}, "
        #    f"size={self.size}, flags={self.flags}, "
        #    f"data_length={len(self.data)})")


"""
// Copyright (C) 2009 Nokia Corporation and/or its subsidiary(-ies).
class QBitArray {
    ...
    QByteArray d;
    ...
}
class QByteArray {
    ...
    struct Data {
        QBasicAtomicInt ref;
        int alloc, size;
        // ### Qt 5.0: We need to add the missing capacity bit
        // (like other tool classes have), to maintain the
        // reserved memory on resize.
        char *data;
        char array[1];
    };
    ...
    Data *d;
    ...
}
"""


class QBitArray:
    """
    en
    The Bitarray class implements a Qt bit array with methods for serialization and working with data.

    Attributes:
        - ref (int): The link counter.
        - alloc (int): The capacity of the array.
        - size (int): The size of the array.
        - data (list): The array data is in the form of a list of bytes.

    Methods:
        - setRawData: Sets the array data.
        - serialize: Serializes an array into a byte array.
    ru
    Класс QBitArray реализует битовый массив Qt с методами для сериализации и работы с данными.

    Атрибуты:
        - ref (int): Счетчик ссылок.
        - alloc (int): Емкость массива.
        - size (int): Размер массива.
        - data (list): Данные массива в виде списка байтов.

    Методы:
        - setRawData: Устанавливает данные массива.
        - serialize: Сериализует массив в байтовый массив.
    """

    def __init__(self):
        self.ref = 1
        self.alloc = 32
        self.size = 0
        self.data = []

    def __init__(self, size, value):
        """
        en
        Constructor of the Qbytearray class.

        Arguments:
            - size (int): The size of the array.
            - value (int): The value for initializing the array (0 or 1).
        ru
        Конструктор класса QBitArray.

        Аргументы:
            - size (int): Размер массива.
            - value (int): Значение для инициализации массива (0 или 1).
        """
        self.ref = 1
        self.alloc = size
        self.size = size
        # 1 byte for bits delta in the last byte
        _bitarray_size = (int)(1 + (size + 7) / 8)
        if value != 0:
            value = 0xFF
        self.data = [value] * _bitarray_size
        self.data[0] = (_bitarray_size * 8 - size)
        if value and size and (size % 8):
            self.data[1 + (int)(size / 8)] = (1 << (size % 8)) - 1

    def setRawData(self, vector):
        """
        en
        Sets the array data.

        Arguments:
            - vector (list): A list of bytes.
        ru
        Устанавливает данные массива.

        Аргументы:
            - vector (list): Список байтов.
        """
        self.data = vector

    def serialize(self):
        """
        en
        Serializes an array into a byte array.

        Returns:
            - bytes: Serialized array data.
        ru
        Сериализует массив в байтовый массив.

        Возвращает:
            - bytes: Сериализованные данные массива.
        """
        buffer = bytearray()
        buffer.extend((self.ref).to_bytes(4, byteorder='little'))
        buffer.extend((self.alloc).to_bytes(4, byteorder='little'))
        buffer.extend((self.size).to_bytes(4, byteorder='little'))
        temp = 0x10  # offset to array
        buffer.extend((temp).to_bytes(4, byteorder='little'))
        print(self.data)
        buffer.extend(bytes(self.data))
        return bytes(buffer)

    # funcks for import
MALLOC_CHUNK_NUM = 20
MALLOC_BASE = 0x10000

# Запихнул эти в класс


class EmulatedQtHelpers:
    """
    en
    The EmulatedQtHelpers class provides auxiliary methods for emulating the behavior of Qt.

    Methods:
        - my_malloc: Emulates memory allocation.
        - - my_list_append: Emulates adding an item to a List.
        - my_qtime_qtime: Emulates the creation of a QTime object.
        - my_qbytearray_realloc: Emulates memory reallocation for QByteArray.
        - my_aeabi_idivmod: Emulates division with remainder.
    ru
    Класс EmulatedQtHelpers предоставляет вспомогательные методы для эмуляции поведения Qt.

    Методы:
        - my_malloc: Эмулирует выделение памяти.
        - my_qlist_append: Эмулирует добавление элемента в QList.
        - my_qtime_qtime: Эмулирует создание объекта QTime.
        - my_qbytearray_realloc: Эмулирует перераспределение памяти для QByteArray.
        - my_aeabi_idivmod: Эмулирует деление с остатком.
    """
    @staticmethod
    def my_malloc(uc, out, args):
        """
        en
        Emulates memory allocation.

        Arguments:
            - - UK: Unicorn Engine.
            - out (list): A list for displaying messages.
            - args (list): The arguments of the call.

        Returns:
            - int: The address of the allocated memory.
        ru
        Эмулирует выделение памяти.

        Аргументы:
            - uc: Unicorn Engine.
            - out (list): Список для вывода сообщений.
            - args (list): Аргументы вызова.

        Возвращает:
            - int: Адрес выделенной памяти.
        """
        global MALLOC_CHUNK_NUM
        global MALLOC_BASE
        MALLOC_CHUNK_NUM = MALLOC_CHUNK_NUM + 1
        mem = MALLOC_BASE * MALLOC_CHUNK_NUM
        uc.mem_map(mem, PAGE_ALIGN)
        # out.append('malloc %x' % mem)
        return mem

    @staticmethod
    def my_qlist_append(uc, out, args):
        # TODO: fix me
        # print('%x' % args[1])
        byte = uc.mem_read(args[1], 1)[0]
        print('%d' % byte)
        return

    @staticmethod
    def my_qlist_append2(uc, out, args):
        """
        en
        Emulates adding an element to a List.

        Arguments:
            - - UK: Unicorn Engine.
            - out (list): A list for displaying messages.
            - args (list): The arguments of the call.

        Returns:
            - None
        ru
        Эмулирует добавление элемента в QList.

        Аргументы:
            - uc: Unicorn Engine.
            - out (list): Список для вывода сообщений.
            - args (list): Аргументы вызова.

        Возвращает:
            - None
        """
        # TODO: fix me
        # print('%x' % args[1])
        qlist_data = unpack('<I', uc.mem_read(args[0], 4))[0]
        raw_bytes = bytes(uc.mem_read(args[1], 1))
        byte = raw_bytes[0]
        shared_null = idaapi.get_name_ea(0, '_ZN9QListData11shared_nullE')
        try:
            if qlist_data == shared_null:
                # allocate new
                qlist2 = QList('uchar')
                qlist2.setData(raw_bytes)
                qlist_new_data = qlist2.serialize()
                data_ptr = EmulatedQtHelpers.my_malloc(
                    uc, out, len(qlist_new_data))
                uc.mem_write(data_ptr, qlist_new_data)
                uc.mem_write(args[0], data_ptr.to_bytes(4, byteorder='little'))
            else:
                # print('%x'% qlist_data)
                qlist_begin = unpack('<I', uc.mem_read(qlist_data + 8, 4))[0]
                qlist_end = unpack('<I', uc.mem_read(qlist_data + 12, 4))[0]
                qlist_size = qlist_end - qlist_begin
                bytes_data = raw_bytes + b'\x00\x00\x00'
                uc.mem_write(qlist_data + 0x10 + qlist_size * 4, bytes_data)
                # update size
                new_qlist_end = qlist_size + int(len(bytes_data) / 4)
                print('new size = %d' % new_qlist_end)
                uc.mem_write(qlist_data + 12,
                             new_qlist_end.to_bytes(4, byteorder='little'))
        except Exception as e:
            print("#ERROR: %s" % e)
        print('%x' % byte)
        # uc.mem_write(args[0]
        return

    @staticmethod
    def my_qstring_append(uc, out, args):
        print('%c' % args[1])
        return

    @staticmethod
    def my_qtime_qtime(uc, out, args):
        print('%04d-%02d-%02d' %
              (args[1], args[2], args[3]))
        return

    @staticmethod
    def my_qstring_remove(uc, out, args):
        return args[0]

    @staticmethod
    def my_qstring_toupper_helper(uc, out, args):
        # TODO: fix me - real Upper
        try:
            val1b = bytes(uc.mem_read(args[1], 4))
            uc.mem_write(args[0], bytes(uc.mem_read(args[1], 4)))
        except UcError as e:
            print("#ERROR: %s" % e)
        except Exception as e:
            print("#ERROR: %s" % e)

    @staticmethod
    def my_qbitarray_qbitarray(uc, out, args):
        qBitArray = args[0]
        try:
            bitArray = QBitArray(args[1], args[2])
            data_ptr = EmulatedQtHelpers.my_malloc(
                uc, out, len(bitArray.serialize()))
        except Exception as e:
            print("#ERROR: %s" % e)
        try:
            uc.mem_write(data_ptr, bitArray.serialize())
        except UcError as e:
            print("#ERROR: %s" % e)
        # put allocated data to d
        uc.mem_write(qBitArray, data_ptr.to_bytes(4, byteorder='little'))
        return

    @staticmethod
    def my_qbytearray_realloc(uc, out, args):
        # TODO: fix me
        qByteArray_ptr = args[0]
        new_size = args[1]
        try:
            qByteArray = unpack('<I', uc.mem_read(qByteArray_ptr, 4))[0]
            oldSize = unpack('<I', uc.mem_read(qByteArray + 4, 4))[0]
            print('realloc %x vs %x' % (oldSize, new_size))
            uc.mem_write(
                qByteArray + 4,
                new_size.to_bytes(
                    4,
                    byteorder='little'))
        except Exception as e:
            print("#ERROR: %s" % e)

    @staticmethod
    def my_aeabi_idivmod(uc, out, args):
        try:
            value = args[0]
            divider = args[1]
            uc.reg_write(UC_ARM_REG_R1, int(value % divider))
            return int(value / divider)
        except Exception as e:
            print("#ERROR: %s" % e)
        return 0


class QList:
    """
    en
    The QList class implements a Qt list with support for various data types.

    Attributes:
        - _v_type (str): The data type in the list.
        - _ref (int): The link counter.
        - _alloc (int): The capacity of the list.
        - _begin (int): The beginning of the list.
        - _end_delta (int): End of the list.
        - data (list): List data.

    Methods:
        - setData: Sets the list data.
        - serialize: Serializes the list into a byte array.
    ru
    Класс QList реализует список Qt с поддержкой различных типов данных.

    Атрибуты:
        - _v_type (str): Тип данных в списке.
        - _ref (int): Счетчик ссылок.
        - _alloc (int): Емкость списка.
        - _begin (int): Начало списка.
        - _end_delta (int): Конец списка.
        - data (list): Данные списка.

    Методы:
        - setData: Устанавливает данные списка.
        - serialize: Сериализует список в байтовый массив.
    """
    MALLOC_CHUNK_NUM = 20
    MALLOC_BASE = 0x10000

    def __init__(self, v_type):
        # Detarmine element size depending on type
        if v_type == 'char' or v_type == 'uchar':
            self._element_size = 1
        elif v_type == 'short' or v_type == 'ushort':
            self._element_size = 2
        elif v_type == 'qchar' or v_type == 'int':
            self._element_size = 4
        else:
            raise ValueError("Unknown element type")
        # private properties
        self._v_type = v_type
        self._ref = 1
        self._alloc = 0x20
        self._begin = 0
        self._end_delta = 0
        # data
        self.data = []

    def setData(self, input_string):
        """
        en
        Sets the list data.

        Arguments:
            - input_string (str): Input string.
        ru
        Устанавливает данные списка.

        Аргументы:
            - input_string (str): Входная строка.
        """
        if self._v_type == 'uchar':
            # self.data = list(input_string)
            utf32_encoded = input_string.decode('utf8').encode('utf-32')[4:]
            self.data = list(utf32_encoded)
        # utf-32 without suffix
        if self._element_size == 4 and self._v_type == 'qchar':
            utf32_encoded = input_string.encode('utf-32')[4:]
            self.data = list(utf32_encoded)

    def serialize(self):
        """
        en
        Serializes the list into a byte array.

        Returns:
            - bytes: Serialized list data.
        ru
        Сериализует список в байтовый массив.

        Возвращает:
            - bytes: Сериализованные данные списка.
        """
        # step-by-step serialization
        buffer = bytearray()
        buffer.extend(self._ref.to_bytes(4, byteorder='little'))
        buffer.extend(self._alloc.to_bytes(4, byteorder='little'))
        buffer.extend(self._begin.to_bytes(4, byteorder='little'))
        temp_end = int(len(self.data) / 4)
        buffer.extend(temp_end.to_bytes(4, byteorder='little'))
        buffer.extend(self.data)
        return bytes(buffer)

    def __iter__(self):
        # for iterators
        return iter(self.data)

    def __eq__(self, other):
        if isinstance(other, QList):
            return (self._ref == other._ref and
                    self._alloc == other._alloc and
                    self.data == other.data)
        return False

    def __repr__(self):
        return (f"QList(ref={self._ref}, alloc={self._alloc}, "
                f"begin={self._begin}, end_delta={self._end_delta}, "
                f"data_length={len(self.data)})")

    @staticmethod
    def my_malloc(uc, out, args):
        QList.MALLOC_CHUNK_NUM = QList.MALLOC_CHUNK_NUM + 1
        mem = QList.MALLOC_BASE * QList.MALLOC_CHUNK_NUM
        # out.append('malloc %x' % mem)
        return mem
    # добавить qlist_append

    @staticmethod
    def my_qlist_append(uc, out, args):
        byte = uc.mem_read(args[1], 1)[0]
        print('%d' % byte)
        return

    @staticmethod
    def my_qlist_append2(uc, out, args):
        qlist_data = unpack('<I', uc.mem_read(args[0], 4))[0]
        raw_bytes = bytes(uc.mem_read(args[1], 1))
        byte = raw_bytes[0]
        shared_null = idaapi.get_name_ea(0, '_ZN9QListData11shared_nullE')

        try:
            if qlist_data == shared_null:
                # Allocate new QList
                qlist2 = QList('uchar')
                qlist2.setData(raw_bytes)
                qlist_new_data = qlist2.serialize()
                data_ptr = EmulatedQtHelpers.my_malloc(
                    uc, out, len(qlist_new_data))

                uc.mem_write(data_ptr, qlist_new_data)
                uc.mem_write(args[0], data_ptr.to_bytes(4, byteorder='little'))

            else:
                # Calculate the size and append the byte
                qlist_begin = int.from_bytes(uc.mem_read(
                    qlist_data + 8, 4), byteorder='little')
                qlist_end = int.from_bytes(uc.mem_read(
                    qlist_data + 12, 4), byteorder='little')
                qlist_size = qlist_end - qlist_begin
                bytes_data = raw_bytes + b'\x00\x00\x00'
                uc.mem_write(qlist_data + 0x10 + qlist_size * 4, bytes_data)
                # Update size
                new_qlist_end = qlist_size + int(len(bytes_data) / 4)
                print('new size = %d' % new_qlist_end)
                uc.mem_write(
                    qlist_data + 12,
                    new_qlist_end.to_bytes(
                        4,
                        byteorder='little'))
        except Exception as e:
            print("#ERROR: %s" % e)

        print('%x' % byte)
