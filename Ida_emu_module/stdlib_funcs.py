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
import idaapi


class StdLib_Ops:
    """
    en
    The StdLib_Ops class provides a set of static methods for working with memory
    and strings in an emulated environment. It is intended to be used in the context of
    emulators such as Unicorn Engine, and integration with IDA Pro via IDAPython.
    The methods include memory allocation, copying, and value setting operations.,
    as well as working with strings.

    Class Description:
    Purpose:
            - Working with memory and strings in an emulated environment.
        Features:
- Memory allocation management.
            - Copying data between addresses.
            - Working with strings (for example, calculating the length of a string, searching for characters).
            - Integration with IDA Pro to read data from the database.

    Methods of the class:

    1. my_malloc(uc, out, args)
        Allocates a block of memory in the emulated environment.

        Description:
            - Uses global variables MALLOC_CHUNK_NUM and MALLOC_BASE
              to calculate the address of the allocated memory.
            - Increases the counter of allocated memory blocks.

        Arguments:
            - uc: The emulator object.
            - out: A list for displaying messages (not used in the current implementation).
            - args: Call arguments (not used in the current implementation).

        Returns:
            - int: The address of the allocated memory block.

    2. mmap_page(uc, ea, size)
        Allocates a memory page in the emulated environment.

        Description:
            - Aligns the address and size to the page border (4 KB).
            - Calls the mem_map method of the emulator to allocate memory.

        Arguments:
            - uc: The emulator object.
            - ea: The starting address.
            - size: The size of the memory.

        Returns:
            - int: 1 if allocation is successful, otherwise 0.

    3. common_copy(uc, ea_to, ea_from, size)
        Copies data from one address to another.

        Description:
             Reads bytes from the source address and writes them to the destination address.
            - If no memory is allocated, tries to allocate a memory page.

        Arguments:
            - uc: The emulator object.
            - ea_to: Target address.
            - ea_from: Source address.
            - size: The size of the data to copy.

    4. my_memcpy(uc, out, args)
        Implements the memcpy function.

        Description:
            - Copies data from one address to another using the common_copy method.
            - Displays information about the call in the out list.

        Arguments:
            - uc: The emulator object.
            - out: A list for displaying messages.
            - args: Call arguments (destination address, source address, size).

    5. my_memset(uc, out, args)
        Implements the memset function.

        Description:
            - Fills the memory area with the specified value.
            - If no memory is allocated, tries to allocate a memory page.

        Arguments:
            - uc: The emulator object.
            - out: A list for displaying messages.
            - args: Call arguments (address, value, size).

    6. my_system(uc, out, args)
        Implements the system function.

        Description:
            - Reads a command line from memory.
            - Outputs a command to the console without executing it.

        Arguments:
            - uc: The emulator object.
            - out: A list for displaying messages (not used in the current implementation).
            - args: Call arguments (address of the command line).

    7. my_strchr(uc, out, args)
        Implements the strchr function.

        Description:
            - Searches for the first occurrence of a character in a string.
            - Returns the address of the symbol or 0 if the symbol is not found.

        Arguments:
            - uc: The emulator object.
            - out: A list for displaying messages (not used in the current implementation).
            - args: Call arguments (string address, character).

        Returns:
            - int: The address of the character, or 0 if the character is not found.

    8. my_nop_func(uc, out, args)
        is an empty stub function.

        Description:
            - Does not perform any actions.

        Arguments:
            - uc: The emulator object.
            - out: A list for displaying messages (not used).
            - args: Call arguments (not used).

    9. my_sprintf(uc, out, args)
        is a stub for implementing the sprintf function.

        Description:
            - Not implemented in the current version.

        Arguments:
            - uc: The emulator object.
            - out: A list for displaying messages.
            - args: Call arguments.

    10. my_strlen(uc, out, args)
        Implements the strlen function.

        Description:
            - Calculates the length of a string ending with a zero byte.

        Arguments:
            - uc: The emulator object.
            - out: A list for displaying messages (not used).
            - args: Call arguments (string address).

        Returns:
            - int: The length of the string.
    ru
    Класс StdLib_Ops предоставляет набор статических методов для работы с памятью
    и строками в эмулированной среде. Он предназначен для использования в контексте
    эмуляторов, таких как Unicorn Engine, и интеграции с IDA Pro через IDAPython.
    Методы включают операции выделения памяти, копирования, установки значений,
    а также работу со строками.

    Описание класса:
        Назначение:
            - Работа с памятью и строками в эмулированной среде.
        Особенности:
            - Управление выделением памяти.
            - Копирование данных между адресами.
            - Работа со строками (например, вычисление длины строки, поиск символов).
            - Интеграция с IDA Pro для чтения данных из базы.

    Методы класса:

    1. my_malloc(uc, out, args)
        Выделяет блок памяти в эмулированной среде.

        Описание:
            - Использует глобальные переменные MALLOC_CHUNK_NUM и MALLOC_BASE
              для расчета адреса выделяемой памяти.
            - Увеличивает счетчик выделенных блоков памяти.

        Аргументы:
            - uc: Объект эмулятора.
            - out: Список для вывода сообщений (не используется в текущей реализации).
            - args: Аргументы вызова (не используются в текущей реализации).

        Возвращает:
            - int: Адрес выделенного блока памяти.

    2. mmap_page(uc, ea, size)
        Выделяет страницу памяти в эмулированной среде.

        Описание:
            - Выравнивает адрес и размер на границу страницы (4 KB).
            - Вызывает метод mem_map эмулятора для выделения памяти.

        Аргументы:
            - uc: Объект эмулятора.
            - ea: Начальный адрес.
            - size: Размер памяти.

        Возвращает:
            - int: 1, если выделение успешно, иначе 0.

    3. common_copy(uc, ea_to, ea_from, size)
        Копирует данные из одного адреса в другой.

        Описание:
            - Читает байты из исходного адреса и записывает их в целевой адрес.
            - Если память не выделена, пытается выделить страницу памяти.

        Аргументы:
            - uc: Объект эмулятора.
            - ea_to: Целевой адрес.
            - ea_from: Исходный адрес.
            - size: Размер данных для копирования.

    4. my_memcpy(uc, out, args)
        Реализует функцию memcpy.

        Описание:
            - Копирует данные из одного адреса в другой, используя метод common_copy.
            - Выводит информацию о вызове в список out.

        Аргументы:
            - uc: Объект эмулятора.
            - out: Список для вывода сообщений.
            - args: Аргументы вызова (адрес назначения, адрес источника, размер).

    5. my_memset(uc, out, args)
        Реализует функцию memset.

        Описание:
            - Заполняет область памяти указанным значением.
            - Если память не выделена, пытается выделить страницу памяти.

        Аргументы:
            - uc: Объект эмулятора.
            - out: Список для вывода сообщений.
            - args: Аргументы вызова (адрес, значение, размер).

    6. my_system(uc, out, args)
        Реализует функцию system.

        Описание:
            - Читает строку команды из памяти.
            - Выводит команду в консоль без выполнения.

        Аргументы:
            - uc: Объект эмулятора.
            - out: Список для вывода сообщений (не используется в текущей реализации).
            - args: Аргументы вызова (адрес строки команды).

    7. my_strchr(uc, out, args)
        Реализует функцию strchr.

        Описание:
            - Ищет первое вхождение символа в строке.
            - Возвращает адрес символа или 0, если символ не найден.

        Аргументы:
            - uc: Объект эмулятора.
            - out: Список для вывода сообщений (не используется в текущей реализации).
            - args: Аргументы вызова (адрес строки, символ).

        Возвращает:
            - int: Адрес символа или 0, если символ не найден.

    8. my_nop_func(uc, out, args)
        Пустая функция-заглушка.

        Описание:
            - Не выполняет никаких действий.

        Аргументы:
            - uc: Объект эмулятора.
            - out: Список для вывода сообщений (не используется).
            - args: Аргументы вызова (не используются).

    9. my_sprintf(uc, out, args)
        Заглушка для реализации функции sprintf.

        Описание:
            - В текущей версии не реализована.

        Аргументы:
            - uc: Объект эмулятора.
            - out: Список для вывода сообщений.
            - args: Аргументы вызова.

    10. my_strlen(uc, out, args)
        Реализует функцию strlen.

        Описание:
            - Вычисляет длину строки, заканчивающейся нулевым байтом.

        Аргументы:
            - uc: Объект эмулятора.
            - out: Список для вывода сообщений (не используется).
            - args: Аргументы вызова (адрес строки).

        Возвращает:
            - int: Длину строки.
    """
    MALLOC_CHUNK_NUM = 0
    MALLOC_BASE = 0x10000
    PAGE_ALIGN = 0x1000  # 4k

    @staticmethod
    def my_malloc(uc, out, args):
        global MALLOC_CHUNK_NUM
        global MALLOC_BASE
        MALLOC_CHUNK_NUM = MALLOC_CHUNK_NUM + 1
        mem = MALLOC_BASE * MALLOC_CHUNK_NUM
        # out.append('malloc %x' % mem)
        return mem

    @staticmethod
    def mmap_page(uc, ea, size):
        map_size = PAGE_ALIGN
        map_addr = (ea / PAGE_ALIGN) * PAGE_ALIGN
        if map_addr < ea:
            map_addr -= PAGE_ALIGN
            size += (ea - map_addr)
        while map_size < size:
            map_size += PAGE_ALIGN
        try:
            uc.mem_map(map_addr, map_size)
            return 1
        except Exception as e:
            print("mmap_page exception: %s" % e)
            return 0
    # @staticmethod
    # def common_copy(uc, ea_to, ea_from, size):
    #    i = 0
    #    while i < size:
    #        addr_from = ea_from + i
    #        addr_to = ea_to + i
    #        try:
    #            byte = struct.pack('B', uc.mem_read(addr_from, 1))
    #        except:
    #            # mem is unmapped, so try to read
    #            # directly from the database
    #            byte = struct.pack('B', idaapi.get_byte(addr_from))
    #        uc.mem_write(addr_to, byte)
    #        i += 1

    @staticmethod
    def common_copy(uc, ea_to, ea_from, size):
        i = 0
        while i < size:
            addr_from = ea_from + i
            addr_to = ea_to + i
            try:
                byte = struct.pack('B', uc.mem_read(addr_from, 1)[0])
            except BaseException:
                # mem is unmapped, so try to read
                # directly from the database
                byte = struct.pack('B', idaapi.get_byte(addr_from))
            try:
                uc.mem_write(addr_to, byte)
            except BaseException:
                uc.mem_map(addr_to, PAGE_ALIGN)
                uc.mem_write(addr_to, byte)
            i += 1

    @staticmethod
    def my_memcpy(uc, out, args):
        # void * memcpy(void *restrict dst, const void *restrict src, size_t n);
        # print 'memcpy: (%#x, %#x, [%#x])' % (args[0], args[1], args[2])
        out.append('memcpy: (%#x, %#x, [%#x])' % (args[0], args[1], args[2]))
        common_copy(uc, args[0], args[1], args[2])

    @staticmethod
    def my_memset(uc, out, args):
        # void *s memset(void *b, int c, size_t len);
        out.append('memset: (%#x, %#x, %#x)' % (args[0], args[1], args[2]))
        i = 0
        ea_to = args[0]
        value = struct.pack('B', args[1] & 0xFF)
        size = args[2]
        while i < size:
            addr_to = ea_to + i
            try:
                uc.mem_write(addr_to, value)
            except Exception as e:
                if mmap_page(uc, ea_to, size):
                    i -= 1
                else:
                    return
            i += 1

    @staticmethod
    def my_system(uc, out, args):
        # int system(const char *command);
        i = 0
        # read back
        data = ''
        while 1:
            try:
                byte = uc.mem_read(args[0] + i, 1)[0]
            except BaseException:
                # mem is unmapped, so try to read
                # directly from the database
                byte = idaapi.get_byte(args[0] + i)
            if byte == 0:
                break
            data += '%c' % byte
            i += 1
        # just print without execution
        print('system(%s)' % (data))

    @staticmethod
    def my_strchr(uc, out, args):
        # char *strchr(const char *s, int c);
        # out.append('strchr: (%#x, %x)' % (args[0], args[1]))
        s = args[0]
        if s == 0:
            return
        c = args[1]
        i = 0
        while 1:
            try:
                byte = uc.mem_read(s + i, 1)[0]
            except BaseException:
                # mem is unmapped, so try to read
                # directly from the database
                byte = idaapi.get_byte(s + i)
            if byte == 0:
                break
            if c == byte:
                return (i + s)
            i += 1
        return 0  # NULL

    @staticmethod
    def my_nop_func(uc, out, args):
        pass

    @staticmethod
    def my_sprintf(uc, out, args):
        # TODO: finish me
        pass

    @staticmethod
    def my_strlen(uc, out, args):
        ea_str = args[0]
        i = 0
        while 1:
            try:
                byte = uc.mem_read(args[0] + i, 1)[0]
            except BaseException:
                # mem is unmapped, so try to read
                # directly from the database
                byte = idaapi.get_byte(args[0] + i)
            if byte == 0:
                break
            i += 1
        return i
