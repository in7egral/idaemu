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
import ctypes


class Conv(ctypes.Union):
    """
    en
    The Conv class is used to convert between floating point numbers (float)
    and 64-bit integers (uint64). This is achieved by using a common
    memory for two fields: float and int.

    Fields:
        - float (ctypes.c_double): A floating-point number.
        - int (ctypes.c_uint64): 64-bit unsigned integer.

    Usage example:
    c = Conv()
    c.float = 3.14
    print(c.int ) # Getting a 64-bit representation of the number 3.14
    ru
    Класс Conv используется для преобразования между числами с плавающей точкой (float)
    и 64-битными целыми числами (uint64). Это достигается за счет использования общей
    памяти для двух полей: float и int.

    Поля:
        - float (ctypes.c_double): Число с плавающей точкой.
        - int (ctypes.c_uint64): 64-битное целое число без знака.

    Пример использования:
        c = Conv()
        c.float = 3.14
        print(c.int)  # Получение 64-битного представления числа 3.14
    """
    _fields_ = [("float", ctypes.c_double), ("int", ctypes.c_uint64)]


class EmulatedMath:
    """
    en
    The Emulated Math class provides static methods for performing mathematical
    operations and converting data between floating point numbers (float) and
    64-bit integers (uint64). It also implements the exponentiation function.
    in an emulated environment.

    Methods:
         to Float(val): Converts a 64-bit integer to a floating-point number.
        - toUint64(val): Converts a floating-point number to a 64-bit integer.
        - - my_power(uc, out, args): Performs exponentiation using
          registers of the emulated environment.
    ru
    Класс EmulatedMath предоставляет статические методы для выполнения математических
    операций и преобразования данных между числами с плавающей точкой (float) и
    64-битными целыми числами (uint64). Также реализует функцию возведения в степень
    в эмулированной среде.

    Методы:
        - toFloat(val): Преобразует 64-битное целое число в число с плавающей точкой.
        - toUint64(val): Преобразует число с плавающей точкой в 64-битное целое число.
        - my_pow(uc, out, args): Выполняет возведение числа в степень, используя
          регистры эмулированной среды.
    """
    @staticmethod
    def toFloat(val):
        """
        en
        Converts a 64-bit integer (uint64) to a floating-point number (float).

        Arguments:
            - val (int): a 64-bit integer.

        Returns:
            - float: A floating-point number.

        Example:
            float_value = EmulatedMath.toFloat(4607182418800017408)
            print(float_value) # Output: 3.14
        ru
        Преобразует 64-битное целое число (uint64) в число с плавающей точкой (float).

        Аргументы:
            - val (int): 64-битное целое число.

        Возвращает:
            - float: Число с плавающей точкой.

        Пример:
            float_value = EmulatedMath.toFloat(4607182418800017408)
            print(float_value)  # Вывод: 3.14
        """
        c = Conv()
        c.int = val
        return c.float

    @staticmethod
    def toUint64(val):
        """
        en
        Converts a floating-point number (float) to a 64-bit integer (uint64).

        Arguments:
            - val (float): A floating-point number.

        Returns:
            - int: a 64-bit integer.

        Example:
            uint64_value = EmulatedMath.toUint64(3.14)
            print(uint64_value) # Output: 4607182418800017408
        ru
        Преобразует число с плавающей точкой (float) в 64-битное целое число (uint64).

        Аргументы:
            - val (float): Число с плавающей точкой.

        Возвращает:
            - int: 64-битное целое число.

        Пример:
            uint64_value = EmulatedMath.toUint64(3.14)
            print(uint64_value)  # Вывод: 4607182418800017408
        """
        c = Conv()
        c.float = val
        return c.int

    @staticmethod
    def my_pow(uc, out, args):
        """
        en
        Performs exponentiation using the registers of the emulated environment.

        Description:
             Reads two floating-point numbers from registers UC_ARM_REV_D0 and UC_ADM_REG_D8.
            - Performs the exponentiation operation: res = pow(arg0, arg1).
            - Converts the result back to a 64-bit integer and writes it
              to the UC_ARM_REG_D0 register.

        Arguments:
            - uc: An emulator object (for example, Unicorn Engine).
            - out: A list for displaying messages (not used in the current implementation).
            - args: Call arguments (not used in the current implementation).

        Returns:
            - None

        Example:
            EmulatedMath.my_pow(uc, None, None)
        ru
        Выполняет возведение числа в степень, используя регистры эмулированной среды.

        Описание:
            - Читает два числа с плавающей точкой из регистров UC_ARM_REG_D0 и UC_ARM_REG_D8.
            - Выполняет операцию возведения в степень: res = pow(arg0, arg1).
            - Преобразует результат обратно в 64-битное целое число и записывает его
              в регистр UC_ARM_REG_D0.

        Аргументы:
            - uc: Объект эмулятора (например, Unicorn Engine).
            - out: Список для вывода сообщений (не используется в текущей реализации).
            - args: Аргументы вызова (не используются в текущей реализации).

        Возвращает:
            - None

        Пример:
            EmulatedMath.my_pow(uc, None, None)
        """
        arg0 = EmulatedMath.toFloat(uc.reg_read(UC_ARM_REG_D0))
        arg1 = EmulatedMath.toFloat(uc.reg_read(UC_ARM_REG_D8))
        print(arg1)
        res = pow(arg0, arg1)
        uc.reg_write(UC_ARM_REG_D0, EmulatedMath.toUint64(res))
        return
