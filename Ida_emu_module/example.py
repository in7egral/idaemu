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
from ida_emu_module import *

a = Emu(UC_ARCH_ARM, UC_MODE_ARM)

a.alt(aeabi_idivmod, EmulatedQtHelpers.my_aeabi_idivmod, 2, False)
a.alt(pow_f, EmulatedMath.my_pow, 2, False)
a.altQt5()
a.alt(QString_append, EmulatedQtHelpers.my_qstring_append, 2, False)
a.alt(QString_remove_char, EmulatedQtHelpers.my_qstring_remove, 3, False)
a.alt(QString_to_Upper, EmulatedQtHelpers.my_qstring_toupper_helper, 2, False)
a.alt(Bit_Array, EmulatedQtHelpers.my_qbitarray_qbitarray, 3, False)
a.alt(Byte_Array_Realloc_Data, EmulatedQtHelpers.my_qbytearray_realloc, 3, False)

a.alt(malloc_ea, EmulatedQtHelpers.my_malloc, 1, False)
a.alt(memcpy_ea, StdLib_Ops.my_memcpy, 3, False)
a.alt(memset_ea, StdLib_Ops.my_memset, 3, False)
a.alt(system_ea, StdLib_Ops.my_system, 1, False)
a.alt(strchr_ea, StdLib_Ops.my_strchr, 2, False)
a.alt(daemon_ea, StdLib_Ops.my_nop_func, 2, False)
a.alt(sprintf_ea, StdLib_Ops.my_sprintf, 2, False)
a.alt(strlen_ea, StdLib_Ops.my_strlen, 1, False)


a.setExtensionEnabled(VFP_ENABLED)
#
# Check UnitController_AccessMode::VerifyCRC
#
#
# set QBitArray in
#
data_ptr5 = 0x60000  # QBitArray
data_ptr6 = 0x70000  # QByteArrayData
# a.setData(data_ptr3, data_ptr4.to_bytes(4, byteorder='little'))
a.setData(data_ptr5, data_ptr6.to_bytes(4, byteorder='little'))
bitArray = QBitArray(100, 0)
bitArray.setRawData(
    b'\x0c\x02\x8e\x5a\x00\x16\xc3\x02\x01\x00\x00\x00\x00\x03')
serialized_data = bitArray.serialize()
a.setData(data_ptr6, serialized_data)

a.setReg(UC_ARM_REG_R1, data_ptr5)
a.silentStart()
a.showDump(data_ptr5, 0x20)
a.showDump(data_ptr6, 0x10)
# VerifyCRC
if 0:
    a.eBlock(0x9D8A0, 0x9DA10)  # last 4 bits
    barray = a.getReg(UC_ARM_REG_R3)
    # a.showDump(barray, 0x20)
    # barray_ptr = a.getReg(UC_ARM_REG_R6)
    # barray2 = a.getData('i', int(barray_ptr), 1)[0]
    # a.showDump(barray2, 0x20)
if 0:
    a.eBlock(0x9D8A0, 0x9D920)
    # crc_stored = 0x40
if 0:
    a.eBlock(0x9D8A0, 0x9DAFC)  # First byte
    barray = a.getReg(UC_ARM_REG_R2)
    # a.eUntilAddress(0x9DAFC, 0x9DAF8)
if 0:
    a.eBlock(0x9D8A0, 0x9DA04)  # Last byte
if 1:
    a.setTrace(TRACE_DATA_WRITE | TRACE_DATA_READ | TRACE_CODE)
    a.eBlock(0x9D8A0, 0x9DB0C)  # Full
    # a.showTrace()
    barray = a.getReg(UC_ARM_REG_R0)
    a.showDump(barray, 0x40)

is64 = 1
helper = Helper(is64)

ea = 0x6E4AC0
info = helper.resolve(ea)
print(f'{info}')
