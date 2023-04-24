import logging
import re
import sys
from dataclasses import dataclass
from typing import Optional, Union, List, Dict

import fixups

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class RegisterSection:
    name: str
    address_range_begin: int
    address_range_end: int
    register_depth: int  # Bytes per address
    register_length_max: int  # Max number of bytes in same register
    header_prefix: str
    address_offset_per_dump_line: int  # Bytes

    @property
    def members(self):
        return (self.name,
                self.address_range_begin,
                self.address_range_end,
                self.register_depth,
                self.register_length_max,
                self.header_prefix,
                self.address_offset_per_dump_line)

    def __eq__(self, other):
        return self.members == other.members

    @property
    def size(self) -> int:
        """Number of bytes in this register section"""
        return (self.address_range_end - self.address_range_begin) * self.register_depth


REGULAR_REGISTER_SECTIONS: list[RegisterSection] = [
    RegisterSection('MAC', 0, 0x800, 1, 4, 'REG_', 16),
    RegisterSection('BB', 0x800, 0x1000, 1, 4, 'REG_', 16),
    RegisterSection('FW', 0x1000, 0x5000, 1, 4, 'REG_', 16),
    RegisterSection('USB', 0xfe17, 0xfe60, 1, 4, 'REG_', 16),
    RegisterSection('NORMAL', 0xfe60, 0xfee0, 1, 4, 'REG_', 16),
]
NAME_TO_REGULAR_REGISTER_SECTION = {r.name: r for r in REGULAR_REGISTER_SECTIONS}

RF_REGISTER_SECTIONS: list[RegisterSection] = [
    RegisterSection('RF', 0, 0x40, 4, 1, 'RF6052_REG_', 4),
]
NAME_TO_RF_REGISTER_SECTION = {r.name: r for r in RF_REGISTER_SECTIONS}

NAME_TO_ANY_REGISTER_SECTION = NAME_TO_REGULAR_REGISTER_SECTION | NAME_TO_RF_REGISTER_SECTION
ALL_REGISTER_SECTIONS = REGULAR_REGISTER_SECTIONS + RF_REGISTER_SECTIONS


@dataclass(frozen=True)
class PartialRegisterDescription:
    name_as_in_header: str
    base_address: int

    def __lt__(self, other) -> bool:
        return self.base_address < other.base_address

    def is_of_type(self, register_type: RegisterSection):
        return self.name_as_in_header.startswith(register_type.header_prefix) and \
               register_type.address_range_begin <= self.base_address < register_type.address_range_end

    @property
    def name(self):
        """Prettified name without the prefixes used in the header"""
        if self.name_as_in_header == 'unknown':
            return self.name_as_in_header
        for t in NAME_TO_ANY_REGISTER_SECTION.values():
            if self.is_of_type(t):
                return self.name_as_in_header.removeprefix(t.header_prefix)
        raise RuntimeError(f'Not a register header name: {self.name_as_in_header}')


class FieldDescription:
    """Describe a (continuous) range of bits within a register. ."""

    def __init__(self, name: str, bitmask: int):
        self.name = name
        self.bitmask = bitmask

    @classmethod
    def from_range(cls, name: str, begin: int, end: int):
        """Create MaskDescription from non-negative, zero-based indexes"""
        if end <= begin or begin < 0:
            raise ValueError('Illegal bit positions')
        bitmask = 0
        for i in range(begin, end):
            bitmask |= 0x1 << i
        return FieldDescription(name, bitmask)

    def __repr__(self) -> str:
        return str(self.__members)

    def __eq__(self, other: 'FieldDescription'):
        return other.__members == self.__members

    def __hash__(self):
        return self.bitmask

    def __lt__(self, other):
        return self.begin < other.begin

    @property
    def __members(self):
        return self.name, self.bitmask

    @property
    def begin(self):
        bit_str_lsb_first = bin(self.bitmask)[::-1]
        return bit_str_lsb_first.find("1")

    @property
    def end(self):
        bit_str_lsb_first = bin(self.bitmask)[::-1]
        return bit_str_lsb_first.rfind("1") + 1

    @property
    def size(self) -> int:
        """Size in bits - Warning: May contain "holes" with bits set to zero!"""
        return self.end - self.begin

    def belongs_to(self, partial_register_description: PartialRegisterDescription):
        return self.name.startswith(partial_register_description.name)

    def get_value(self, register_value: int) -> int:
        """Value of bits described by the field"""
        register_value &= self.bitmask
        register_value >>= self.begin
        return register_value


class RegisterDescription:
    """Describing a register as well as possible using the available information"""

    REGISTERS_HINTS = {
        'TSFTR': 'Ignore (Timer)',
        'TSFTR1': 'Ignore (Timer)',
        'INIT_TSFTR': 'Ignore (Timer)',
        'TSFTR1_OVERFLOW': 'Ignore (Timer)',
        'FPGA0_POWER_SAVE': 'Bit 28 never set by [rtl]8192cu',
        'FPGA0_XB_HSSI_PARM1': 'Ignore (RF B path)',
        'FPGA0_XB_HSSI_PARM2': 'Ignore (RF B path)',
        'FPGA0_XB_LSSI_PARM': 'Ignore (RF B path)',
        'HSPI_XB_READBACK': 'Ignore (RF B path)',
        'FPGA0_XB_LSSI_READBACK': 'Ignore (RF B path)',
        'FPGA0_XB_RF_SW_CTRL': 'Ignore (RF B path)',
        'OFDM0_XB_RX_IQ_IMBALANCE': 'Ignore (RF B path)',
        'OFDM0_XB_TX_IQ_IMBALANCE': 'Ignore (RF B path)',
        'TX_AGC_B_RATE18_06': 'Ignore (RF B path)',
        'TX_AGC_B_RATE54_24': 'Ignore (RF B path)',
        'TX_AGC_B_CCK1_55_MCS32': 'Ignore (RF B path)',
        'TX_AGC_B_MCS03_MCS00': 'Ignore (RF B path)',
        'TX_AGC_B_MCS07_MCS04': 'Ignore (RF B path)',
        'TX_AGC_B_MCS11_MCS08': 'Ignore (RF B path)',
        'TX_AGC_B_MCS15_MCS12': 'Ignore (RF B path)',
        'TX_AGC_B_CCK11_A_CCK2_11': 'Ignore (RF B path)',
        'RETRY_LIMIT': 'rtl8xxxu: Adjusted by mac80211',
        'SPEC_SIFS': 'Endian error in rtl8192cu?',
        'RXERR_RPT': 'Ignore (not a control register)',
        'NAV_UPPER': 'Setting to zero *reduces* performance!',
        'RXFF_PTR': '8192cu: unstable; probably to ignore',
        'MCUTST_2': '8192cu: unstable; probably to ignore',
        'TDECTRL': '8192cu: unstable; probably to ignore',
        'MULTI_BCNQ_OFFSET': '8192cu: unstable; probably to ignore',
        'POWER_STATUS': 'Toggles often, probably to ignore!',
        'CAM_DEBUG': 'Toggles often, probably to ignore!',
        'RSV_CTRL': '8192cu: unstable (LEDCFG0)',
        'EFUSE_CTRL': 'Ignore (used of io on efuse)',
        'HMBOX_0': 'Ignore (used for H2C)',
        'HMBOX_1': 'Ignore (used for H2C)',
        'HMBOX_2': 'Ignore (used for H2C)',
        'HMBOX_3': 'Ignore (used for H2C)',
        'HMBOX_EXT_0': 'Ignore (used for H2C)',
        'HMBOX_EXT_1': 'Ignore (used for H2C)',
        'HMBOX_EXT_2': 'Ignore (used for H2C)',
        'HMBOX_EXT_3': 'Ignore (used for H2C)',
        'MCU': 'Ignore (MCU control)',
        'GPIO_OUTSTS': 'Simple write does not work'
    }

    def __init__(self, parent: 'RegisterMap', name: str, base_address: int):
        self.parent = parent
        self.name = name
        self.base_address = base_address
        self.fields = {}

    def __repr__(self):
        return self.name, self.base_address

    def __str__(self):
        return f'{self.name}@{self.base_address:x}'

    def __lt__(self, other):
        return self.base_address < other.base_address

    @property
    def end_address(self):
        return self.base_address + self.length

    @property
    def hint(self) -> str:
        try:
            return self.REGISTERS_HINTS[self.name]
        except KeyError:
            return ''

    @property
    def _next_register_description(self) -> Optional['RegisterDescription']:
        return self.parent.next_register(self)

    @property
    def length(self) -> int:
        """Number of addresses covered by this register"""
        # Best guess if no next register is known
        if self._next_register_description is None:
            return self.parent.section.register_length_max - self.base_address % self.parent.section.register_length_max
        return min(self.parent.section.register_length_max,
                   self._next_register_description.base_address - self.base_address)

    @property
    def depth(self) -> int:
        """Number of bytes behind every address"""
        return self.parent.section.register_depth

    @property
    def size(self) -> int:
        """Number of bytes belonging to this register"""
        return self.length * self.depth

    @property
    def bitmask(self):
        return (0x1 << self.size * 8) - 1

    def add_field(self, field_description: FieldDescription) -> None:
        # Create dict to map each bit to its field description (or None)
        if len(self.fields) != self.size * 8:
            self.fields = {i: None for i in range(self.size * 8)}
        if self.size * 8 < field_description.end:
            raise RuntimeError(
                f'Bit #{field_description.end - 1} of field {field_description.name} exceeds {self.size} bytes size of register "{self.name}"')
        for i in range(field_description.begin, field_description.end):
            if self.fields[i] is not None:
                raise RuntimeError(
                    f'Bit #{i} of register "{self.name}" is already claimed by field "{self.fields[i].name}"')
            self.fields[i] = field_description

    @property
    def known_bitmask(self):
        r = 0
        for k, v in self.fields.items():
            if v is not None:
                r |= 0x1 << k
        return r

    @property
    def unknown_field(self) -> FieldDescription:
        if len(self.fields) == 0:
            return FieldDescription('unknown', (1 << self.size) - 1)
        mask = 0
        for offset, v in self.fields.items():
            if v is None:
                mask |= 0x1 << offset
        return FieldDescription('unknown', mask)

    @property
    def known_fields(self) -> List[FieldDescription]:
        return sorted({x for x in self.fields.values() if x})

    def get_affected_fields(self, bitmask: int) -> List[FieldDescription]:
        begin_to_field = []
        index = 0
        while bitmask:
            if bitmask & (0x1 << index):
                bitmask &= ~self.fields[index].bitmask
                begin_to_field.append(self.fields[index])
            index += 1
        return begin_to_field


class RegisterMap:
    def __init__(self, section: RegisterSection):
        self.section = section
        self._address_to_register = {x: None for x in
                                     range(section.address_range_begin, section.address_range_end)}

    def add_register(self, partial_register_descriptions: PartialRegisterDescription) -> RegisterDescription:
        new = RegisterDescription(self, partial_register_descriptions.name, partial_register_descriptions.base_address)
        if (old := self._address_to_register[new.base_address]) is not None:
            if old == new:
                raise RuntimeError(f'Already added register "{new.name}"')
            if old.base_address == new.base_address:
                raise RuntimeError(f'Conflict: Register "{new.name}" vs "{old.name} at 0x{new.base_address:04x}')
            if new.base_address < old.base_address:
                raise RuntimeError(f'Invariant violated by register "{old.name} at 0x{new.base_address:04x}')
        for address in range(new.base_address,
                             new.base_address + self.section.register_length_max - new.base_address % self.section.register_length_max):
            old = self._address_to_register[address]
            if old is not None and new.base_address < old.base_address:
                break
            self._address_to_register[address] = new
        return new

    def next_register(self, current_register: RegisterDescription) -> Optional[RegisterDescription]:
        for address, maybe_next_register in self._address_to_register.items():
            if maybe_next_register is not None and maybe_next_register.base_address > current_register.base_address:
                return maybe_next_register
        return

    def previous_register_from_address(self, address: int) -> Optional[RegisterDescription]:
        for maybe_address in range(address - 1, self.section.address_range_begin - 1, -1):
            if (maybe_register := self._address_to_register[maybe_address]) is not None:
                return maybe_register
        return

    @staticmethod
    def from_rtl8xxxu_header(rtl8xxxu_header_content: Union[List[str], str],
                             register_type: RegisterSection) -> 'RegisterMap':
        partial_register_descriptions, field_descriptions = _parse_rtl8xxxu_reg_header_extract(
            rtl8xxxu_header_content)
        register_map = RegisterMap(register_type)
        # Remove all register types not relevant for this register type
        partial_register_descriptions = sorted(r for r in partial_register_descriptions
                                               if r.name_as_in_header not in fixups.REGISTER_NAMES_TO_IGNORE
                                               and r.is_of_type(register_type))
        # Add all (relevant) registers to register map
        # Registers with longest names first to make sure we assign the proper fields.
        # Not sorting by length would cause GPIO_IO_SEL_2_GPIO09_INPUT to be assigned to register REG_GPIO_PIN_CTRL
        # instead of REG_GPIO_PIN_CTRL_2.
        fields_remaining = set(field_descriptions)
        for partial_register_description in sorted(partial_register_descriptions, key=lambda d: d.name, reverse=True):
            register = register_map.add_register(partial_register_description)
            fields_to_assign = [f for f in fields_remaining if f.belongs_to(partial_register_description)]
            for f in fields_to_assign:
                register.add_field(f)
            fields_remaining -= set(fields_to_assign)
        return register_map

    @property
    def registers_with_names(self) -> List[RegisterDescription]:
        return sorted({x for x in self._address_to_register.values() if x})

    def print(self, file=sys.stdout):
        for register in self.registers_with_names:
            print(
                f'{register.name}: {register.depth} byte(s) at {register.length} addresses starting at 0x{register.base_address:04x}',
                file=file)
            for field in register.known_fields + [register.unknown_field]:
                print(f' - {field.name}: 0x{field.bitmask:04x}', file=file)

    def register_at_address(self, address: int):
        if reg := self._address_to_register[address]:
            return reg
        previous = self.previous_register_from_address(address)
        base_address = max(previous.base_address, address - address % self.section.register_length_max)
        return self.add_register(PartialRegisterDescription("unknown", base_address))


def register_maps_from_header(rtl8xxxu_header_content: Union[List[str], str]) -> Dict[str, 'RegisterMap']:
    return {x.name: RegisterMap.from_rtl8xxxu_header(rtl8xxxu_header_content, x) for x in ALL_REGISTER_SECTIONS}


def _parse_rtl8xxxu_reg_header_extract_register(line: str) -> Optional[PartialRegisterDescription]:
    if match_register := re.match(
        "^#define (?P<name>(RF6052_)?REG_[A-Z_0-9]+)	+(?P<base_address>0x[a-f0-9]+)",
        line,
    ):
        name = match_register['name']
        if name in fixups.REGISTER_NAMES_TO_IGNORE:
            return
        base_address = int(match_register['base_address'], 16)
        return PartialRegisterDescription(name, base_address)


def _parse_rtl8xxxu_reg_header_extract_field(line: str) -> Optional[FieldDescription]:
    if match_bit := re.match(r"^#define {2}(?P<name>[A-Z_0-9]+)	+BIT\((?P<bit>[0-9]+)\)", line):
        name = match_bit['name']
        if name in fixups.MASK_NAMES_TO_IGNORE:
            return
        bit = int(match_bit['bit'])
        return FieldDescription.from_range(name, bit, bit + 1)
    if match_mask := re.match(r"^#define {2}(?P<name>[A-Z_0-9]+)_MASK	+(?P<mask>0x[0-9a-z]+)", line):
        name = match_mask['name']
        if name in fixups.MASK_NAMES_TO_IGNORE:
            return
        mask = int(match_mask['mask'], 16)
        return FieldDescription(name, mask)
    if match_bits := re.match(r"^#define {2}(?P<name>[A-Z_0-9]+)	+\((?P<bits>(BIT\([0-9]+\) \| )+BIT\([0-9]+\))\)",
                              line):
        name = match_bits['name']
        if name in fixups.MASK_NAMES_TO_IGNORE:
            return
        bits = sorted([int(x) for x in re.findall(r'\d+', match_bits['bits'])])
        if len(bits) != len(set(bits)):
            raise RuntimeError(f"Duplicates in bit mask: {line}")
        if bits[-1] - bits[0] != len(bits) - 1:
            raise RuntimeError(f"Non-continuous mask: {line}")
        return FieldDescription.from_range(name, bits[0], bits[-1] + 1)


def _parse_rtl8xxxu_reg_header_extract(rtl8xxxu_header_content: Union[List[str], str]) \
        -> ([PartialRegisterDescription], [FieldDescription]):
    """
    Extract register and field description from rtl8xxxu_regs.h
    """
    if type(rtl8xxxu_header_content) == str:
        rtl8xxxu_header_content = rtl8xxxu_header_content.splitlines()

    registers = []
    fields = []
    for line in rtl8xxxu_header_content:
        line = line.strip()
        if not line:
            continue
        if register := _parse_rtl8xxxu_reg_header_extract_register(line):
            registers.append(register)
            continue
        if field := _parse_rtl8xxxu_reg_header_extract_field(line):
            fields.append(field)
        log.debug(f'Unhandled line: {line}')
    return registers, fields
