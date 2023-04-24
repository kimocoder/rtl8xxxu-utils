import logging
import os.path
import re
from dataclasses import dataclass
from io import TextIOWrapper
from typing import Optional, Iterable, Dict, Set, List

from register import RegisterSection, NAME_TO_ANY_REGISTER_SECTION, RegisterDescription

log = logging.getLogger(__name__)


@dataclass
class RawDump:
    name: str
    content: str

    def lines(self):
        return [line.strip() for line in self.content.splitlines()]


@dataclass
class Dump:
    driver: Optional[str]
    section: RegisterSection
    address_to_value: Dict[int, bytes]
    name: str

    @property
    def driver_name(self):
        return self.driver if self.driver else "unknown driver"

    @classmethod
    def parse_dump(cls, dump_file: RawDump):
        lines = dump_file.lines()
        header_line = lines[0]
        if (m := re.search('^=+ (?P<section>[A-Z]+) REG \\((?P<driver>[a-z0-9]+)\\) =+$', header_line)) is None:
            raise RuntimeError(f"Invalid header: {header_line}")

        driver = m['driver']
        section = NAME_TO_ANY_REGISTER_SECTION[m['section']]

        value_at_address: Dict[int, bytes] = {}
        for line in lines[1:]:
            if not (m := re.match(
                    '^((?P<section>[A-Za-z]+) REG \\((?P<source>.+)\\) )?(?P<address>0x[0-9a-fA-F]{3}): (?P<values>((0x[0-9a-fA-F]{8}) ?)+)$',
                    line)):
                log.warning(f"Invalid line: {line}")
                continue

            address_offset = int(m['address'], 16)
            for register_value_hex_string in m['values'].split():
                four_bytes = bytearray.fromhex(register_value_hex_string[2:])
                if section.register_length_max == 1:
                    value_at_address[address_offset] = four_bytes
                    address_offset += 1
                else:
                    four_bytes.reverse()
                    for offset_within_register in range(section.register_length_max):
                        value_at_address[address_offset + offset_within_register] = four_bytes[
                                                                                    offset_within_register:offset_within_register + 1]
                    address_offset += 4

        return Dump(driver, section, value_at_address, dump_file.name)

    @property
    def size(self):
        """Number of bytes in this dump"""
        return sum(len(x) for x in self.address_to_value.values())

    def register_value(self, register: RegisterDescription) -> int:
        if register.depth > 1:
            return int.from_bytes(self.address_to_value[register.base_address], byteorder='big')
        return int.from_bytes([self.address_to_value[x][0] for x in range(register.base_address, register.end_address)],
                              byteorder='little')


class Collection:
    """Collection of register dumps of the same register section"""

    def __init__(self, section: RegisterSection):
        self._section = section
        self._dumps = []

    def add_dump(self, register_dump: Dump):
        if self._dumps:
            if register_dump.size != self._dumps[0].size:
                raise RuntimeError(
                    f"Mismatching byte count: {self._dumps[0].size} vs {register_dump.size}")
            if register_dump.section != self._dumps[0].section:
                raise RuntimeError(
                    f"Mismatching types: {self._dumps[0].section} vs {register_dump.section}")
        self._dumps.append(register_dump)

    @classmethod
    def from_strings(cls, contents: Iterable[RawDump]) -> Dict[str, 'Collection']:
        """Read provided dumps, return mapping from section types to their register dump collections"""
        collection_by_section = {}
        for content in contents:
            dump = Dump.parse_dump(content)
            if dump.section.name not in collection_by_section:
                collection_by_section[dump.section.name] = Collection(dump.section)
            collection_by_section[dump.section.name].add_dump(dump)
        return collection_by_section

    @classmethod
    def from_files(cls, files: Iterable[TextIOWrapper]) -> Dict[str, 'Collection']:
        """Read provided dumps, return mapping from section types to their register dump collections"""
        return Collection.from_strings([RawDump(f.name, f.read()) for f in files])

    @property
    def section(self) -> RegisterSection:
        return self._dumps[0].section

    @property
    def dumps(self) -> List[Dump]:
        return self._dumps

    @property
    def dump_filenames_shortened(self) -> List[str]:
        """Filenames with (some of) the common prefix eliminated"""
        common_prefix = os.path.commonprefix([dump.name for dump in self._dumps])
        if (slash_index := common_prefix.rfind('/')) != -1:
            to_remove = common_prefix[:slash_index + 1]
        else:
            to_remove = common_prefix
        return [d.name[len(to_remove):] for d in self._dumps]

    def get_mismatching_addresses(self) -> Set[int]:
        """Addresses on whose value the dumps differ"""
        if not self._dumps:
            raise RuntimeError('Need at least one register dump!')
        first_dump = self._dumps[0]
        mismatching_addresses = set()
        # For every address
        for address in first_dump.address_to_value:
            a = first_dump.address_to_value[address]
            for current_dump in self._dumps[1:]:
                b = current_dump.address_to_value[address]
                if a != b and address not in mismatching_addresses:
                    mismatching_addresses.add(address)
        return mismatching_addresses

    def get_value_mismatches_by_address(self) -> Dict[int, bytes]:
        """Bitmask for ever addresses, indicating differences between the dumps"""
        if not self._dumps:
            raise RuntimeError('Need at least one register dump!')
        first_dump = self._dumps[0]
        addresses_and_their_disagreeing_bits = {}
        for address in first_dump.address_to_value:
            delta = bytes(len(first_dump.address_to_value[address]))
            a = first_dump.address_to_value[address]
            for current_dump in self._dumps[1:]:
                b = current_dump.address_to_value[address]
                if a == b:
                    continue
                xor = bytes(a ^ b for a, b in zip(a, b))
                delta = bytes(a | b for a, b in zip(xor, delta))
            if int.from_bytes(delta, byteorder='little') != 0:
                addresses_and_their_disagreeing_bits[address] = delta
        return addresses_and_their_disagreeing_bits
