import pytest

from register import RegisterMap, NAME_TO_RF_REGISTER_SECTION
from register_diff import RegisterDiffer
from register_dump import RawDump, Collection

rf_reg_dump_1 = """======== RF REG (rtl8xxxu) =======
RF REG (debugfs) 0x000: 0x00000000 0x00011111 0x00022222 0x000EEEEE"""

rf_reg_dump_2 = """======== RF REG (rtl8192cu) =======
RF REG (debugfs) 0x000: 0x00012345 0x00011111 0x00022222 0x000FFFFF"""

rf_reg_definitions = """/* RF6052 registers */
#define RF6052_REG_AC			0x00
#define  AC_BIT_FIELD_0			BIT(0)
#define  AC_BIT_FIELD_4			BIT(4)
#define RF6052_REG_IQADJ_G1		0x01
#define RF6052_REG_IQADJ_G2		0x02
#define RF6052_REG_BS_PA_APSET_G1_G4	0x03
"""


@pytest.fixture
def register_map_rf() -> RegisterMap:
    return RegisterMap.from_rtl8xxxu_header(rf_reg_definitions, NAME_TO_RF_REGISTER_SECTION['RF'])


@pytest.fixture
def register_dump_collection_rf():
    return Collection.from_strings([RawDump('experiments/2021-12-12/rf_reg_dump', rf_reg_dump_1),
                                    RawDump('experiments/2021-12-13/rf_reg_dump', rf_reg_dump_2)])['RF']


def test_register_dump_collection_short_filenames(register_dump_collection_rf):
    assert register_dump_collection_rf.dump_filenames_shortened == ['2021-12-12/rf_reg_dump', '2021-12-13/rf_reg_dump']


def test_mismatching_addresses(register_dump_collection_rf):
    assert register_dump_collection_rf.get_value_mismatches_by_address() == {
        0x0: bytearray.fromhex("00 01 23 45"),
        0x3: bytearray.fromhex("00 01 11 11"),
    }


def test_register_differ(register_dump_collection_rf, register_map_rf):
    rg = RegisterDiffer(register_dump_collection_rf, register_map_rf)
    names_of_relevant_registers = {r.name for r in rg.get_mismatching_registers()}
    assert names_of_relevant_registers == {'AC', 'BS_PA_APSET_G1_G4'}


def test_mismatching_calculation(register_dump_collection_rf, register_map_rf):
    rg = RegisterDiffer(register_dump_collection_rf, register_map_rf)
    expected = {
        0x0000: {
            'name': 'AC',
            'bitmask': 0xFFFFFFFF,
            'nibbles': 8,
            'values': [0x00000000, 0x00012345],
            'hint': '',
            'fields': [
                {
                    'name': 'AC_BIT_FIELD_0',
                    'bitmask': 0x1,
                    'nibbles': 1,
                    'values': [0x0, 0x1],
                    'hint': '',
                },
                {
                    'name': 'unknown',
                    'bitmask': 0xFFFFFFEE,
                    'nibbles': 8,
                    'values': [0x00000000, (0x00012344 >> 1)],
                    'hint': '',
                },
            ]
        },
        0x0003: {
            'name': 'BS_PA_APSET_G1_G4',
            'bitmask': 0xFFFFFFFF,
            'nibbles': 8,
            'values': [0x000EEEEE, 0x000FFFFF],
            'hint': '',
            'fields': []
        },
    }
    actual = rg.get_mismatching()
    assert actual == expected
