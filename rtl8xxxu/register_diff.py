import math
from typing import Dict, Set, List

from tabulate import tabulate

from register import RegisterMap, RegisterDescription
from register_dump import Collection


class RegisterDiffer:
    """Diffs multiple dumps, print easy-to-understand breakdown of involved registers and their values"""

    def __init__(self, dump_collection: Collection, register_map: RegisterMap):
        if dump_collection.section != register_map.section:
            raise RuntimeError(
                f'Section mismatch between dump ({dump_collection.section}) and map ({register_map.section})')
        self.dump_collection = dump_collection
        self.register_map: RegisterMap = register_map

    def get_mismatching_registers(self) -> Set[RegisterDescription]:
        """Set of all registers having values which differ between register dumps"""
        mismatching_registers = set()
        for address in self.dump_collection.get_mismatching_addresses():
            r = self.register_map.register_at_address(address)
            mismatching_registers.add(r)
        return mismatching_registers

    def get_mismatching_register_values(self, register: RegisterDescription) -> List[int]:
        return [dump.register_value(register) for dump in self.dump_collection.dumps]

    def get_mismatching_register_fields_description(self, register: RegisterDescription) -> List[Dict]:
        result = []
        mismatching_register_values = self.get_mismatching_register_values(register)
        for field in register.known_fields:
            values = [field.get_value(register_value) for register_value in mismatching_register_values]
            if len(set(values)) <= 1:
                continue
            result.append({
                'name': field.name,
                'bitmask': field.bitmask,
                'nibbles': math.ceil(field.size / 4),
                'values': values,
                'hint': ''
            })

        # Without known fields, printing the unknown field does not make sense
        if not result:
            return []

        unknown_field = register.unknown_field
        values = [unknown_field.get_value(register_value) for register_value in mismatching_register_values]
        result.append({
            'name': unknown_field.name,
            'bitmask': unknown_field.bitmask,
            'nibbles': register.size * 2,
            'values': values,
            'hint': ''
        })
        return result

    def get_mismatching(self):
        """Nested dictionary with all relevant information for comparing register dumps"""
        result = {}
        for register in self.get_mismatching_registers():
            register_dict = {
                'name': register.name,
                'bitmask': register.bitmask,
                'nibbles': register.size * 2,
                'values': self.get_mismatching_register_values(register),
                'hint': register.hint,
                'fields': self.get_mismatching_register_fields_description(register)
            }
            result[register.base_address] = register_dict
        return result

    def print_tabular(self):
        print(f'# Register value delta analysis for {self.register_map.section.name} registers')
        print('## Inputs ')
        for index, short_filename in enumerate(self.dump_collection.dump_filenames_shortened):
            print(f' - #{index}: {short_filename}')

        disagreeing_registers = self.get_mismatching()
        if len(disagreeing_registers) == 0:
            print('Dumps do not differ')
            return

        header = ['**Address**', '**Name**', 'Mask']
        header += [f'**#{index}: {dump.driver_name}**' for index, dump in enumerate(self.dump_collection.dumps)]
        header += ['**Hint**']
        rows = []
        for address, register in sorted(disagreeing_registers.items()):
            rows.append([f'0x{address:X}', register['name'], f'0x{register["bitmask"]:X}'])
            rows[-1] += [f'0x{register_value:0{register["nibbles"]}X}' for register_value in register['values']]
            rows[-1] += [register['hint']]
            for field in register['fields']:
                rows.append(['', field['name'], f'0x{field["bitmask"]:X}'])
                rows[-1] += [f'0x{field_value:0{field["nibbles"]}X}' for field_value in field['values']]
                rows[-1] += [field['hint']]

        print(tabulate(rows, headers=header, tablefmt='orgtbl'))
