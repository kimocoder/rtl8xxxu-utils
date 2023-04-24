#!/usr/bin/env python3
import argparse
import logging
import sys

from rtl8xxxu.register import register_maps_from_header
from rtl8xxxu.register_diff import RegisterDiffer
from rtl8xxxu.register_dump import Collection

log = logging.getLogger('register-diff')

"""
Usage: ./rtl8xxxu_regdiff /path/to/rtl8xxxu_reg.h header [path to register dump] [[path to register dump] ... ]
"""


def main():
    parser = argparse.ArgumentParser(description='Print changes between register dumps')
    parser.add_argument('header', metavar='<register header file>', type=argparse.FileType('r'),
                        help='rtl8xxxu.h file to parse')
    parser.add_argument('dump',
                        metavar='<register dump file>',
                        type=argparse.FileType('r'),
                        action='append',
                        help='First register dump file to parse')
    parser.add_argument('dump',
                        metavar='<register dump file>',
                        type=argparse.FileType('r'),
                        nargs='+',
                        action='extend',
                        help='register dump files to parse')
    parser.add_argument('-v', '--verbose',
                        dest='verbose_count',
                        action='count',
                        default=0,
                        help='Increase log verbosity for each occurrence (up to 3).')
    args = parser.parse_args()
    log_level = max(3 - args.verbose_count, 1) * 10
    log.setLevel(log_level)
    log.info(f"Setting logging level to {log_level}")

    register_maps_by_section_name = register_maps_from_header(args.header.readlines())
    dump_collections_by_section_name = Collection.from_files(args.dump)
    for table_index, (section_name, dump_collection) in enumerate(dump_collections_by_section_name.items()):
        rg = RegisterDiffer(dump_collection, register_maps_by_section_name[section_name])
        if table_index:
            print('')
        rg.print_tabular()


if __name__ == '__main__':
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stderr)
    log.addHandler(handler)
    main()
