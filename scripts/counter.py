#!/usr/bin/env python3

import argparse
from collections import Counter
import csv
import os
import subprocess

def read_binary_objdump(filename):
    
    # TODO: Add check=True, exception handling
    ret = subprocess.run(["objdump", "-d", "--no-show-raw-insn", filename],
                         stdout=subprocess.PIPE,
                         universal_newlines=True)
    return ret.stdout.split(os.linesep)

def parse_objdump(raw_data):

    # Eliminate all empty lines
    data = [line for line in raw_data if line]

    # Eliminate first line (file info)
    data = data[1:]

    # Eliminate all "Disassembly of section XXXX" lines
    data = [line for line in data if "Disassembly of section" not in line]

    # Eliminate all function declarations
    data = [line for line in data if len(line.split()) > 2]

    # We need to just get the 2nd "column" of data (containing the instruction)
    data = [line.split()[1] for line in data]

    # Now to sanitize:
    #   (1) Replace all "data16" with "nopw"
    data = ["nopw" if datum == "data16" else datum for datum in data]

    return dict(Counter(data))

def to_csv(data, outfile):
    with open(outfile, "w") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["instruction", "count"])
        for inst, count in sorted(data.items()):
            writer.writerow([inst, count])

def pretty_print(data):
    for inst, count in sorted(data.items()):
        print(inst, count)

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Instruction Counter")
    parser.add_argument("binary",
                        help="Name of binary file")
    parser.add_argument("--output", "-o",
                        help="Name of output CSV file")
    args = parser.parse_args()
    
    raw_data = read_binary_objdump(args.binary)
    data = parse_objdump(raw_data)
    if args.output:
        to_csv(data, args.output)
    else:
        pretty_print(data)
