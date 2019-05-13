#!/usr/bin/env python
'''
python aliases-lpm.py -a [aliasedprefix.txt] -i [input filename] --non-aliased-result=[non-aliased.txt] --aliased-result=[aliased.txt]
'''
from __future__ import print_function

import argparse
import sys

try:
    import SubnetTree
except Exception as e:
    print(e, file=sys.stderr)
    print("Use `pip install pysubnettree` to install the required module", file=sys.stderr)
    sys.exit(1)


def read_non_aliased(tree, fh):
    return fill_tree(tree, fh, ",0")

def read_aliased(tree, fh):
    return fill_tree(tree, fh, ",1")

def fill_tree(tree, fh, suffix):
    for line in fh:
        line = line.strip()
        try:
            tree[line] = line + suffix
        except ValueError as e:
            print("Skipped line '" + line + "'", file=sys.stderr)
    return tree


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--aliased-file", required=True, type=argparse.FileType('r'), help="File containing aliased prefixes")
    #parser.add_argument("-n", "--non-aliased-file", required=True, type=argparse.FileType('r'), help="File containing non-aliased prefixes")
    parser.add_argument("-i", "--ip-address-file", required=True, type=argparse.FileType('r'), help="File containing IP addresses to be matched against (non-)aliased prefixes")
    parser.add_argument("--non-aliased-result", type=str, help="File")
    parser.add_argument("--aliased-result", type=str, help="File")
    args = parser.parse_args()

    # Store aliased and non-aliased prefixes in a single subnet tree
    tree = SubnetTree.SubnetTree()

    # Read aliased and non-aliased prefixes
    tree = read_aliased(tree, args.aliased_file)
    #tree = read_non_aliased(tree, args.non_aliased_file)
    
    f_non = open(args.non_aliased_result, 'w')
    f_alias = open(args.aliased_result, 'w')
    # Read IP address file, match each address to longest prefix and print output
    for line in args.ip_address_file:
        line = line.strip()
        try:
            #print(line + "," + tree[line])
            if line in tree:
                f_alias.write(line + '\n')
            else:
                f_non.write(line + '\n')
            '''    
            isAliased = tree[line]
            if isAliased == 1:
                f_alias.write(line + '\n')
            elif isAliased == 0:
                f_non.write(line + '\n')
            else:
                print(line)
            '''
        except KeyError as e:
            print("Skipped line '" + line + "'", file=sys.stderr)
    f_non.close()
    f_alias.close()
if __name__ == "__main__":
    main()
