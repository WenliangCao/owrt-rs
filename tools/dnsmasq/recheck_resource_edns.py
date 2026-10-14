#!/usr/bin/env python3
"""Prepare audit-C clients with OPT so local REFUSED includes its EDE cause.

This is a diagnostic variant, never a substitute for the unchanged load run.
The original answer checker already consumes additional records. Every failed
answer is retained, including its complete OPT/EDE bytes.
"""
import argparse
from pathlib import Path

from predeploy_resource_prepare import prepare, replace_once


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    prepare(args.output)
    source = args.output / 'loadgen.c'
    text = source.read_text()
    text = replace_once(text,
        '  length+=4; if (prefix) write16(c->tx,(unsigned)length);',
        '  length+=4;\n'
        '  /* Recheck diagnostic: empty EDNS0 OPT, UDP size 1232, DO off. */\n'
        '  write16(packet+10,1); memset(packet+length,0,11);\n'
        '  write16(packet+length+1,41); write16(packet+length+3,1232);\n'
        '  length+=11; if (prefix) write16(c->tx,(unsigned)length);')
    source.write_text(text)


if __name__ == '__main__':
    main()
