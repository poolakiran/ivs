#!/usr/bin/python
############################################################
#
#
#
############################################################
import os
import sys
import json
import argparse

if len(sys.argv) != 3:
    sys.stderr.write("Usage: %s <asre-json> <outputformat>\n" % sys.argv[0])
    sys.exit(1)

ap = argparse.ArgumentParser(description="ASRE Formatter.")
ap.add_argument("json", help="ASRE JSON Input File.")
ap.add_argument("format", choices=['html', 'text'])
ops = ap.parse_args()

ASRE=json.load(open(ops.json))

if 'text' in ops.format:
    for entry in ASRE:
        print "Level:  %s" % entry['level']
        print "Format: %s" % entry['format']
        print "Doc:    %s" % entry['doc']
        print
elif 'html' in ops.format:
    raise Exception("HTML format is not implemented.")
