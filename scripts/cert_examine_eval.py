#!/usr/bin/python3
#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2018 Johannes Bauer
#
#	This file is part of x509sak.
#
#	x509sak is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	x509sak is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with x509sak; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import os
import json
import collections

input_dir = "examine"

unknown_ext_cnt = collections.Counter()
unknown_ext = { }
code_example = { }
code_cnt = collections.Counter()
total_file_cnt = 0
pubkey_cnt = collections.Counter()
sigfnc_cnt = collections.Counter()

def traverse(ffilename, structure):
	if isinstance(structure, list):
		for item in structure:
			traverse(ffilename, item)
	elif isinstance(structure, dict):
		if "code" in structure:
			code_example[structure["code"]] = ffilename
			code_cnt[structure["code"]] += 1
		for (key, value) in structure.items():
			traverse(ffilename, value)

for (dirname, subdirs, files) in os.walk(input_dir):
	for filename in files:
		if not filename.endswith(".json"):
			continue
		total_file_cnt += 1
		ffilename = dirname + "/" + filename
		with open(ffilename) as f:
			data = json.load(f)
		for ext in data["data"][0]["extensions"]["individual"]:
			if not ext["known"]:
				unknown_ext[ext["oid"]] = ffilename
				unknown_ext_cnt[ext["oid"]] += 1
		traverse(ffilename, data["data"])
		pubkey_cnt[data["data"][0]["pubkey"]["pretty"]] += 1
		sigfnc_cnt[data["data"][0]["signature"]["pretty"]] += 1

print("Analyzed files: %d" % (total_file_cnt))
print("Currently unknown X.509 extensions:")
for (oid, jsonfile) in sorted(unknown_ext.items()):
	print("%6d %-60s %s" % (unknown_extension_cnt[oid], oid, jsonfile))
print()

print("Found codes:")
for (code, count) in code_cnt.most_common():
	print("%6d %-60s %s" % (count, code, code_example[code]))
print()

print("Public keys:")
for (pubkey, count) in pubkey_cnt.most_common():
	print("%6d %5.1f%% %-60s" % (count, count / total_file_cnt * 100, pubkey))
print()

print("Signature functions:")
for (sigfnc, count) in sigfnc_cnt.most_common():
	print("%6d %5.1f%% %-60s" % (count, count / total_file_cnt * 100, sigfnc))
print()
