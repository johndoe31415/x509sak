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

input_dir = "examine"

unknown_ext = { }
for (dirname, subdirs, files) in os.walk(input_dir):
	for filename in files:
		if not filename.endswith(".json"):
			continue
		ffilename = dirname + "/" + filename
		with open(ffilename) as f:
			data = json.load(f)
		for ext in data["data"][0]["extensions"]["individual"]:
			if not ext["known"]:
				unknown_ext[ext["oid"]] = ffilename

print("Currently unknown X.509 extensions:")
for (oid, jsonfile) in sorted(unknown_ext.items()):
	print("%-30s %s" % (oid, jsonfile))

