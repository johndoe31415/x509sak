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

import subprocess
import os
import re
import collections

class CertCreator(object):
	def __init__(self, outdir):
		self._outdir = outdir
		try:
			os.makedirs(self._outdir)
		except FileExistsError:
			pass
		self._subdirs = self._collect_subdirs()
		self._parts = self._collect_parts()

	def _collect_subdirs(self):
		SubDir = collections.namedtuple("SubDir", [ "part_id", "name", "filename" ])
		subdirs = [ ]
		seen_ids = set()
		seen_names = set()
		match_re = re.compile("^(?P<id>\d{2})_(?P<name>.*)")
		for filename in os.listdir("."):
			if not os.path.isdir(filename):
				continue
			result = match_re.match(filename)
			if result is not None:
				result = result.groupdict()
				part_id = int(result["id"])
				name = result["name"]
				if part_id in seen_ids:
					raise Exception("Duplicate part id %d" % (part_id))
				if name in seen_names:
					raise Exception("Duplicate name %s" % (name))
				subdirs.append(SubDir(part_id = part_id, name = name, filename = filename))
		subdirs.sort()
		return subdirs

	def _collect_parts_for_subdir(self, subdir):
		parts = set()
		for filename in os.listdir(subdir.filename):
			full_filename = subdir.filename + "/" + filename
			if os.path.isfile(full_filename):
				parts.add(filename)
		return parts

	def _collect_parts(self):
		parts = { }
		for subdir in self._subdirs:
			parts[subdir.part_id] = self._collect_parts_for_subdir(subdir)
		return parts

	def create(self, output_filename, **kwargs):
		crt_input = ""
		for subdir in self._subdirs:
			choose = subdir.filename + "/" + kwargs.get(subdir.name, "default")
			with open(choose) as f:
				crt_input += f.read()

		der_data = subprocess.check_output([ "ascii2der" ], input = crt_input.encode())
		crt_data = subprocess.check_output([ "openssl", "x509", "-inform", "der", "-text" ], input = der_data)
		with open(self._outdir + "/" + output_filename, "wb") as f:
			f.write(crt_data)

creator = CertCreator(outdir = "output/")
creator.create("normal.pem")
creator.create("long_serial.pem", serial = "long")
