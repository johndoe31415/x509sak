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
import subprocess
import sys
import x509sak
import x509sak.estimate
from Parallelizer import Parallelizer

class ResultCollector():
	def __init__(self):
		self._errors = [ ]
		self._codes = set()

	def run(self, filename):
		# try to load certificate from file
		try:
			cert = x509sak.X509Certificate.read_pemfile(filename)
		except x509sak.Exceptions.UnexpectedFileContentException:
			return None

		print(filename, file = sys.stderr)
		output = subprocess.check_output([ "./x509sak.py", "examine", "-f", "json", filename ], stderr = subprocess.DEVNULL)
		json_data = json.loads(output)
		return json_data

	def _analyze(self, data):
		if isinstance(data, dict):
			if "code" in data:
				self._codes.add(data["code"])
			for (key, value) in data.items():
				self._analyze(value)
		elif isinstance(data, list):
			for item in data:
				self._analyze(item)

	def finished_callback(self, call_args, result):
		if result is None:
			return
		(filename, ) = call_args
		if isinstance(result, Exception):
			print("Errored: %s (%s: %s)" % (filename, result.__class__.__name__, result), file = sys.stderr)
			self._errors.append(filename)
			return
		self._analyze(result)

	def dump(self):
		print("%d failed:" % (len(self._errors)))
		for filename in sorted(self._errors):
			print("    %s" % (filename))
		print()
		encountered = set(getattr(x509sak.estimate.Judgement.JudgementCode, name) for name in self._codes)
		all_codes = set(x509sak.estimate.Judgement.JudgementCode)
		missing = all_codes - encountered
		print("%d codes encountered, %d total. %d missing:" % (len(encountered), len(all_codes), len(missing)))
		for item in sorted([ code.name for code in missing ]):
			print("    %s" % (item))

	def add_codes(self, codes):
		self._codes |= set(codes)

rc = ResultCollector()
if len(sys.argv) != 2:
	parallelizer = Parallelizer()
	base_dir = "x509sak/tests/data"
	for (dirname, subdirs, files) in os.walk(base_dir):
		for filename in sorted(files):
			if not (filename.endswith(".pem") or filename.endswith(".crt")):
				continue

			full_filename = dirname + "/" + filename
			parallelizer.run(rc.run, args = (full_filename, ), finished_callback = rc.finished_callback)
	parallelizer.wait()
else:
	with open(sys.argv[1]) as f:
		codes = json.load(f)
	rc.add_codes(codes)
rc.dump()
