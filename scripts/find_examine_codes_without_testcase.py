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
from x509sak.FriendlyArgumentParser import FriendlyArgumentParser

class ResultCollector():
	def __init__(self, args):
		self._args = args
		self._all_codes = set(code.name for code in x509sak.estimate.Judgement.JudgementCode)
		self._errors = [ ]
		self._encountered_certs = { }

	def _analyze(self, codes, data):
		if isinstance(data, dict):
			if "code" in data:
				codes.add(data["code"])
			for (key, value) in data.items():
				self._analyze(codes, value)
		elif isinstance(data, list):
			for item in data:
				self._analyze(codes, item)

	def run(self, basefilename, filename):
		# try to load certificate from file
		try:
			cert = x509sak.X509Certificate.read_pemfile(filename)
		except x509sak.Exceptions.UnexpectedFileContentException:
			return None

		print(filename, file = sys.stderr)
		output = subprocess.check_output([ "./x509sak.py", "examine", "-f", "json", filename ], stderr = subprocess.DEVNULL)
		json_data = json.loads(output)

		encountered_codes = set()
		self._analyze(encountered_codes, json_data)
		return (basefilename, encountered_codes)


	def finished_callback(self, call_args, result):
		if result is None:
			return
		(basefilename, encountered_codes) = result
		for encountered_code in encountered_codes:
			if encountered_code not in self._encountered_certs:
				self._encountered_certs[encountered_code] = (basefilename, None)

	def _dump_errors(self):
		if len(self._errors) == 0:
			return
		print("%d files produced errors:" % (len(self._errors)))
		for filename in sorted(self._errors):
			print("    %s" % (filename))
		print()

	def _dump_codes(self, codes, scantype):
		if len(set(codes) - self._all_codes) != 0:
			raise Exception("Found codes as encountered that are not defined (%s). Re-run test suite?" % (", ".join(sorted(set(codes) - self._all_codes))))

		missing = self._all_codes - set(codes)
		print("%s: %d of %d codes seen (%.1f%%), %d missing (%.1f%%):" % (scantype, len(codes), len(self._all_codes), len(codes) / len(self._all_codes) * 100, len(missing), len(missing) / len(self._all_codes) * 100))
		for codename in sorted(missing):
			if codename in self._all_scans:
				(certfile, ca_certfile) = self._all_scans[codename]
				if ca_certfile is None:
					print("    %s (%s)" % (codename, certfile))
				else:
					print("    %s (%s with CA %s)" % (codename, certfile, ca_certfile))
			else:
				print("    %s" % (codename))
		print()

	def dump(self):
		try:
			with open(".examinecert_stats.json") as f:
				local_stats = json.load(f)
		except (FileNotFoundError, json.JSONDecodeError):
			# No stat file available
			print("No stat file available, not checking against testcases that ran.", file = sys.stderr)
			local_stats = False

		self._all_scans = dict(self._encountered_certs)
		if local_stats is not None:
			self._all_scans.update(local_stats["encountered_codes"])
			self._all_scans.update(local_stats["checked_codes"])

		if self._args.scan:
			self._dump_errors()
			self._dump_codes(self._encountered_certs, "Local certificate scan")

		self._dump_codes(local_stats["encountered_codes"], "Testcases encountered")
		self._dump_codes(local_stats["checked_codes"], "Testcases specifically tested for")


	def add_codes(self, codes):
		self._codes |= set(codes)

parser = FriendlyArgumentParser(description = "Find untested result codes for the examinecert facility.")
parser.add_argument("-s", "--scan", action = "store_true", help = "Scan all certificates in the test/ subdirectory as well to find out which codes would be emitted")
args = parser.parse_args(sys.argv[1:])

rc = ResultCollector(args)
parallelizer = Parallelizer()
if args.scan:
	base_dir = "x509sak/tests/data"
	for (dirname, subdirs, files) in os.walk(base_dir):
		for filename in sorted(files):
			if not (filename.endswith(".pem") or filename.endswith(".crt")):
				continue

			full_filename = dirname + "/" + filename
			base_filename = full_filename[len(base_dir) + 1 : ]
			parallelizer.run(rc.run, args = (base_filename, full_filename), finished_callback = rc.finished_callback)
parallelizer.wait()
rc.dump()
