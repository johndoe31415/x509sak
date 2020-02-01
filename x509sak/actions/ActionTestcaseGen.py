#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2020-2020 Johannes Bauer
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
import sys
import contextlib
import itertools
import subprocess
import collections
from x509sak.BaseAction import BaseAction
from x509sak.X509Certificate import X509Certificate
from x509sak.OID import OID
from x509sak.estimate import JudgementCode
from x509sak.certgen.CertGenerator import CertGenerator
from x509sak.Tools import PEMDataTools

class ActionTestcaseGen(BaseAction):
	_EXPECT_PRESENT_CODEPOINT_OID = OID.from_str("1.13.99.127.41")
	_TCDefinition = collections.namedtuple("TCDefinition", [ "full_name", "filename", "expect_present" ])

	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		sys.setrecursionlimit(10000)
		self._cg = CertGenerator.instantiate(self._args.tcname + ".ader")
		if self._args.list_parameters:
			for (name, values) in sorted(self._cg.parameters):
				print("%-30s %s" % (name, ", ".join(sorted(values))))
			sys.exit(0)

		template_parameters = { }
		for parameter in self._args.parameter:
			(key, value) = parameter.split("=", maxsplit = 1)
			if value == "*":
				template_parameters[key] = self._cg.get_choices(key)
			else:
				template_parameters[key] = [ value ]

		for (name, values) in self._cg.parameters:
			if name not in template_parameters:
				template_parameters[name] = values

		with contextlib.suppress(FileExistsError):
			os.makedirs(self._args.output_dir)

		template_parameters = list(template_parameters.items())
		keys = [ key for (key, values) in template_parameters ]
		values = [ values for (key, values) in template_parameters ]
		self._tcs = [ ]
		for concrete_values in itertools.product(*values):
			concrete_values = dict(zip(keys, concrete_values))
			try:
				self._render(concrete_values)
			except subprocess.CalledProcessError as e:
				print("Failed: %s (%s)" % (str(concrete_values), str(e)))

		self._tcs.sort()
		self._print_tcs()

	@staticmethod
	def testcase_codepoint_string(codepoints):
		if len(codepoints) == 1:
			return "\"%s\"" % (codepoints[0])
		else:
			return "[ " + ", ".join("\"%s\"" % (codepoint) for codepoint in codepoints)  + " ]"

	def _print_tcs(self):
		with open(self._args.output_dir + "/tcs.txt", "w") as f:
			print("# " + ("=" * 70) + " Begin of %s " % (self._args.tcname) + ("=" * 70), file = f)
			for tc in self._tcs:
				print("\tdef %s(self):" % (tc.full_name), file = f)
				print("\t\tself._test_examine_x509test_resultcode(\"%s\", expect_present = %s)" % (tc.filename, self.testcase_codepoint_string(tc.expect_present)), file = f)
				print(file = f)
			print("# " + ("=" * 70) + " End of %s " % (self._args.tcname) + ("=" * 70), file = f)

	def _analyze_pemfile(self, pem_filename):
		x509cert = X509Certificate.read_pemfile(pem_filename)[0]
		present_codepoints = [ rdn.get_value(self._EXPECT_PRESENT_CODEPOINT_OID).printable_value for rdn in x509cert.subject.get_all(self._EXPECT_PRESENT_CODEPOINT_OID) ]
		present_codepoints += [ rdn.get_value(self._EXPECT_PRESENT_CODEPOINT_OID).printable_value for rdn in x509cert.issuer.get_all(self._EXPECT_PRESENT_CODEPOINT_OID) ]

		file_prefix = os.path.basename(pem_filename)[:-4]

		for codepoint_name in present_codepoints:
			try:
				codepoint = getattr(JudgementCode, codepoint_name)
			except AttributeError:
				print("No such codepoint: %s (in %s)" % (codepoint_name, pem_filename))
				return

		tc_filename = "certs/generated/%s/%s" % (self._args.tcname, os.path.basename(pem_filename))
		tc = self._TCDefinition(full_name = "test_generated_%s_%s" % (self._args.tcname, file_prefix), filename = tc_filename, expect_present = present_codepoints)
		self._tcs.append(tc)

	def _render(self, concrete_values):
		if self._args.verbose >= 1:
			print(concrete_values)
		render_result = self._cg.render(concrete_values)
		pem_filename = self._store(render_result)
		if pem_filename is not None:
			self._analyze_pemfile(pem_filename)

	def _store(self, render_result):
		(basename, ascii_der) = render_result

		if self._args.no_pem:
			outfile = self._args.output_dir + "/" + basename + ".ader"
			with open(outfile, "w") as f:
				f.write(ascii_der)
			print(ascii_der)
			return None
		else:
			outfile = self._args.output_dir + "/" + basename + ".pem"
			der_data = subprocess.check_output("ascii2der", input = ascii_der.encode())
			try:
				cert_data = subprocess.check_output([ "openssl", "x509", "-inform", "der", "-text" ], input = der_data)
				cert_data = cert_data.decode()
				cert_data = [ line.rstrip("\t ") for line in cert_data.split("\n") ]
				cert_data = "\n".join(cert_data)
			except subprocess.CalledProcessError as e:
				# OpenSSL cannot encode the certificate
				cert_data = PEMDataTools.data2pem(der_data, marker = "CERTIFICATE")
			with open(outfile, "w") as f:
				f.write(cert_data)
			return outfile
