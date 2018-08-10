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
from x509sak.tests import BaseTest

class CmdLineTestsBuildChain(BaseTest):
	def assertOcurrences(self, haystack, needle, expected_count):
		count = haystack.count(needle)
		self.assertEqual(count, expected_count)

	def test_root_only(self):
		output = subprocess.check_output([ "./x509sak.py", "buildchain", "x509sak/tests/data/johannes-bauer-root.crt" ])
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)

	def test_root_notrust(self):
		output = subprocess.check_output([ "./x509sak.py", "buildchain", "--dont-trust-crtfile", "x509sak/tests/data/johannes-bauer-root.crt" ])
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)

	def test_interm_root_notrust(self):
		with  self.assertRaises(subprocess.CalledProcessError):
			subprocess.check_call([ "./x509sak.py", "buildchain", "x509sak/tests/data/johannes-bauer-intermediate.crt" ], stderr = subprocess.DEVNULL)
		output = subprocess.check_output([ "./x509sak.py", "buildchain", "--allow-partial-chain", "x509sak/tests/data/johannes-bauer-intermediate.crt" ])
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)

		output = subprocess.check_output([ "./x509sak.py", "buildchain", "-s", "x509sak/tests/data", "x509sak/tests/data/johannes-bauer-intermediate.crt" ])
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 2)
