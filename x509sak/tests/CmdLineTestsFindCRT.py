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

from x509sak.tests import BaseTest, ResourceFileLoader

class CmdLineTestsFindCRT(BaseTest):
	def test_find_all(self):
		with ResourceFileLoader([ "certs/ok/johannes-bauer.com.pem", "certs/ok/johannes-bauer-root.pem", "certs/ok/pubkey_sig_ed25519.pem", "certs/ok/ecc_secp256r1.pem" ]) as srcdir:
			stdout = self._run_x509sak([ "find", srcdir ]).stdout
			self.assertOcurrences(stdout, b"BEGIN CERTIFICATE", 4)

	def test_find_specific(self):
		with ResourceFileLoader([ "certs/ok/johannes-bauer.com.pem", "certs/ok/johannes-bauer-root.pem", "certs/ok/pubkey_sig_ed25519.pem", "certs/ok/ecc_secp256r1.pem" ]) as srcdir:
			stdout = self._run_x509sak([ "find", "-h", "853e", srcdir ]).stdout
			self.assertIn(b"853ecf1f70c5f7db4d3883f3f217a9a06ec29445839e9c6acbcf69a399ecaea9", stdout)
			self.assertOcurrences(stdout, b"BEGIN CERTIFICATE", 1)

	def test_find_none(self):
		with ResourceFileLoader([ "certs/ok/johannes-bauer.com.pem", "certs/ok/johannes-bauer-root.pem", "certs/ok/pubkey_sig_ed25519.pem", "certs/ok/ecc_secp256r1.pem" ]) as srcdir:
			stdout = self._run_x509sak([ "find", "-h", "abcdef112233", srcdir ]).stdout
			self.assertEqual(b"", stdout)
