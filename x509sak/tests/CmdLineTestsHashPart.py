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

import tempfile
from x509sak.tests import BaseTest, ResourceFileLoader

class CmdLineTestsHashPart(BaseTest):
	def test_simple_hash(self):
		with ResourceFileLoader("certs/ok/johannes-bauer.com.pem") as infile:
			result = self._run_x509sak([ "hashpart", "-l", "3", "-h", "md5", infile ])
			self.assertIn("cfab1ba8c67c7c838db98d666f02a132", result.stdout_text)		# md5("--")
			lines = result.stdout_text.split("\n")[:-1]
			self.assertEqual(len(lines), 6)

	def test_hash_search1(self):
		with ResourceFileLoader("certs/ok/johannes-bauer.com.pem") as infile:
			result = self._run_x509sak([ "hashpart", "-o", "20", "-l", "20", "-s", "af620e0", "-h", "md5", infile ])
			self.assertIn("602223a041eaf620e00527d2c0a8cb31", result.stdout_text)
			lines = result.stdout_text.split("\n")[:-1]
			self.assertEqual(len(lines), 1)

	def test_hash_search2(self):
		with ResourceFileLoader("certs/ok/johannes-bauer.com.pem") as infile:
			result = self._run_x509sak([ "hashpart", "-o", "100", "-l", "20", "-s", "0000", "-h", "sha1", "-h", "shake_256", infile ])
			self.assertIn("b2736f6e448f6b6971a1e8ad5000009bf48752d1", result.stdout_text)
			self.assertIn("e96fe7bce088755d56506ab6238fd4c8a3a2cda6e9ddf9af58a0c79bebce02815c26731cad30bf0000b72acd5b5b5842", result.stdout_text)
			lines = result.stdout_text.split("\n")[:-1]
			self.assertEqual(len(lines), 2)

	def test_hash_der_cert(self):
		cert = self._load_crt("ok/pubkey_sig_ed25519")
		with tempfile.NamedTemporaryFile(prefix = "cert_", suffix = ".der") as certfile:
			certfile.write(cert.der_data)
			certfile.flush()
			result = self._run_x509sak([ "hashpart", "-s", "6403FEE102060D6C6907473A9115583AD83C9B90", certfile.name ])
			self.assertIn("sha1 0x94 0xb4 0x20 6403fee102060d6c6907473a9115583ad83c9b90", result.stdout_text)
			lines = result.stdout_text.split("\n")[:-1]
			self.assertEqual(len(lines), 1)
