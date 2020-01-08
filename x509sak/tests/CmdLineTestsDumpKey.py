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

from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.tests.BaseTest import BaseTest, ResourceFileLoader

class CmdLineTestsDumpKey(BaseTest):
	def test_dump_rsa_privkey(self):
		with ResourceFileLoader("privkey/ok/rsa_768.pem") as keyfile:
			output = self._run_x509sak([ "dumpkey", keyfile ]).stdout
		self.assertIn(b"768 bit RSA private key", output)
		self.assertIn(b"p = 0xf918e2f126754ce0eaee977d800c", output)
		self.assertIn(b"q = 0xec3e0a0cf644a2ea4a2bd0dd47d6", output)
		self.assertIn(b"d = 0x114ac524f66671a3f18a4778f4b6b9", output)
		self.assertIn(b"e = 0x10001", output)

	def test_dump_rsa_pubkey(self):
		with ResourceFileLoader("pubkey/ok/rsa_768.pem") as keyfile:
			output = self._run_x509sak([ "dumpkey", "--public-key", keyfile ]).stdout
		self.assertIn(b"768 bit RSA public key", output)
		self.assertIn(b"n = 0xe5df4f04db84354c15180af8034e", output)
		self.assertIn(b"e = 0x10001", output)

	def test_dump_ecc_privkey(self):
		with ResourceFileLoader("privkey/ok/ecc_secp256r1.pem") as keyfile:
			output = self._run_x509sak([ "dumpkey", "--key-type", "ecc", keyfile ]).stdout
		self.assertIn(b"ECC private key on prime256v1", output)
		self.assertIn(b"(x, y) = (0x4774531f884fd64bf4ad6f2eaf6f1b777b5f4e163c6a354449af98bb3151d2af, 0x4b17e06b9f14831069356e9f5f511163a1a7032c59d8bbea304339ac86d84cb5)", output)
		self.assertIn(b"d = 0x403ae4dc0ec5671c9eae4fa5fec04170a1a5fef7968190904fcfa874c90d6664", output)

	def test_dump_ecc_pubkey(self):
		with ResourceFileLoader("pubkey/ok/ecc_secp256r1.pem") as keyfile:
			output = self._run_x509sak([ "dumpkey", "--key-type", "ecc", "--public-key", keyfile ]).stdout
		self.assertIn(b"ECC public key on prime256v1", output)
		self.assertIn(b"(x, y) = (0x4774531f884fd64bf4ad6f2eaf6f1b777b5f4e163c6a354449af98bb3151d2af, 0x4b17e06b9f14831069356e9f5f511163a1a7032c59d8bbea304339ac86d84cb5)", output)

	def test_dump_eddsa_pubkey(self):
		with ResourceFileLoader("pubkey/ok/eddsa_ed25519.pem") as keyfile:
			output = self._run_x509sak([ "dumpkey", "--key-type", "eddsa", "--public-key", keyfile ]).stdout_text
		self.assertIn("ECC public key on Twisted Edwards", output)
		self.assertIn("25519", output)
		# Data generated from EdDSA RFC sample code
		(x, y) = (41813759258201104901177976525237306556409505649727048514495581204412188724937, 31506162238578656787028761145192509467375405779266640356453115396763494432732)
		self.assertIn("(x, y) = (0x%x, 0x%x)" % (x, y), output)

	def test_dump_eddsa_privkey(self):
		with ResourceFileLoader("privkey/ok/eddsa_ed25519.pem") as keyfile:
			output = self._run_x509sak([ "dumpkey", "--key-type", "eddsa", keyfile ]).stdout_text
		self.assertIn("ECC private key on Twisted Edwards", output)
		self.assertIn("25519", output)
		# Data generated from EdDSA RFC sample code
		(x, y) = (41813759258201104901177976525237306556409505649727048514495581204412188724937, 31506162238578656787028761145192509467375405779266640356453115396763494432732)
		a = 44908355547921110221441252462696832399707573104554503641423314681972008958608
		self.assertIn("(x, y) = (0x%x, 0x%x)" % (x, y), output)
		self.assertIn("a = 0x%x" % (a), output)
