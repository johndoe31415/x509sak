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
from x509sak.PrivateKeyStorage import PrivateKeyStorage, PrivateKeyStorageForm
from x509sak.RSAPrivateKey import RSAPrivateKey
from x509sak.ECPrivateKey import ECPrivateKey
from x509sak.EDPrivateKey import EDPrivateKey
from x509sak.Exceptions import UnexpectedFileContentException

class PrivateKeyTests(BaseTest):
	def test_storage_load_key_pem(self):
		with ResourceFileLoader("privkey/ok/ecc_secp256r1.pem", "privkey/ok/eddsa_ed25519_rfc8032.pem", "privkey/ok/eddsa_ed448.pem", "privkey/ok/rsa_768.pem") as privkey_filenames:
			for privkey_filename in privkey_filenames:
				pks = PrivateKeyStorage(PrivateKeyStorageForm.PEM_FILE, filename = privkey_filename)
				privkey = pks.load_private_key()
				self.assertIsInstance(privkey, (RSAPrivateKey, ECPrivateKey, EDPrivateKey))

	def test_storage_load_key_der(self):
		with ResourceFileLoader("privkey/ok/ecc_secp256r1.der", "privkey/ok/eddsa_ed25519_rfc8032.der", "privkey/ok/rsa_768.der") as privkey_filenames:
			for privkey_filename in privkey_filenames:
				pks = PrivateKeyStorage(PrivateKeyStorageForm.DER_FILE, filename = privkey_filename)
				privkey = pks.load_private_key()
				self.assertIsInstance(privkey, (RSAPrivateKey, ECPrivateKey, EDPrivateKey))

	def test_storage_load_fails(self):
		with ResourceFileLoader("certs/ok/johannes-bauer-root.pem") as cert_filename:
			pks = PrivateKeyStorage(PrivateKeyStorageForm.PEM_FILE, filename = cert_filename)
			with self.assertRaises(UnexpectedFileContentException):
				pks.load_private_key()

	def test_eddsa_ed25519_privkey(self):
		with ResourceFileLoader("privkey/ok/eddsa_ed25519.pem") as privkey_filename:
			privkey = EDPrivateKey.read_pemfile(privkey_filename)[0]
			self.assertIn("ed25519", str(privkey).lower())
			self.assertEqual(privkey.priv, bytes.fromhex("6da749b74428d3b57ffe0de0ace76e23205be1ac2d855c92a882fd3596116f95"))
			self.assertFalse(privkey.prehash)
			self.assertEqual(privkey.scalar, 44908355547921110221441252462696832399707573104554503641423314681972008958608)
			self.assertEqual(privkey.cryptosystem.name, "ECC_EdDSA")

			pubkey = privkey.pubkey
			pubkey_point = pubkey.point
			self.assertTrue(pubkey_point.on_curve())
			self.assertEqual(pubkey_point.encode(), bytes.fromhex("dcbfc4d2bd9b5b9b3f7cd673cf559fe3793946a6a904355c07a552991bdba7c5"))
