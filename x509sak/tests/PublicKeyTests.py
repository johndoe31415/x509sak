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

from x509sak.tests import BaseTest

class PublicKeyTests(BaseTest):
	def test_rsa_pubkey(self):
		pubkey = self._load_pubkey("johannes-bauer-intermediate.crt")
		self.assertEqual(pubkey.e, 65537)
		self.assertEqual(pubkey.n, 0x9cd30cf05ae52e47b7725d3783b3686330ead735261925e1bdbe35f170922fb7b84b4105aba99e350858ecb12ac468870ba3e375e4e6f3a76271ba7981601fd7919a9ff3d0786771c8690e9591cffee699e9603c48cc7eca4d7712249d471b5aebb9ec1e37001c9cac7ba705eace4aebbd41e53698b9cbfd6d3c9668df232a42900c867467c87fa59ab8526114133f65e98287cbdbfa0e56f68689f3853f9786afb0dc1aef6b0d95167dc42ba065b299043675806bac4af31b9049782fa2964f2a20252904c674c0d031cd8f31389516baa833b843f1b11fc3307fa27931133d2d36f8e3fcf2336ab93931c5afc48d0d1d641633aafa8429b6d40bc0d87dc393)

	def test_rsa_keyid(self):
		pubkey = self._load_pubkey("johannes-bauer-intermediate.crt")
		self.assertEqual(pubkey.keyid(), bytes.fromhex("A84A6A63047DDDBAE6D139B7A64565EFF3A8ECA1"))

	def test_ecc_pubkey(self):
		pubkey = self._load_pubkey("johannes-bauer.com.crt")
		self.assertEqual(pubkey.curve, "secp384r1")
		self.assertEqual(pubkey.x, 0x53559b24a6bf90e6533c957915ec2a5580a07fcb77571e798986869b446b012ff219f8c0b30628d95bc9de795a54df11)
		self.assertEqual(pubkey.y, 0x50a9a4ffecb67f74485cc85bd5218a6c06ea20f3fdbb41aae225c3789f5acdf65544a3b4d519b6ed6f09553afbc26e84)

	def test_ecc_keyid(self):
		pubkey = self._load_pubkey("johannes-bauer.com.crt")
		self.assertEqual(pubkey.keyid(), bytes.fromhex("1A4AB011B05CFA57FB49028765169337F78D8EE6"))
