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

import datetime
from x509sak.tests import BaseTest

from x509sak.OtherModels import SignedCertificateTimestampList, SCTVersion
from x509sak.tls.Enums import SignatureAlgorithm, HashAlgorithm
from x509sak.HexDump import HexDump

class OtherModelsTests(BaseTest):
	def test_serialize_sctl(self):

		ts = round(datetime.datetime(2020, 1, 1, 12, 34, 56).timestamp() * 1000)

		sstl = {
			"payload": [
				{ "sct":
					{
						"sct_version":		SCTVersion.v1,
						"log_id":			bytes(range(32)),
						"timestamp":		ts,
						"extensions":		bytes(),
						"DigitalSignature": {
							"hash_algorithm":	HashAlgorithm.sha256,
							"sig_algorithm":	SignatureAlgorithm.ED25519,
							"signature":		bytes(range(64)),
						},
					}
				},
			],
		}
		serialized_data = SignedCertificateTimestampList.pack(sstl)

		expect_payload = bytes.fromhex("""
			0071
				006f
					00
					000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
					00 00 01 6f 60 e3 23 00
					0000

					04
					07
					0040
						000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
		""".replace("\n", "").replace("\t", "").replace(" ", ""))
		HexDump().dump(expect_payload)
		HexDump().dump(serialized_data)
		self.assertEqual(expect_payload, serialized_data)
