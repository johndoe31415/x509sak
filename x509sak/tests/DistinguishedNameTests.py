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

import base64
import pyasn1.codec.der.decoder
from pyasn1_modules import rfc2459
from x509sak.tests import BaseTest
from x509sak.OID import OIDDB
from x509sak.DistinguishedName import RelativeDistinguishedName, DistinguishedName

class DistinguishedNameTests(BaseTest):
	def test_simple_rdn_1(self):
		rdn1 = RelativeDistinguishedName.create("CN", "Rick Astley")
		rdn2 = RelativeDistinguishedName.create("CN", "Rick Astley")
		rdn3 = RelativeDistinguishedName.create("CN", "Darude")
		self.assertEqual(rdn1, rdn2)
		self.assertNotEqual(rdn1, rdn3)
		self.assertEqual(rdn1.rfc2253_str, "CN=Rick Astley")

	def test_simple_mvrdn_1(self):
		# Order of elements in RDN does not matter
		rdn = RelativeDistinguishedName.create("CN", "Rick Astley", "OU", "Infinite Persistence Systems Inc.")
		self.assertIn(rdn.rfc2253_str, [ "CN=Rick Astley+OU=Infinite Persistence Systems Inc.", "OU=Infinite Persistence Systems Inc.+CN=Rick Astley" ])

	def test_simple_mvrdn_2(self):
		rdn = RelativeDistinguishedName.create("CN", "Rick Astley", "CN", "Foo Bar")
		self.assertIn(rdn.rfc2253_str, [ "CN=Rick Astley+CN=Foo Bar", "CN=Foo Bar+CN=Rick Astley" ])

	def test_simple_dn_1(self):
		elements = [ RelativeDistinguishedName.create("CN", "Rick Astley") ]
		dn = DistinguishedName(elements)
		self.assertEqual(dn.rfc2253_str, "CN=Rick Astley")

	def test_simple_dn_2(self):
		elements = [ RelativeDistinguishedName.create("CN", "Rick Astley"), RelativeDistinguishedName.create("OU", "Infinite Persistence Systems Inc.") ]
		dn1 = DistinguishedName(elements)
		self.assertEqual(dn1.rfc2253_str, "OU=Infinite Persistence Systems Inc.,CN=Rick Astley")

		elements = [ RelativeDistinguishedName.create("OU", "Infinite Persistence Systems Inc."), RelativeDistinguishedName.create("CN", "Rick Astley") ]
		dn2 = DistinguishedName(elements)
		self.assertEqual(dn2.rfc2253_str, "CN=Rick Astley,OU=Infinite Persistence Systems Inc.")

		self.assertNotEqual(dn1, dn2)

	def test_simple_dn_3(self):
		elements = [ RelativeDistinguishedName.create("CN", "Rick Astley"), RelativeDistinguishedName.create("CN", "Foo Bar"), RelativeDistinguishedName.create("OU", "OrgUnit"), RelativeDistinguishedName.create("CN", "Bar Foo") ]
		dn = DistinguishedName(elements)
		self.assertEqual(dn.rfc2253_str, "CN=Bar Foo,OU=OrgUnit,CN=Foo Bar,CN=Rick Astley")

	def test_json_DNs(self):
		for testcase in self._load_json("misc/dn_tests.json"):
			rdn_sequence_derdata = base64.b64decode(testcase["rdn_sequence"].encode())
			(rdn_sequence_asn1, _) = pyasn1.codec.der.decoder.decode(rdn_sequence_derdata, asn1Spec = rfc2459.Name())
			dn = DistinguishedName.from_asn1(rdn_sequence_asn1)
			self.assertEqual(dn.rfc2253_str, testcase["rfc2253"])
