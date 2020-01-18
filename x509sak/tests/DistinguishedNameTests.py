#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2020 Johannes Bauer
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
from x509sak.Exceptions import InvalidInputException
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

	def test_decoded_asn1_different_types(self):
		(utf8, _) = pyasn1.codec.der.decoder.decode(bytes.fromhex("30 16 31 14 30 12 06 03 55 04 03 0c 0b 43 6f 6d 6d 6f 6e 20 4e 61 6d 65"), asn1Spec = rfc2459.Name())
		(ia5, _) = pyasn1.codec.der.decoder.decode(bytes.fromhex("30 16 31 14 30 12 06 03 55 04 03 16 0b 43 6f 6d 6d 6f 6e 20 4e 61 6d 65"), asn1Spec = rfc2459.Name())
		utf8dn = DistinguishedName.from_asn1(utf8)
		ia5dn = DistinguishedName.from_asn1(ia5)
		self.assertEqual(utf8dn, ia5dn)

	def test_decoded_asn1_different_types_umlaut(self):
		(utf8, _) = pyasn1.codec.der.decoder.decode(bytes.fromhex("30 17 31 15 30 13 06 03 55 04 03 0c 0c 43 c3 b6 6d 6d 6f 6e 20 4e 61 6d 65"), asn1Spec = rfc2459.Name())
		(bmp, _) = pyasn1.codec.der.decoder.decode(bytes.fromhex("30 21 31 1f 30 1d 06 03 55 04 03 1e 16 00 43 00 f6 00 6d 00 6d 00 6f 00 6e 00 20 00 4e 00 61 00 6d 00 65"), asn1Spec = rfc2459.Name())
		utf8dn = DistinguishedName.from_asn1(utf8)
		bmpdn = DistinguishedName.from_asn1(bmp)
		self.assertEqual(utf8dn, bmpdn)

	def test_equality_rdn(self):
		rdn1 = RelativeDistinguishedName.create("CN", "Foo", "O", "Bar")
		rdn2 = RelativeDistinguishedName.create("O", "Bar", "CN", "Foo")
		self.assertEqual(rdn1, rdn2)

	def test_equality_dn(self):
		dn1 = DistinguishedName([ RelativeDistinguishedName.create("CN", "Foo"), RelativeDistinguishedName.create("CN", "Bar") ])
		dn2 = DistinguishedName([ RelativeDistinguishedName.create("CN", "Bar"), RelativeDistinguishedName.create("CN", "Foo") ])
		dn3 = DistinguishedName([ RelativeDistinguishedName.create("CN", "Foo"), RelativeDistinguishedName.create("CN", "Bar") ])
		self.assertNotEqual(dn1, dn2)
		self.assertEqual(dn1, dn3)

	def test_string_parse(self):
		dn = DistinguishedName.from_rfc2253_str("cn=foo,ou=bar,o=koo")
		self.assertEqual(dn, DistinguishedName([ RelativeDistinguishedName.create("CN", "foo"), RelativeDistinguishedName.create("OU", "bar"), RelativeDistinguishedName.create("O", "koo") ]))

		dn = DistinguishedName.from_rfc2253_str("cn=foo,ou=bar,o=koo+ou=moo")
		self.assertEqual(dn, DistinguishedName([ RelativeDistinguishedName.create("CN", "foo"), RelativeDistinguishedName.create("OU", "bar"), RelativeDistinguishedName.create("O", "koo", "OU", "moo") ]))

		dn = DistinguishedName.from_rfc2253_str("")
		self.assertEqual(dn, DistinguishedName([ ]))

	def test_string_parse_fail(self):
		with self.assertRaises(InvalidInputException):
			DistinguishedName.from_rfc2253_str("/")

		with self.assertRaises(InvalidInputException):
			DistinguishedName.from_rfc2253_str("CN,OU=bar")

		with self.assertRaises(InvalidInputException):
			DistinguishedName.from_rfc2253_str("MUH=KUH")
