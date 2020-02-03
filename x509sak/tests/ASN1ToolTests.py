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

from pyasn1.type.univ import BitString, Integer, OctetString
from pyasn1.type.useful import UTCTime
from pyasn1.type.constraint import ValueRangeConstraint
from x509sak.tests.BaseTest import BaseTest
from x509sak.Tools import ASN1Tools

class BasicASN1Model(Integer): pass
class RestrictiveASN1Model(Integer):
	subtypeSpec = ValueRangeConstraint(100, 199)

class ASN1ToolTests(BaseTest):
	def test_bitstring_trailing_zero(self):
		self.assertTrue(ASN1Tools.bitstring_has_trailing_zeros(BitString([ 0, 1, 0 ])))
		self.assertTrue(ASN1Tools.bitstring_has_trailing_zeros(BitString([ 0 ])))
		self.assertTrue(ASN1Tools.bitstring_has_trailing_zeros(BitString([ 1, 1, 1, 1, 1, 1, 1, 0 ])))
		self.assertTrue(ASN1Tools.bitstring_has_trailing_zeros(BitString([ 1, 1, 1, 1, 1, 1, 1, 1, 0 ])))

		self.assertFalse(ASN1Tools.bitstring_has_trailing_zeros(BitString([ 0, 1 ])))
		self.assertFalse(ASN1Tools.bitstring_has_trailing_zeros(BitString([ ])))
		self.assertFalse(ASN1Tools.bitstring_has_trailing_zeros(BitString([ 0, 0, 0, 0, 1 ])))
		self.assertFalse(ASN1Tools.bitstring_has_trailing_zeros(BitString([ 0, 0, 0, 0, 0, 0, 1 ])))
		self.assertFalse(ASN1Tools.bitstring_has_trailing_zeros(BitString([ 0, 0, 0, 0, 0, 0, 0, 1 ])))

	def test_bitstring_empty(self):
		self.assertTrue(ASN1Tools.bitstring_is_empty(BitString([ ])))
		self.assertTrue(ASN1Tools.bitstring_is_empty(BitString([ 0 ])))
		self.assertTrue(ASN1Tools.bitstring_is_empty(BitString([ 0, 0, 0 ])))

		self.assertFalse(ASN1Tools.bitstring_is_empty(BitString([ 1 ])))
		self.assertFalse(ASN1Tools.bitstring_is_empty(BitString([ 0, 1 ])))
		self.assertFalse(ASN1Tools.bitstring_is_empty(BitString([ 0, 0, 1, 0 ])))

	def test_bitstring_highest_set_bit(self):
		self.assertEqual(ASN1Tools.bitstring_highbit(BitString([ ])), None)
		self.assertEqual(ASN1Tools.bitstring_highbit(BitString([ 0 ])), None)
		self.assertEqual(ASN1Tools.bitstring_highbit(BitString([ 0, 0 ])), None)
		self.assertEqual(ASN1Tools.bitstring_highbit(BitString([ 1 ])), 0)
		self.assertEqual(ASN1Tools.bitstring_highbit(BitString([ 1, 1 ])), 1)
		self.assertEqual(ASN1Tools.bitstring_highbit(BitString([ 1, 1, 1 ])), 2)
		self.assertEqual(ASN1Tools.bitstring_highbit(BitString([ 1, 1, 1, 0 ])), 2)
		self.assertEqual(ASN1Tools.bitstring_highbit(BitString([ 1, 1, 1, 0, 0 ])), 2)
		self.assertEqual(ASN1Tools.bitstring_highbit(BitString([ 1, 1, 1, 0, 0, 1 ])), 5)
		self.assertEqual(ASN1Tools.bitstring_highbit(BitString([ 1, 1, 1, 0, 0, 1, 0 ])), 5)
		self.assertEqual(ASN1Tools.bitstring_highbit(BitString([ 1, 1, 1, 0, 0, 1, 0, 1 ])), 7)

	def test_safedecode_undecodable(self):
		der_data = bytes.fromhex("aa bb cc")
		asn1_details = ASN1Tools.safe_decode(der_data)
		self.assertEqual(asn1_details.flags, set([ "undecodable" ]))
		self.assertEqual(asn1_details.tail, None)
		self.assertEqual(asn1_details.asn1, None)
		self.assertEqual(asn1_details.generic_asn1, None)
		self.assertEqual(asn1_details.encoded_der, None)
		self.assertEqual(asn1_details.original_der, der_data)
		self.assertEqual(asn1_details.model_index, None)

	def test_safedecode_ok_nomodel(self):
		der_data = bytes.fromhex("02 01   7b")		# 123
		asn1_details = ASN1Tools.safe_decode(der_data)
		self.assertEqual(asn1_details.flags, set())
		self.assertEqual(asn1_details.tail, bytes())
		self.assertEqual(asn1_details.asn1, Integer(123))
		self.assertEqual(asn1_details.generic_asn1, None)
		self.assertEqual(asn1_details.encoded_der, None)
		self.assertEqual(asn1_details.original_der, der_data)
		self.assertEqual(asn1_details.model_index, 0)

	def test_safedecode_ok_model(self):
		der_data = bytes.fromhex("02 01   7b")		# 123
		asn1_details = ASN1Tools.safe_decode(der_data, asn1_spec = RestrictiveASN1Model())
		self.assertEqual(asn1_details.flags, set())
		self.assertEqual(asn1_details.asn1, Integer(123))
		self.assertEqual(asn1_details.generic_asn1, None)
		self.assertEqual(asn1_details.encoded_der, None)
		self.assertEqual(asn1_details.original_der, der_data)
		self.assertEqual(asn1_details.model_index, 0)

	def test_safedecode_ok_model_fallback(self):
		der_data = bytes.fromhex("02 02 01c8")		# 456
		asn1_details = ASN1Tools.safe_decode(der_data, asn1_spec = (RestrictiveASN1Model(), BasicASN1Model()))
		self.assertEqual(asn1_details.flags, set([ "fallback" ]))
		self.assertEqual(asn1_details.tail, bytes())
		self.assertEqual(asn1_details.asn1, Integer(456))
		self.assertEqual(asn1_details.generic_asn1, None)
		self.assertEqual(asn1_details.encoded_der, None)
		self.assertEqual(asn1_details.original_der, der_data)
		self.assertEqual(asn1_details.model_index, 1)

	def test_safedecode_fail_model_generic(self):
		der_data = bytes.fromhex("02 02 01c8")		# 456
		asn1_details = ASN1Tools.safe_decode(der_data, asn1_spec = RestrictiveASN1Model())
		self.assertEqual(asn1_details.flags, set([ "unexpected_type" ]))
		self.assertEqual(asn1_details.tail, bytes())
		self.assertEqual(asn1_details.asn1, None)
		self.assertEqual(asn1_details.generic_asn1, Integer(456))
		self.assertEqual(asn1_details.encoded_der, None)
		self.assertEqual(asn1_details.original_der, der_data)
		self.assertEqual(asn1_details.model_index, None)

	def test_safedecode_ok_trailing_data(self):
		der_data = bytes.fromhex("02 02 01c8 aabb")		# 456
		asn1_details = ASN1Tools.safe_decode(der_data, asn1_spec = BasicASN1Model())
		self.assertEqual(asn1_details.flags, set([ "trailing_data" ]))
		self.assertEqual(asn1_details.asn1, Integer(456))
		self.assertEqual(asn1_details.tail, bytes.fromhex("aa bb"))
		self.assertEqual(asn1_details.generic_asn1, None)
		self.assertEqual(asn1_details.encoded_der, None)
		self.assertEqual(asn1_details.original_der, der_data)
		self.assertEqual(asn1_details.model_index, 0)

	def test_safedecode_ok_nonder(self):
		der_data = bytes.fromhex("02 02 007b")		# 123 non-DER
		asn1_details = ASN1Tools.safe_decode(der_data, asn1_spec = RestrictiveASN1Model())
		self.assertEqual(asn1_details.flags, set([ "non_der" ]))
		self.assertEqual(asn1_details.asn1, Integer(123))
		self.assertEqual(asn1_details.tail, bytes())
		self.assertEqual(asn1_details.generic_asn1, None)
		self.assertEqual(asn1_details.encoded_der, bytes.fromhex("02 01 7b"))
		self.assertEqual(asn1_details.original_der, der_data)
		self.assertEqual(asn1_details.model_index, 0)

	def test_safedecode_ok_nonder_trailing_data(self):
		der_data = bytes.fromhex("02 02 007b aabb")		# 123 non-DER
		asn1_details = ASN1Tools.safe_decode(der_data, asn1_spec = RestrictiveASN1Model())
		self.assertEqual(asn1_details.flags, set([ "non_der", "trailing_data" ]))
		self.assertEqual(asn1_details.asn1, Integer(123))
		self.assertEqual(asn1_details.tail, bytes.fromhex("aabb"))
		self.assertEqual(asn1_details.generic_asn1, None)
		self.assertEqual(asn1_details.encoded_der, bytes.fromhex("02 01 7b"))
		self.assertEqual(asn1_details.original_der, der_data)
		self.assertEqual(asn1_details.model_index, 0)

	def test_safedecode_wrong_type(self):
		der_data = bytes.fromhex("04 06 666f6f626172")		# "foobar" OctetString
		asn1_details = ASN1Tools.safe_decode(der_data, asn1_spec = RestrictiveASN1Model())
		self.assertEqual(asn1_details.flags, set([ "unexpected_type" ]))
		self.assertEqual(asn1_details.asn1, None)
		self.assertEqual(asn1_details.tail, bytes())
		self.assertEqual(asn1_details.generic_asn1, OctetString(b"foobar"))
		self.assertEqual(asn1_details.encoded_der, None)
		self.assertEqual(asn1_details.original_der, der_data)
		self.assertEqual(asn1_details.model_index, None)

	def test_safedecode_non_encodable(self):
		der_data = bytes.fromhex("17 11 31 36 30 32 31 37 31 30 32 37 30 30 2b 30 31 30 30")		# UTCTime("160217102700+0100")
		asn1_details = ASN1Tools.safe_decode(der_data)
		self.assertEqual(asn1_details.flags, set([ "non_encodable" ]))
		self.assertEqual(asn1_details.asn1, UTCTime("160217102700+0100"))
		self.assertEqual(asn1_details.tail, bytes())
		self.assertEqual(asn1_details.generic_asn1, None)
		self.assertEqual(asn1_details.encoded_der, None)
		self.assertEqual(asn1_details.original_der, der_data)
		self.assertEqual(asn1_details.model_index, 0)
