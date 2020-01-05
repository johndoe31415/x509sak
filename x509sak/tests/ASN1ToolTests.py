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

from pyasn1.type.univ import BitString
from x509sak.tests.BaseTest import BaseTest
from x509sak.Tools import ASN1Tools

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
