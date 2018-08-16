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
from x509sak.CurveDB import CurveDB
from x509sak.Exceptions import InvalidInputException, UnsupportedEncodingException

class ECCMathTests(BaseTest):
	def test_ecc_prime_curve(self):
		curve = CurveDB().instanciate(name = "secp112r1")
		self.assertTrue(curve.G.on_curve)

	def test_ecc_binary_trinomial_basis_poly(self):
		curve = CurveDB().instanciate(name = "sect113r1")
		self.assertEqual(sorted(curve.poly), [ 0, 9, 113 ])

	def test_ecc_binary_pentanomial_basis_poly(self):
		curve = CurveDB().instanciate(name = "sect163r1")
		self.assertEqual(sorted(curve.poly), [ 0, 3, 6, 7, 163 ])

	def test_ecc_curvedb(self):
		db = CurveDB()
		for curve_oid in db:
			curve = db.instanciate(oid = curve_oid)
			self.assertTrue(curve.G.on_curve())

	def test_point_encode(self):
		point = CurveDB().instanciate(name = "sect113r1").G
		self.assertEqual(point.encode(), bytes.fromhex("04 009d73616f35f4ab1407d73562c10f 00a52830277958ee84d1315ed31886"))

	def test_point_decode(self):
		curve = CurveDB().instanciate(name = "sect113r1")
		decoded_point = curve.decode_point(bytes.fromhex("04 009d73616f35f4ab1407d73562c10f 00a52830277958ee84d1315ed31886"))
		self.assertEqual(decoded_point, curve.G)

	def test_point_decode_fail(self):
		curve = CurveDB().instanciate(name = "sect113r1")
		with self.assertRaises(InvalidInputException):
			decoded_point = curve.decode_point(bytes.fromhex("04 0011 2233"))

		with self.assertRaises(UnsupportedEncodingException):
			decoded_point = curve.decode_point(bytes.fromhex("02 0011 2233"))

	def test_point_str(self):
		point = CurveDB().instanciate(name = "sect113r1").G
		point_str = str(point)
		self.assertIn("0x9d7361", point_str)
		self.assertIn("0xa52830", point_str)
		self.assertIn("Order 113", point_str)
