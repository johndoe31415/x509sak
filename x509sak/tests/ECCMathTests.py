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
