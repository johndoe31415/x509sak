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

from x509sak.tests import BaseTest
from x509sak.CurveDB import CurveDB
from x509sak.Exceptions import InvalidInputException, UnsupportedEncodingException

class ECCMathTests(BaseTest):
	def test_ecc_prime_curve(self):
		curve = CurveDB().instantiate(name = "secp112r1")
		self.assertTrue(curve.G.on_curve)

	def test_ecc_binary_trinomial_basis_poly(self):
		curve = CurveDB().instantiate(name = "sect113r1")
		self.assertEqual(sorted(curve.poly), [ 0, 9, 113 ])

	def test_ecc_binary_pentanomial_basis_poly(self):
		curve = CurveDB().instantiate(name = "sect163r1")
		self.assertEqual(sorted(curve.poly), [ 0, 3, 6, 7, 163 ])

	def test_ecc_curvedb(self):
		db = CurveDB()
		for curve_oid in db:
			curve = db.instantiate(oid = curve_oid)
			self.assertTrue(curve.G.on_curve())

	def test_point_encode(self):
		point = CurveDB().instantiate(name = "sect113r1").G
		self.assertEqual(point.encode(), bytes.fromhex("04 009d73616f35f4ab1407d73562c10f 00a52830277958ee84d1315ed31886"))

	def test_point_decode(self):
		curve = CurveDB().instantiate(name = "sect113r1")
		decoded_point = curve.decode_point(bytes.fromhex("04 009d73616f35f4ab1407d73562c10f 00a52830277958ee84d1315ed31886"))
		self.assertEqual(decoded_point, curve.G)

	def test_point_decode_fail(self):
		curve = CurveDB().instantiate(name = "sect113r1")
		with self.assertRaises(InvalidInputException):
			curve.decode_point(bytes.fromhex("04 0011 2233"))

		with self.assertRaises(UnsupportedEncodingException):
			curve.decode_point(bytes.fromhex("02 0011 2233"))

	def test_point_str(self):
		point = CurveDB().instantiate(name = "sect113r1").G
		point_str = str(point)
		self.assertIn("0x9d7361", point_str)
		self.assertIn("0xa52830", point_str)
		self.assertIn("sect113r1", point_str)

	def test_point_decode_ed25519(self):
		curve = CurveDB().instantiate(name = "ed25519")

		Q = curve.decode_point(bytes(32))
		self.assertEqual(Q.x, 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0)
		self.assertEqual(Q.y, 0)
		self.assertTrue(Q.on_curve())
		self.assertEqual(Q.encode(), bytes(32))

		Q = curve.decode_point(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"))
		self.assertEqual(Q.x, 0x547cdb7fb03e20f4d4b2ff66c2042858d0bce7f952d01b873b11e4d8b5f15f3d)
		self.assertEqual(Q.y, 0)
		self.assertTrue(Q.on_curve())
		self.assertEqual(Q.encode(), bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"))

		Q = curve.decode_point(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
		self.assertEqual(Q.x, 0x55d0e09a2b9d34292297e08d60d0f620c513d47253187c24b12786bd777645ce)
		self.assertEqual(Q.y, 0x1a5107f7681a02af2523a6daf372e10e3a0764c9d3fe4bd5b70ab18201985ad7)
		self.assertTrue(Q.on_curve())
		self.assertEqual(Q.encode(), bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))

		Q = curve.decode_point(bytes.fromhex("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292"))
		self.assertEqual(Q.x, 0x3493c89a1d42961795326fb77ddda9b1073eb50954eec3acc573cd718bed3093)
		self.assertEqual(Q.y, 0x128224abe0fe0c86fb8badb42b1c85d6aef9f59c25f0290c7f8f964f5e42c9df)
		self.assertTrue(Q.on_curve())
		self.assertEqual(Q.encode(), bytes.fromhex("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292"))

		Q = curve.decode_point(bytes.fromhex("dcbfc4d2bd9b5b9b3f7cd673cf559fe3793946a6a904355c07a552991bdba7c5"))
		self.assertEqual(Q.x, 0x5c71bfc23d23bb896be916c12e2b02aa5d22c1883ac097fe5ab604aa52020ec9)
		self.assertEqual(Q.y, 0x45a7db1b9952a5075c3504a9a6463979e39f55cf73d67c3f9b5b9bbdd2c4bfdc)
		self.assertTrue(Q.on_curve())

		with self.assertRaises(InvalidInputException):
			curve.decode_point(bytes.fromhex("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6"))

	def test_scalar_mul_ed25519(self):
		curve = CurveDB().instantiate(name = "ed25519")
		self.assertEqual(curve.G.scalar_mul(0), curve.point(0, 1))
		self.assertEqual(curve.G.scalar_mul(1), curve.G)
		self.assertEqual(curve.G, curve.point(0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a, 0x6666666666666666666666666666666666666666666666666666666666666658))
		self.assertEqual(curve.G.scalar_mul(2), curve.point(0x36ab384c9f5a046c3d043b7d1833e7ac080d8e4515d7a45f83c5a14e2843ce0e, 0x2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9))
		self.assertEqual(curve.G.scalar_mul(3), curve.point(0x67ae9c4a22928f491ff4ae743edac83a6343981981624886ac62485fd3f8e25c, 0x1267b1d177ee69aba126a18e60269ef79f16ec176724030402c3684878f5b4d4))
		self.assertEqual(curve.G.scalar_mul(123456789), curve.point(0x547df969eeaad777ccc47f172eb04d76d148ac6fe7e6f03c5f764f1e15327545, 0x5bd3c1a4f2053b458e38123b41e36ddeb5d13a6f63365d93e90ddc6880adff17))

	def test_secret_expand_ed25519(self):
		curve = CurveDB().instantiate(name = "ed25519")
		(scalar, Q) = curve.expand_secret(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
		self.assertEqual(scalar, 36144925721603087658594284515452164870581325872720374094707712194495455132720)
		self.assertEqual(Q.encode(), bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))

	def test_ed448_generator(self):
		curve = CurveDB().instantiate(name = "ed448")
		rfc_8032_G = curve.point(224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710, 298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660)
		self.assertTrue(rfc_8032_G.on_curve())
		self.assertEqual(curve.G, rfc_8032_G)

	def test_secret_expand_ed448(self):
		curve = CurveDB().instantiate(name = "ed448")
		(scalar, Q) = curve.expand_secret(bytes.fromhex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"))
		self.assertEqual(scalar, 521658399617511624509929819094270498323007786671637499019582168374758478770958028340603419308639592898868374490003595203618871291427304)
		self.assertEqual(Q.encode(), bytes.fromhex("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"))

	def test_fp_scalar_mul(self):
		curve = CurveDB().instantiate(name = "secp112r1")
		P = curve.G.scalar_mul(0xa14b08db884ecd9acc3e507110be)
		self.assertEqual(P.x, 0x5d39a5c8d8f5c634afea9d0adf23)
		self.assertEqual(P.y, 0x88056785c1ea5bb9f320eefd630e)

	def test_fp_scalar_mul_n(self):
		curve = CurveDB().instantiate(name = "secp112r1")
		P = curve.G.scalar_mul(curve.n)
		self.assertEqual(P, curve.neutral_point)

	def test_fp_scalar_mul_0(self):
		curve = CurveDB().instantiate(name = "secp112r1")
		P = curve.G.scalar_mul(0)
		self.assertEqual(P, curve.neutral_point)

	def test_fp_scalar_mul_1(self):
		curve = CurveDB().instantiate(name = "secp112r1")
		P = curve.G.scalar_mul(1)
		self.assertEqual(P, curve.G)

	def test_fp_point_dbl(self):
		curve = CurveDB().instantiate(name = "secp112r1")
		P = curve.point_addition(curve.G, curve.G)
		self.assertEqual(P.x, 0x57cf52a0f9318000ee0bc032d756)
		self.assertEqual(P.y, 0x60aee03bbcff537a8d17401f006c)

	def test_fp_point_add(self):
		curve = CurveDB().instantiate(name = "secp112r1")
		Q = curve.point(0x123, 0x84bdce9a00a1895369a805a6c44e)
		self.assertTrue(Q.on_curve())
		P = curve.point_addition(curve.G, Q)
		self.assertEqual(P.x, 0xbbabcf20193b825046cb2357bb87)
		self.assertEqual(P.y, 0x5625e546a0459574b5eff88d17b9)

	def test_fp_point_add_neutral(self):
		curve = CurveDB().instantiate(name = "secp112r1")
		Q = curve.point(0x9487239995a5ee76b55f9c2f098, 0x32df450fdbbe9dc44268aeb5ab8b)
		self.assertTrue(Q.on_curve())
		P = curve.point_addition(curve.G, Q)
		self.assertEqual(P, curve.neutral_point)
