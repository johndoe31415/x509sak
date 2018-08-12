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

from x509sak.KwargsChecker import KwargsChecker

class EllipticCurvePoint(object):
	"""Affine representation of an ECC curve point."""
	def __init__(self, curve, x, y):
		self._curve = curve
		self._x = x
		self._y = y

	def on_curve(self):
		return self._curve.on_curve(self)

	def encode_point(self, pt_format = "explicit"):
		assert(pt_format in [ "explicit" ])

	@property
	def curve(self):
		return self._curve

	@property
	def x(self):
		return self._x

	@property
	def y(self):
		return self._y

	def __str__(self):
		return "(0x%x, 0x%x) on %s" % (self.x, self.y, self.curve)

class EllipticCurve(object):
	_DomainArgs = None

	def __init__(self, **domain_parameters):
		if self._DomainArgs is not None:
			self._DomainArgs.check(domain_parameters, "EllipticCurve")
		self._domain_parameters = domain_parameters

	@property
	def field_bits(self):
		raise Exception(NotImplemented)

	@property
	def G(self):
		return EllipticCurvePoint(self, self.Gx, self.Gy)

	def on_curve(self, point):
		raise Exception(NotImplemented)

	def decode_point(self, serialized_point):
		if serialized_point[0] == 0x04:
			field_len = (self.n.field_bits + 7) // 8
			expected_length = 1 + (2 * field_len)
			if len(serialized_point == expected_length):
				Gx = int.from_bytes(serialized_point[1 : 1 + field_len], byteorder = "big")
				Gy = int.from_bytes(serialized_point[1 + field_len : 1 + (2 * field_len)], byteorder = "big")
				return EllipticCurvePoint(x = Gx, y = Gy, curve = self)
			else:
				raise InvalidInputException("Do not know how to decode explicit serialized point with length %d (expected %d = 1 + 2 * %d bytes)." % (len(serialized_point), 1 + (2 * field_len), field_len))
		else:
			raise LazyDeveloperException("Do not know how to decode serialized point in non-explicit point format 0x%x." % (serialized_point[0]))

	def __getattr__(self, key):
		return self._domain_parameters[key]

	def __str__(self):
		return "Order %d %s" % (self.n.bit_length(), self.__class__.__name__)

class PrimeFieldEllipticCurve(EllipticCurve):
	"""y^2 = x^3 + ax + b (mod p)"""
	_DomainArgs = KwargsChecker(required_arguments = set([ "p", "a", "b", "n", "h" ]), optional_arguments = set([ "Gx", "Gy" ]))

	@property
	def field_bits(self):
		return self.p.bit_length()

	def on_curve(self, point):
		lhs = (point.y * point.y) % self.p
		rhs = ((point.x ** 3) + (self.a * point.x) + self.b) % self.p
		return lhs == rhs

class BinaryFieldEllipticCurve(EllipticCurve):
	"""y^2 + xy = x^3 + ax^2 + b (in F_{2^m}, reduced by irreducible poly)"""
	_DomainArgs = KwargsChecker(required_arguments = set([ "m", "poly", "a", "b", "n", "h" ]), optional_arguments = set([ "Gx", "Gy" ]))

	@property
	def field_bits(self):
		return self.m

	def on_curve(self, point):
		print(point)
		pass
