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

import hashlib
from x509sak.KwargsChecker import KwargsChecker
from x509sak.NumberTheory import NumberTheory
from x509sak.Exceptions import InvalidInputException, UnsupportedEncodingException

class EllipticCurvePoint(object):
	"""Affine representation of an ECC curve point."""
	def __init__(self, curve, x, y):
		self._curve = curve
		self._x = x
		self._y = y

	def on_curve(self):
		return self._curve.on_curve(self)

	def encode(self):
		return self._curve.encode_point(self)

	@property
	def curve(self):
		return self._curve

	@property
	def x(self):
		return self._x

	@property
	def y(self):
		return self._y

	def scalar_mul(self, scalar):
		result = self.curve.neutral_point
		accumulator = self
		for bit in range(scalar.bit_length()):
			if ((scalar >> bit) & 1) == 1:
				# Bit set, add
				result = self.curve.point_addition(result, accumulator)
			accumulator = self.curve.point_addition(accumulator, accumulator)
		return result

	def __eq__(self, other):
		return (self.curve, self.x, self.y) == (other.curve, other.x, other.y)

	def __str__(self):
		return "(0x%x, 0x%x) on %s" % (self.x, self.y, self.curve)

class EllipticCurve(object):
	_DomainArgs = None

	def __init__(self, metadata = None, **domain_parameters):
		if self._DomainArgs is not None:
			self._DomainArgs.check(domain_parameters, "EllipticCurve")
		self._domain_parameters = domain_parameters
		self._metadata = metadata
		if self._metadata is None:
			self._metadata = { }

	@property
	def name(self):
		return self._metadata.get("name")

	@property
	def oid(self):
		return self._metadata.get("oid")

	@property
	def domain_parameters(self):
		return dict(self._domain_parameters)

	@property
	def field_bits(self):
		raise NotImplementedError()

	@property
	def element_octet_cnt(self):
		return (self.field_bits + 7) // 8

	def point(self, x, y):
		return EllipticCurvePoint(self, x, y)

	@property
	def G(self):
		return self.point(self.Gx, self.Gy)

	@property
	def neutral_point(self):
		raise NotImplementedError()

	def on_curve(self, point):
		raise NotImplementedError()

	def point_addition(self, P, Q):
		raise NotImplementedError()

	def encode_point(self, point):
		return bytes([ 0x04 ]) + point.x.to_bytes(length = self.element_octet_cnt, byteorder = "big") + point.y.to_bytes(length = self.element_octet_cnt, byteorder = "big")

	def decode_point(self, serialized_point):
		if serialized_point[0] == 0x04:
			expected_length = 1 + (2 * self.element_octet_cnt)
			if len(serialized_point) == expected_length:
				Gx = int.from_bytes(serialized_point[1 : 1 + self.element_octet_cnt], byteorder = "big")
				Gy = int.from_bytes(serialized_point[1 + self.element_octet_cnt : 1 + (2 * self.element_octet_cnt)], byteorder = "big")
				return EllipticCurvePoint(x = Gx, y = Gy, curve = self)
			else:
				raise InvalidInputException("Do not know how to decode explicit serialized point with length %d (expected %d = 1 + 2 * %d bytes)." % (len(serialized_point), 1 + (2 * self.element_octet_cnt), self.element_octet_cnt))
		else:
			raise UnsupportedEncodingException("Do not know how to decode serialized point in non-explicit point format 0x%x." % (serialized_point[0]))

	def __eq__(self, other):
		# TODO: Two curves with different names will not be equal. Right now we
		# don't have that case because we don't support explicit curve
		# encodings, but we might in the future.
		return self._domain_parameters == other._domain_parameters

	def __getattr__(self, key):
		return self._domain_parameters[key]

	def __str__(self):
		if self.name is None:
			return "Order %d %s" % (self.n.bit_length(), self.__class__.__name__)
		else:
			return "%s %s" % (self.__class__.__name__, self.name)

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

	def __init__(self, **domain_parameters):
		super().__init__(**domain_parameters)
		self._domain_parameters["intpoly"] = sum(1 << bit for bit in set(self.poly))

	@property
	def field_bits(self):
		return self.m

	def on_curve(self, point):
		lhs = NumberTheory.binpoly_reduce(NumberTheory.cl_mul(point.y, point.y) ^ NumberTheory.cl_mul(point.x, point.y), self.intpoly)
		rhs = NumberTheory.binpoly_reduce(NumberTheory.cl_mul(NumberTheory.cl_mul(point.x, point.x), point.x) ^ NumberTheory.cl_mul(NumberTheory.cl_mul(self.a, point.x), point.x) ^ self.b, self.intpoly)
		return lhs == rhs

class TwistedEdwardsEllipticCurve(EllipticCurve):
	"""ax^2 + y^2 = 1 + dx^2 y^2 (mod p)"""
	_DomainArgs = KwargsChecker(required_arguments = set([ "p", "a", "d", "element_octet_cnt", "expand_bitwise_and", "expand_bitwise_or", "expand_hashfnc" ]), optional_arguments = set([ "Gx", "Gy", "expand_hashlen" ]))
	def __init__(self, **domain_parameters):
		super().__init__(**domain_parameters)
		self._sqrt_neg1_modp = pow(2, (self.p - 1) // 4, self.p)

	@property
	def element_octet_cnt(self):
		return self._domain_parameters["element_octet_cnt"]

	@property
	def field_bits(self):
		return self.p.bit_length()

	@property
	def neutral_point(self):
		return self.point(0, 1)

	def on_curve(self, point):
		lhs = ((self.a * point.x * point.x) + (point.y * point.y)) % self.p
		rhs = 1 + (self.d * point.x * point.x * point.y * point.y) % self.p
		return lhs == rhs

	def point_addition(self, P, Q):
		x = (P.x * Q.y + Q.x * P.y) % self.p
		x = (x * NumberTheory.modinv(1 + self.d * P.x * Q.x * P.y * Q.y, self.p)) % self.p
		y = (P.y * Q.y - self.a * P.x * Q.x)  % self.p
		y = (y * NumberTheory.modinv(1 - self.d * P.x * Q.x * P.y * Q.y, self.p)) % self.p
		return self.point(x, y)

	def encode_point(self, point):
		encoded_point = bytearray(point.y.to_bytes(length = self.element_octet_cnt, byteorder = "little"))
		encoded_point[-1] |= (point.x & 1) << 7
		return bytes(encoded_point)

	def decode_point(self, serialized_point):
		assert(isinstance(serialized_point, bytes))
		if len(serialized_point) != self.element_octet_cnt:
			raise InvalidInputException("Do not know how to decode %s point. Expected %d octets, but got %d." % (str(self), self.element_octet_cnt, len(serialized_point)))

		serialized_point = bytearray(serialized_point)
		x_lsb = (serialized_point[-1] >> 7) & 1
		serialized_point[-1] &= 0x7f
		y = int.from_bytes(serialized_point, byteorder = "little")

		if y >= self.p:
			raise InvalidInputException("y coordinate of point must be smaller than p.")

		# x^2 = (1 - y^2) / (a - dy^2)
		x2 = (1 - y * y) % self.p
		x2 *= NumberTheory.modinv(self.a - self.d * y * y, self.p)
		(x_pos, x_neg) = NumberTheory.sqrt_mod_p(x2, self.p)

		if x_lsb == 0:
			x = x_pos
		else:
			x = x_neg

		point = self.point(x, y)
		return point

	def expand_secret(self, serialized_unhashed_secret):
		assert(isinstance(serialized_unhashed_secret, bytes))
		if len(serialized_unhashed_secret) != self.element_octet_cnt:
			raise InvalidInputException("Do not know how to decode %s secret. Expected %d octets, but got %d." % (str(self), self.element_octet_cnt, len(serialized_unhashed_secret)))
		hashfnc = hashlib.new(self.expand_hashfnc)
		hashfnc.update(serialized_unhashed_secret)
		if ("expand_hashlen" in self._domain_parameters) and (hashfnc.digest_size == 0):
			hashed_secret = hashfnc.digest(self.expand_hashlen)
		else:
			hashed_secret = hashfnc.digest()

		if ("expand_hashlen" in self._domain_parameters) and (len(hashed_secret) != self._domain_parameters["expand_hashlen"]):
			raise InvalidInputException("Expansion of secret requires %d byte hash function output, but %s provided %d bytes." % (self._domain_parameters["expand_hashlen"], str(hashfnc), len(hashed_secret)))

		scalar = int.from_bytes(hashed_secret[ : self.element_octet_cnt], byteorder = "little")
		scalar &= self.expand_bitwise_and
		scalar |= self.expand_bitwise_or
		return (scalar, self.G.scalar_mul(scalar))
