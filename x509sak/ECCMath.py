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

import math
import hashlib
import pyasn1.codec.der.decoder
from x509sak.KwargsChecker import KwargsChecker
from x509sak.NumberTheory import NumberTheory
from x509sak.Exceptions import InvalidInputException, UnsupportedEncodingException
from x509sak.ASN1Models import SpecifiedECDomain, ECFieldParametersPrimeField, ECFieldParametersCharacteristicTwoField, ECFieldParametersCharacteristicTwoFieldTrinomial, ECFieldParametersCharacteristicTwoFieldPentanomial
from x509sak.Tools import ASN1Tools
from x509sak.OID import OID, OIDDB

class EllipticCurvePoint():
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
		return (other is not None) and ((self.curve, self.x, self.y) == (other.curve, other.x, other.y))

	def __str__(self):
		return "(0x%x, 0x%x) on %s" % (self.x, self.y, self.curve)

class EllipticCurve():
	_CURVE_TYPE = None
	_DomainArgs = None
	_CurveTypes = { }

	def __init__(self, metadata = None, **domain_parameters):
		if self._DomainArgs is not None:
			self._DomainArgs.check(domain_parameters, "EllipticCurve")
		self._domain_parameters = domain_parameters
		self._metadata = metadata
		if self._metadata is None:
			self._metadata = { }

	@classmethod
	def register(cls, ec_class):
		cls._CurveTypes[ec_class._CURVE_TYPE] = ec_class
		return ec_class

	@classmethod
	def get_class_for_curvetype(cls, curve_type):
		return cls._CurveTypes.get(curve_type)

	@property
	def curvetype(self):
		if self._CURVE_TYPE is None:
			raise NotImplementedError(self.__class__.__name__)
		return self._CURVE_TYPE

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
	def order_bits(self):
		raise NotImplementedError(self.__class__.__name__)

	@property
	def field_bits(self):
		raise NotImplementedError(self.__class__.__name__)

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
		raise NotImplementedError(self.__class__.__name__)

	def on_curve(self, point):
		raise NotImplementedError(self.__class__.__name__)

	def point_addition(self, P, Q):
		raise NotImplementedError(self.__class__.__name__)

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

	@classmethod
	def from_asn1(cls, asn1):
		"""Decode explicitly encoded elliptic curve domain parameters, given as a Sequence (SpecifiedECDomain)."""

		(specified_domain, tail) = ASN1Tools.redecode(asn1, SpecifiedECDomain())
		if len(tail) != 0:
			raise InvalidInputException("Attempted to decode the excplicit EC domain and encountered %d bytes of trailing data." % (len(tail)))

		version = int(specified_domain["version"])
		if version != 1:
			raise InvalidInputException("Attempted to decode the excplicit EC domain and saw unknown version %d." % (version))

		field_type = OID.from_asn1(specified_domain["fieldID"]["fieldType"])
		field_type_id = OIDDB.ECFieldType.get(field_type)
		if field_type_id is None:
			raise InvalidInputException("Encountered explicit EC domain parameters in unknown field with OID %s." % (str(field_type)))

		domain_parameters = {
			"a":	int.from_bytes(bytes(specified_domain["curve"]["a"]), byteorder = "big"),
			"b":	int.from_bytes(bytes(specified_domain["curve"]["b"]), byteorder = "big"),
			"n":	int(specified_domain["order"]),
		}
		if specified_domain["cofactor"].hasValue():
			domain_parameters["h"] = int(specified_domain["cofactor"])
		base_point = bytes(specified_domain["base"])
		if field_type_id == "prime-field":
			(field_params, tail) = pyasn1.codec.der.decoder.decode(bytes(specified_domain["fieldID"]["parameters"]), asn1Spec = ECFieldParametersPrimeField())
			if len(tail) != 0:
				raise InvalidInputException("Attempted to decode the excplicit EC domain and encountered %d bytes of trailing data of the prime basis Integer." % (len(tail)))

			domain_parameters.update({
				"p":	int(field_params),
			})
			return cls.get_class_for_curvetype("prime").instantiate(domain_parameters, base_point)
		elif field_type_id == "characteristic-two-field":
			(field_params, tail) = pyasn1.codec.der.decoder.decode(bytes(specified_domain["fieldID"]["parameters"]), asn1Spec = ECFieldParametersCharacteristicTwoField())
			if len(tail) != 0:
				raise InvalidInputException("Attempted to decode the excplicit EC domain and encountered %d bytes of trailing data of the characteristic two field Sequence." % (len(tail)))

			basis_type = OID.from_asn1(field_params["basis"])
			basis_type_id = OIDDB.ECTwoFieldBasistype.get(basis_type)
			if basis_type_id is None:
				raise InvalidInputException("Unknown two-field basis type with OID %s found in public key." % (str(basis_type)))

			# Field width is common to all two-fields
			domain_parameters.update({
				"m":		int(field_params["m"]),
				"basis":	basis_type_id,
			})

			if basis_type_id == "gnBasis":
				raise InvalidInputException("Binary field explicit domain parameters with Gaussian polynomial basis is not implemented.")
			elif basis_type_id == "tpBasis":
				(params, tail) = ASN1Tools.redecode(field_params["parameters"], ECFieldParametersCharacteristicTwoFieldTrinomial())
				if len(tail) != 0:
					raise InvalidInputException("Attempted to decode the excplicit EC domain and encountered %d bytes of trailing data of the characteristic two field trinomial basis." % (len(tail)))
				poly = [ domain_parameters["m"], int(params), 0 ]
			elif basis_type_id == "ppBasis":
				(params, tail) = ASN1Tools.redecode(field_params["parameters"], ECFieldParametersCharacteristicTwoFieldPentanomial())
				if len(tail) != 0:
					raise InvalidInputException("Attempted to decode the excplicit EC domain and encountered %d bytes of trailing data of the characteristic two field pentanomial basis." % (len(tail)))
				poly = [ domain_parameters["m"], int(params["k1"]), int(params["k2"]), int(params["k3"]), 0 ]
			else:
				raise NotImplementedError("Binary field basis", basis_type_id)
			domain_parameters.update({
				"m":		int(field_params["m"]),
				"poly":		poly,
			})
			return cls.get_class_for_curvetype("binary").instantiate(domain_parameters, base_point)
		else:
			raise NotImplementedError("Explicit EC domain parameter encoding for field type \"%s\" is not implemented." % (field_type_id))

	@classmethod
	def instantiate(cls, domain_parameters, encoded_base_point):
		curve_without_generator = cls(**domain_parameters)
		G = curve_without_generator.decode_point(encoded_base_point)
		domain_parameters.update({
			"Gx":	G.x,
			"Gy":	G.y,
		})
		curve = cls(**domain_parameters)
		return curve

	def __hash__(self):
		return hash(self.characteristic_cmpkey)

	def __eq__(self, other):
		return self.characteristic_cmpkey == other.characteristic_cmpkey

	def __lt__(self, other):
		return self.characteristic_cmpkey < other.characteristic_cmpkey

	def __neq__(self, other):
		return not (self == other)

	@property
	def characteristic_cmpkey(self):
		raise NotImplementedError(self.__class__.__name__)

	def __getattr__(self, key):
		if key in self._domain_parameters:
			return self._domain_parameters[key]
		else:
			if self._DomainArgs.is_optional_argument(key):
				return None
			else:
				raise AttributeError(key)

	def __str__(self):
		if self.name is None:
			return "Order %d %s" % (self.n.bit_length(), self.__class__.__name__)
		else:
			return "%s %s" % (self.__class__.__name__, self.name)

@EllipticCurve.register
class PrimeFieldEllipticCurve(EllipticCurve):
	"""y^2 = x^3 + ax + b (mod p)"""
	_DomainArgs = KwargsChecker(required_arguments = set([ "p", "a", "b", "n" ]), optional_arguments = set([ "h", "Gx", "Gy" ]))
	_CURVE_TYPE = "prime"

	@property
	def neutral_point(self):
		return None

	def point_addition(self, P, Q):
		if P is None:
			# O + Q = Q
			return Q
		elif Q is None:
			# P + O = P
			return P
		elif ((P.x == Q.x) and (((P.y + Q.y) % self.p) == 0)):
			# P + (-P) = O
			return None
		elif P == Q:
			# Point doubling
			s = ((3 * P.x ** 2) + self.a) * NumberTheory.modinv(2 * P.y, self.p)
			x = (s * s - (2 * P.x)) % self.p
			y = (s * (P.x - x) - P.y) % self.p
			return EllipticCurvePoint(self, x, y)
		else:
			# Point addition
			s = (P.y - Q.y) * NumberTheory.modinv(P.x - Q.x, self.p)
			x = ((s ** 2) - P.x - Q.x) % self.p
			y = (s * (P.x - x) - P.y) % self.p
			return EllipticCurvePoint(self, x, y)

	@property
	def is_koblitz(self):
		"""Test if a = 0 and b is sufficiently small."""
		return (self.a == 0) and (self.b < 1000)

	@property
	def order_bits(self):
		return math.log(self.n, 2)

	@property
	def field_bits(self):
		return self.p.bit_length()

	@property
	def characteristic_cmpkey(self):
		return (self.curvetype, self.a, self.b, self.n, self.h, self._domain_parameters.get("Gx"), self._domain_parameters.get("Gy"), self.p)

	def on_curve(self, point):
		lhs = (point.y * point.y) % self.p
		rhs = ((point.x ** 3) + (self.a * point.x) + self.b) % self.p
		return lhs == rhs

@EllipticCurve.register
class BinaryFieldEllipticCurve(EllipticCurve):
	"""y^2 + xy = x^3 + ax^2 + b (in F_{2^m}, reduced by irreducible poly)"""
	_DomainArgs = KwargsChecker(required_arguments = set([ "m", "poly", "a", "b", "n" ]), optional_arguments = set([ "h", "Gx", "Gy", "basis" ]))
	_CURVE_TYPE = "binary"

	def __init__(self, **domain_parameters):
		super().__init__(**domain_parameters)
		self._domain_parameters["intpoly"] = sum(1 << bit for bit in set(self.poly))

	@property
	def is_koblitz(self):
		"""Test if a, b in [ 0, 1 ]."""
		return (self.a in  [ 0, 1 ]) and (self.b in [ 0, 1 ])

	@property
	def order_bits(self):
		return math.log(self.n, 2)

	@property
	def field_bits(self):
		return self.m

	@property
	def int_poly(self):
		return sum(1 << exponent for exponent in self.poly)

	@property
	def characteristic_cmpkey(self):
		return (self.curvetype, self.a, self.b, self.n, self.h, self._domain_parameters.get("Gx"), self._domain_parameters.get("Gy"), self.m, tuple(sorted(set(self.poly))))

	def on_curve(self, point):
		lhs = NumberTheory.binpoly_reduce(NumberTheory.cl_mul(point.y, point.y) ^ NumberTheory.cl_mul(point.x, point.y), self.intpoly)
		rhs = NumberTheory.binpoly_reduce(NumberTheory.cl_mul(NumberTheory.cl_mul(point.x, point.x), point.x) ^ NumberTheory.cl_mul(NumberTheory.cl_mul(self.a, point.x), point.x) ^ self.b, self.intpoly)
		return lhs == rhs

@EllipticCurve.register
class TwistedEdwardsEllipticCurve(EllipticCurve):
	"""ax^2 + y^2 = 1 + dx^2 y^2 (mod p)"""
	_DomainArgs = KwargsChecker(required_arguments = set([ "p", "a", "d", "element_octet_cnt", "expand_bitwise_and", "expand_bitwise_or", "expand_hashfnc" ]), optional_arguments = set([ "Gx", "Gy", "expand_hashlen" ]))
	_CURVE_TYPE = "twisted_edwards"

	def __init__(self, **domain_parameters):
		super().__init__(**domain_parameters)
		self._sqrt_neg1_modp = pow(2, (self.p - 1) // 4, self.p)

	@property
	def element_octet_cnt(self):
		return self._domain_parameters["element_octet_cnt"]

	@property
	def order_bits(self):
		return NumberTheory.hamming_weight(self.expand_bitwise_and & ~self.expand_bitwise_or)

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

	@property
	def characteristic_cmpkey(self):
		return (self.curvetype, self.a, self.d, self.p, self._domain_parameters.get("Gx"), self._domain_parameters.get("Gy"), self.element_octet_cnt, self.expand_bitwise_and, self.expand_bitwise_or, self.expand_hashfnc, self._domain_params.get("expand_hashlen"))
