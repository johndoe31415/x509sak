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
import collections
import pyasn1.codec.der.decoder
from pyasn1_modules import rfc2459, rfc2437
from x509sak.OID import OID, OIDDB
from x509sak.PEMDERObject import PEMDERObject
from x509sak.Tools import ASN1Tools
from x509sak.KeySpecification import KeySpecification
from x509sak.Exceptions import UnknownAlgorithmException, LazyDeveloperException, InvalidUseException
from x509sak.SecurityEstimator import SecurityEstimator
from x509sak.CurveDB import CurveDB
from x509sak.AlgorithmDB import PublicKeyAlgorithms, Cryptosystems

class PublicKey(PEMDERObject):
	_PEM_MARKER = "PUBLIC KEY"
	_ASN1_MODEL = rfc2459.SubjectPublicKeyInfo
	_ECPoint = collections.namedtuple("ECPoint", [ "curve", "x", "y" ])

	def keyid(self, hashfnc = "sha1"):
		hashval = hashlib.new(hashfnc)
		inner_key = ASN1Tools.bitstring2bytes(self.asn1["subjectPublicKey"])
		hashval.update(inner_key)
		return hashval.digest()

	@property
	def pk_alg(self):
		return self._pk_alg

	@property
	def params(self):
		return self._key["params"]

	@property
	def keyspec(self):
		if self.pk_alg.value.cryptosystem == Cryptosystems.RSA:
			return KeySpecification(cryptosystem = self.pk_alg.value.cryptosystem, parameters = { "bitlen": self.n.bit_length() })
		elif self.pk_alg.value.cryptosystem in [ Cryptosystems.ECC_ECDSA, Cryptosystems.ECC_EdDSA ]:
			return KeySpecification(cryptosystem = self.pk_alg.value.cryptosystem, parameters = { "curvename": self.curve.name })
		else:
			raise LazyDeveloperException(NotImplemented, self.cryptosystem)

	@property
	def point(self):
		if not all(element in self._key for element in [ "curve", "x", "y" ]):
			raise InvalidUseException("To return a public key point, there needs to be a curve, x and y coordinate set.")
		return self.curve.point(self.x, self.y)

	def _post_decode_hook(self):
		alg_oid = OID.from_asn1(self.asn1["algorithm"]["algorithm"])
		self._pk_alg = PublicKeyAlgorithms.lookup("oid", alg_oid)
		if self._pk_alg is None:
			raise UnknownAlgorithmException("Unable to determine public key algorithm for OID %s." % (alg_oid))

		inner_key = ASN1Tools.bitstring2bytes(self.asn1["subjectPublicKey"])
		if self.pk_alg.value.cryptosystem == Cryptosystems.RSA:
			(key, _) = pyasn1.codec.der.decoder.decode(inner_key, asn1Spec = rfc2437.RSAPublicKey())
			self._key = {
				"n":		int(key["modulus"]),
				"e":		int(key["publicExponent"]),
				"params":	self.asn1["algorithm"]["parameters"] if self.asn1["algorithm"]["parameters"].hasValue() else None,
			}
		elif self.pk_alg.value.cryptosystem == Cryptosystems.ECC_ECDSA:
			(alg_oid, _) = pyasn1.codec.der.decoder.decode(self.asn1["algorithm"]["parameters"])
			alg_oid = OID.from_asn1(alg_oid)
			curve = CurveDB().instanciate(oid = alg_oid)
			pk_point = curve.decode_point(inner_key)
			self._key = {
				"x":			pk_point.x,
				"y":			pk_point.y,
				"curve":		curve,
			}
		elif self.pk_alg.value.cryptosystem == Cryptosystems.ECC_EdDSA:
			curve = CurveDB().instanciate(oid = alg_oid)
			self._key = dict(self._pk_alg.value.fixed_params)
			pk_point = curve.decode_point(inner_key)
			self._key.update({
				"x":		pk_point.x,
				"y":		pk_point.y,
				"curve":	curve,
			})
		else:
			raise LazyDeveloperException(NotImplemented, self._pk_alg.cryptosystem)

	@classmethod
	def create(cls, cryptosystem, parameters):
		asn1 = cls._ASN1_MODEL()
		asn1["algorithm"] = rfc2459.AlgorithmIdentifier()
		if cryptosystem == Cryptosystems.RSA:
			asn1["algorithm"]["algorithm"] = OIDDB.KeySpecificationAlgorithms.inverse("rsaEncryption").to_asn1()
			inner_key = rfc2437.RSAPublicKey()
			inner_key["modulus"] = pyasn1.type.univ.Integer(parameters["n"])
			inner_key["publicExponent"] = pyasn1.type.univ.Integer(parameters["e"])
			inner_key = pyasn1.codec.der.encoder.encode(inner_key)
		elif cryptosystem == Cryptosystems.ECC_ECDSA:
			curve = parameters["curve"]
			asn1["algorithm"]["algorithm"] = OIDDB.KeySpecificationAlgorithms.inverse("ecPublicKey").to_asn1()
			asn1["algorithm"]["parameters"] = pyasn1.codec.der.encoder.encode(curve.oid.to_asn1())
			inner_key = curve.point(parameters["x"], parameters["y"]).encode()
		elif cryptosystem == Cryptosystems.ECC_EdDSA:
			curve = parameters["curve"]
			asn1["algorithm"]["algorithm"] = curve.oid.to_asn1()
			inner_key = curve.point(parameters["x"], parameters["y"]).encode()
		else:
			raise LazyDeveloperException(NotImplemented, cryptosystem)
		asn1["subjectPublicKey"] = ASN1Tools.bytes2bitstring(inner_key)
		return cls.from_asn1(asn1)

	def analyze(self, analysis_options = None):
		result = {
			"pubkey_alg":	self._pk_alg.value.name,
		}
		if self.pk_alg.value.cryptosystem == Cryptosystems.RSA:
			result["pretty"] = "RSA with %d bit modulus" % (self.n.bit_length())
			result.update(SecurityEstimator.algorithm("rsa", analysis_options = analysis_options).analyze(self))
		elif self.pk_alg.value.cryptosystem == Cryptosystems.ECC_ECDSA:
			result["pretty"] = "ECC on %s" % (self.curve.name)
			result.update(SecurityEstimator.algorithm("ecc", analysis_options = analysis_options).analyze(self))
		elif self.pk_alg.value.cryptosystem == Cryptosystems.ECC_EdDSA:
			result["pretty"] = "EdDSA on %s" % (self.curve.name)
			result.update(SecurityEstimator.algorithm("eddsa", analysis_options = analysis_options).analyze(self))
		else:
			raise LazyDeveloperException(NotImplemented, self.cryptosystem)
		return result

	def __getattr__(self, key):
		if key in self._key:
			return self._key[key]
		raise AttributeError("%s public key does not have a '%s' attribute." % (self.pk_alg.value.name, key))

	def __str__(self):
		return "PublicKey<%s>" % (self.keyspec)
