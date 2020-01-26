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

import hashlib
import collections
import pyasn1.codec.der.decoder
from pyasn1_modules import rfc2459, rfc2437, rfc3279
from x509sak.OID import OID, OIDDB
from x509sak.PEMDERObject import PEMDERObject
from x509sak.Tools import ASN1Tools
from x509sak.KeySpecification import KeySpecification
from x509sak.Exceptions import UnknownAlgorithmException, LazyDeveloperException, InvalidUseException
from x509sak.CurveDB import CurveDB
from x509sak.ECCMath import EllipticCurve
from x509sak.AlgorithmDB import PublicKeyAlgorithms, Cryptosystems
from x509sak.ASN1Models import ECParameters

class PublicKey(PEMDERObject):
	_PEM_MARKER = "PUBLIC KEY"
	_ASN1_MODEL = rfc2459.SubjectPublicKeyInfo
	_HANDLERS_BY_PK_ALG = { }
	_HANDLERS_BY_CRYPTOSYSTEM = { }

	@classmethod
	def register_handler(cls, handler_class):
		public_key_algs = handler_class._PK_ALG
		assert(public_key_algs is not None)
		if not isinstance(public_key_algs, tuple):
			public_key_algs = [ public_key_algs ]
		for public_key_alg in public_key_algs:
			cls._HANDLERS_BY_PK_ALG[public_key_alg] = handler_class
			cls._HANDLERS_BY_CRYPTOSYSTEM[public_key_alg.value.cryptosystem] = handler_class
		return handler_class

	def keyid(self, hashfnc = "sha1"):
		hashval = hashlib.new(hashfnc)
		inner_key = ASN1Tools.bitstring2bytes(self.asn1["subjectPublicKey"])
		hashval.update(inner_key)
		return hashval.digest()

	@property
	def pk_alg(self):
		return self._pk_alg

	@property
	def key(self):
		return self._key

	@property
	def keyspec(self):
		return self._key.keyspec

	def _post_decode_hook(self):
		alg_oid = OID.from_asn1(self.asn1["algorithm"]["algorithm"])
		self._pk_alg = PublicKeyAlgorithms.lookup("oid", alg_oid)
		if self._pk_alg is None:
			raise UnknownAlgorithmException("Unable to determine public key algorithm for OID %s." % (alg_oid))

		if self._pk_alg not in self._HANDLERS_BY_PK_ALG:
			raise UnknownAlgorithmException("Unable to determine public key handler for public key algorithm %s." % (self._pk_alg.name))

		handler_class = self._HANDLERS_BY_PK_ALG[self._pk_alg]
		key_data = ASN1Tools.bitstring2bytes(self.asn1["subjectPublicKey"])
		self._key = handler_class.from_subject_pubkey_info(self._pk_alg, self.asn1["algorithm"]["parameters"], key_data)


	@classmethod
	def create(cls, cryptosystem, parameters):
		if cryptosystem not in cls._HANDLERS_BY_CRYPTOSYSTEM:
			raise UnknownAlgorithmException("Unable to create public key for cryptosystem %s." % (cryptosystem.name))

		handler_class = cls._HANDLERS_BY_CRYPTOSYSTEM[cryptosystem]
		asn1 = handler_class.create(parameters)
		encoded_pubkey = pyasn1.codec.der.encoder.encode(asn1)
		return cls(encoded_pubkey)

	def __getattr__(self, name):
		try:
			return self._key[name]
		except KeyError:
			raise AttributeError("%s public key does not have a '%s' attribute." % (self.pk_alg.value.name, name))

	def __str__(self):
		return "PublicKey<%s>" % (self.keyspec)


class _BasePublicKey():
	_PK_ALG = None

	def __init__(self, accessible_parameters, decoding_details = None):
		self._accessible_parameters = accessible_parameters if (accessible_parameters is not None) else { }
		self._decoding_details = decoding_details

	@property
	def decoding_details(self):
		return self._decoding_details

	@property
	def malformed(self):
		raise NotImplementedError(cls.__name__)

	def has_param(self, name):
		return name in self._accessible_parameters

	def _param(self, name):
		return self._accessible_parameters.get(name)

	def __getitem__(self, name):
		return self._accessible_parameters[name]

	@classmethod
	def create(cls, parameters):
		raise NotImplementedError(cls.__name__)

	@classmethod
	def from_subject_pubkey_info(cls, pk_alg, params_asn1, pubkey_data):
		raise NotImplementedError(cls.__name__)


@PublicKey.register_handler
class RSAPublicKey(_BasePublicKey):
	_PK_ALG = PublicKeyAlgorithms.RSA

	@property
	def malformed(self):
		return not self.has_param("n")

	@property
	def keyspec(self):
		return KeySpecification(cryptosystem = self._PK_ALG.value.cryptosystem, parameters = { "bitlen": self["n"].bit_length() })

	@classmethod
	def create(self, parameters):
		asn1 = rfc2459.SubjectPublicKeyInfo()
		asn1["algorithm"] = rfc2459.AlgorithmIdentifier()
		asn1["algorithm"]["algorithm"] = OIDDB.KeySpecificationAlgorithms.inverse("rsaEncryption").to_asn1()
		asn1["algorithm"]["parameters"] = pyasn1.type.univ.Any(value = pyasn1.codec.der.encoder.encode(pyasn1.type.univ.Null()))

		inner_key = rfc2437.RSAPublicKey()
		inner_key["modulus"] = pyasn1.type.univ.Integer(parameters["n"])
		inner_key["publicExponent"] = pyasn1.type.univ.Integer(parameters["e"])
		inner_key = pyasn1.codec.der.encoder.encode(inner_key)
		asn1["subjectPublicKey"] = ASN1Tools.bytes2bitstring(inner_key)
		return asn1

	@classmethod
	def from_subject_pubkey_info(cls, pk_alg, params_asn1, pubkey_data):
		pubkey = ASN1Tools.safe_decode(pubkey_data, asn1_spec = rfc2437.RSAPublicKey())

		if pubkey.asn1 is not None:
			accessible_parameters = {
				"n":		int(pubkey.asn1["modulus"]),
				"e":		int(pubkey.asn1["publicExponent"]),
				"params":	params_asn1 if params_asn1.hasValue() else None,
			}
		else:
			accessible_parameters = None
		return cls(accessible_parameters = accessible_parameters, decoding_details = pubkey)

	def __repr__(self):
		if self._param("n") is not None:
			return "%s(%d bit modulus)" % (self.__class__.__name__, self["n"].bit_length())
		else:
			return "%s(undecodable)" % (self.__class__.__name__)


@PublicKey.register_handler
class DSAPublicKey(_BasePublicKey):
	_PK_ALG = PublicKeyAlgorithms.DSA

	@property
	def malformed(self):
		return not (self.has_param("p") and self.has_param("pubkey"))

	@property
	def N(self):
		return self._params("p").bit_length() if (self._params("p") is not None) else None

	@property
	def L(self):
		return self._params("q").bit_length() if (self._params("q") is not None) else None

	@property
	def keyspec(self):
		return KeySpecification(cryptosystem = self._PK_ALG.value.cryptosystem, parameters = { "N": self.N, "L": self.L })

	@classmethod
	def create(self, parameters):
		asn1 = rfc2459.SubjectPublicKeyInfo()
		asn1["algorithm"] = rfc2459.AlgorithmIdentifier()
		asn1["algorithm"]["algorithm"] = OIDDB.KeySpecificationAlgorithms.inverse("id-dsa").to_asn1()
		asn1["algorithm"]["parameters"] = rfc3279.Dss_Parms()
		asn1["algorithm"]["parameters"]["p"] = parameters["p"]
		asn1["algorithm"]["parameters"]["q"] = parameters["q"]
		asn1["algorithm"]["parameters"]["g"] = parameters["g"]

		inner_key = rfc3279.DSAPublicKey(parameters["pubkey"])
		inner_key = pyasn1.codec.der.encoder.encode(inner_key)
		asn1["subjectPublicKey"] = ASN1Tools.bytes2bitstring(inner_key)

		return asn1

	@classmethod
	def from_subject_pubkey_info(cls, pk_alg, params_asn1, pubkey_data):
		params = ASN1Tools.safe_decode(params_asn1, asn1_spec = rfc3279.Dss_Parms())
		pubkey = ASN1Tools.safe_decode(pubkey_data, asn1_spec = rfc3279.DSAPublicKey())

		accessible_parameters = { }
		if params.asn1 is not None:
			accessible_parameters.update({
				"p":		int(params.asn1["p"]),
				"q":		int(params.asn1["q"]),
				"g":		int(params.asn1["g"]),
			})

		if pubkey.asn1 is not None:
			accessible_parameters.update({
				"pubkey":	int(pubkey.asn1),
			})

		return cls(accessible_parameters = accessible_parameters, decoding_details = [ params, pubkey ])

	def __repr__(self):
		if self._param("p") is not None:
			return "%s(%d-%d)" % (self.__class__.__name__, self.N, self.L)
		else:
			return "%s(undecodable)" % (self.__class__.__name__)


@PublicKey.register_handler
class ECDSAPublicKey(_BasePublicKey):
	_PK_ALG = PublicKeyAlgorithms.ECC

	@property
	def malformed(self):
		return self._param("curve") is None

	@property
	def keyspec(self):
		if self._param("curve_source") == "namedCurve":
			return KeySpecification(cryptosystem = self._PK_ALG.value.cryptosystem, parameters = { "curvename": self["curve"].name })
		else:
			return None

	@classmethod
	def create(self, parameters):
		asn1 = rfc2459.SubjectPublicKeyInfo()

		asn1["algorithm"]["algorithm"] = OIDDB.KeySpecificationAlgorithms.inverse("ecPublicKey").to_asn1()
		if parameters["curve"].oid is not None:
			asn1["algorithm"]["parameters"] = pyasn1.codec.der.encoder.encode(parameters["curve"].oid.to_asn1())
		else:
			# TODO not implemented
			#domain_params = SpecifiedECDomain()
			#domain_params["version"] = 1
			#asn1["algorithm"]["parameters"] = domain_params
			raise NotImplementedError("Creation of explicitly specified elliptic curve domain parameters (i.e., non-named curves) is not implemented in x509sak")

		inner_key = parameters["curve"].point(parameters["x"], parameters["y"]).encode()
		asn1["subjectPublicKey"] = ASN1Tools.bytes2bitstring(inner_key)
		return asn1

	@classmethod
	def from_subject_pubkey_info(cls, pk_alg, params_asn1, pubkey_data):
		params = ASN1Tools.safe_decode(params_asn1, asn1_spec = ECParameters())

		accessible_parameters = { }
		if params.asn1 is not None:
			accessible_parameters["curve_source"] = params.asn1.getName()
			if accessible_parameters["curve_source"] == "namedCurve":
				# Named curve
				curve_oid = OID.from_asn1(params.asn1.getComponent())
				curve = CurveDB().instantiate(oid = curve_oid)
				accessible_parameters.update({
					"curve_oid":		curve_oid,
					"curve":			curve,
				})
			elif accessible_parameters["curve_source"] == "specifiedCurve":
				# Explicit curve or implicit curve
				curve = EllipticCurve.from_asn1(params.asn1.getComponent())
				accessible_parameters.update({
					"curve":			curve,
				})
			else:
				# Implicit curve
				pass

		if accessible_parameters.get("curve") is not None:
			pk_point = curve.decode_point(pubkey_data)
			accessible_parameters.update({
				"x": pk_point.x,
				"y": pk_point.y,
			})
		else:
			pk_point = None

		return cls(accessible_parameters = accessible_parameters, decoding_details = [ params, pk_point ])


@PublicKey.register_handler
class EdDSAPublicKey(_BasePublicKey):
	_PK_ALG = (PublicKeyAlgorithms.Ed25519, PublicKeyAlgorithms.Ed448)

	@property
	def malformed(self):
		return False

	@property
	def point(self):
		return self["curve"].point(self["x"], self["y"])

	@property
	def keyspec(self):
		return KeySpecification(cryptosystem = self._PK_ALG.value.cryptosystem, parameters = { "curvename": self["curve"].name })

	@classmethod
	def create(self, parameters):
		asn1 = rfc2459.SubjectPublicKeyInfo()
		asn1["algorithm"] = rfc2459.AlgorithmIdentifier()
		asn1["algorithm"]["algorithm"] = OIDDB.KeySpecificationAlgorithms.inverse("id-dsa").to_asn1()
		asn1["algorithm"]["algorithm"] = parameters["curve"].oid.to_asn1()

		inner_key = parameters["curve"].point(parameters["x"], parameters["y"]).encode()
		asn1["subjectPublicKey"] = ASN1Tools.bytes2bitstring(inner_key)
		return asn1

	@classmethod
	def from_subject_pubkey_info(cls, pk_alg, params_asn1, pubkey_data):
		curve = CurveDB().instantiate(oid = pk_alg.value.oid)
		pk_point = curve.decode_point(pubkey_data)

		accessible_parameters = dict(pk_alg.value.fixed_params)
		accessible_parameters.update({
			"x":			pk_point.x,
			"y":			pk_point.y,
			"curve":		curve,
			"point":		pk_point,
			"curve_source":	"namedCurve",
		})
		return cls(accessible_parameters = accessible_parameters, decoding_details = [ pk_point ])
