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

import enum
import collections
import pyasn1.codec.der.decoder
import hashlib
from pyasn1_modules import rfc2459, rfc2437
from x509sak.OID import OID, OIDDB
from x509sak.PEMDERObject import PEMDERObject
from x509sak.Tools import ASN1Tools, ECCTools
from x509sak.KeySpecification import KeySpecification, Cryptosystem
from x509sak.Exceptions import UnknownAlgorithmException, LazyDeveloperException

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
	def cryptosystem(self):
		return self._cryptosystem

	@property
	def keyspec(self):
		if self.cryptosystem == Cryptosystem.RSA:
			return KeySpecification(cryptosystem = self.cryptosystem, parameters = { "bitlen": self.n.bit_length() })
		elif self.cryptosystem == Cryptosystem.ECC:
			return KeySpecification(cryptosystem = self.cryptosystem, parameters = { "curve": self.curve })
		else:
			raise LazyDeveloperException(NotImplemented, self.cryptosystem)

	def _post_decode_hook(self):
		alg_oid = OID.from_asn1(self.asn1["algorithm"]["algorithm"])
		if alg_oid not in OIDDB.KeySpecificationAlgorithms:
			raise UnknownAlgorithmException("Unable to determine public algorithm for OID %s." % (alg_oid))
		alg_name = OIDDB.KeySpecificationAlgorithms[alg_oid]
		self._cryptosystem = Cryptosystem(alg_name)

		inner_key = ASN1Tools.bitstring2bytes(self.asn1["subjectPublicKey"])
		if self.cryptosystem == Cryptosystem.RSA:
			(key, tail) = pyasn1.codec.der.decoder.decode(inner_key, asn1Spec = rfc2437.RSAPublicKey())
			self._key = {
				"n":	int(key["modulus"]),
				"e":	int(key["publicExponent"]),
			}
		elif self.cryptosystem == Cryptosystem.ECC:
			(x, y) = ECCTools.decode_enc_pubkey(inner_key)
			(alg_oid, tail) = pyasn1.codec.der.decoder.decode(self.asn1["algorithm"]["parameters"])
			alg_oid = OID.from_asn1(alg_oid)
			if alg_oid not in OIDDB.EllipticCurves:
				raise UnknownAlgorithmException("Unable to determine curve name for curve OID %s." % (alg_oid))
			self._key = {
				"curve":	OIDDB.EllipticCurves[alg_oid],
				"x":		x,
				"y":		y
			}
		else:
			raise LazyDeveloperException(NotImplemented, self.cryptosystem)

	@classmethod
	def create(cls, cryptosystem, parameters):
		asn1 = cls._ASN1_MODEL()
		asn1["algorithm"] = rfc2459.AlgorithmIdentifier()
		if cryptosystem == Cryptosystem.RSA:
			asn1["algorithm"]["algorithm"] = OIDDB.KeySpecificationAlgorithms.inverse("rsaEncryption").to_asn1()
			inner_key = rfc2437.RSAPublicKey()
			inner_key["modulus"] = pyasn1.type.univ.Integer(parameters["n"])
			inner_key["publicExponent"] = pyasn1.type.univ.Integer(parameters["e"])
			inner_key = pyasn1.codec.der.encoder.encode(inner_key)
		elif cryptosystem == Cryptosystem.ECC:
			asn1["algorithm"]["algorithm"] = OIDDB.KeySpecificationAlgorithms.inverse("ecPublicKey").to_asn1()
			asn1["algorithm"]["parameters"] = pyasn1.codec.der.encoder.encode(OIDDB.EllipticCurves.inverse(parameters["curve"]).to_asn1())

			# TODO: Shame on me! This is not how length is computed. It needs
			# to be looked up in the curve database, also see SEC1, ver 1.9,
			# page 12 (2.3.5) for each field element: "Output: An octet string M
			# of length mlen = ceil((log2 q)/8) octets."
			length = (max(parameters["x"].bit_length(), parameters["y"].bit_length()) + 7) // 8
			inner_key = b"\x04" + parameters["x"].to_bytes(length = length, byteorder = "big") + parameters["y"].to_bytes(length = length, byteorder = "big")
		else:
			raise LazyDeveloperException(NotImplemented, self.cryptosystem)
		asn1["subjectPublicKey"] = ASN1Tools.bytes2bitstring(inner_key)
		return cls.from_asn1(asn1)

	def __getattr__(self, key):
		if key in self._key:
			return self._key[key]
		raise AttributeError("%s public key does not have a '%s' parameter." % (self.cryptosystem.name, key))

	def __str__(self):
		return "PublicKey<%s>" % (self.keyspec)
