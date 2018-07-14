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
from x509sak.OID import OID, OIDDB
from x509sak.Exceptions import LazyDeveloperException, UnknownAlgorithmException
from x509sak.KwargsChecker import KwargsChecker

class Cryptosystem(enum.Enum):
	RSA = "rsaEncryption"
	ECC = "ecPublicKey"
	HARDWARE_TOKEN = "hardwareToken"

class KeySpecification(object):
	_PARAMETER_CONSTRAINTS = {
		Cryptosystem.RSA:				KwargsChecker(required_arguments = set([ "bitlen" ])),
		Cryptosystem.ECC:				KwargsChecker(required_arguments = set([ "curve" ])),
		Cryptosystem.HARDWARE_TOKEN:	KwargsChecker(required_arguments = set([ "key_id" ])),
	}

	def __init__(self, cryptosystem, parameters = None):
		assert(isinstance(cryptosystem, Cryptosystem))
		if parameters is None:
			parameters = { }
		self._cryptosystem = cryptosystem
		self._parameters = dict(parameters)
		self._PARAMETER_CONSTRAINTS[self._cryptosystem].check(parameters, hint = "keyspec for cryptosystem %s" % (self._cryptosystem.name))

	@property
	def explicit(self):
		return self.cryptosystem != Cryptosystem.HARDWARE_TOKEN

	@property
	def cryptosystem(self):
		return self._cryptosystem

	@classmethod
	def from_keyspec_argument(cls, keyspec_arg):
		if keyspec_arg.cryptosystem == keyspec_arg.KeySpecification.RSA:
			return cls(cryptosystem = Cryptosystem.RSA, parameters = { "bitlen": keyspec_arg.bitlen })
		elif keyspec_arg.cryptosystem == keyspec_arg.KeySpecification.ECC:
			return cls(cryptosystem = Cryptosystem.ECC, parameters = { "curve": keyspec_arg.curve })
		elif keyspec_arg.cryptosystem == keyspec_arg.KeySpecification.HARDWARE_TOKEN:
			return cls(cryptosystem = Cryptosystem.HARDWARE_TOKEN, parameters = { "key_id": keyspec_arg.key_id })
		else:
			raise LazyDeveloperException(NotImplemented, keyspec_arg)

	def __getitem__(self, key):
		return self._parameters[key]

	def __str__(self):
		if self._cryptosystem == Cryptosystem.RSA:
			return "RSA-%d" % (self["bitlen"])
		elif self._cryptosystem == Cryptosystem.ECC:
			return "ECC-%s" % (self["curve"])
		elif self._cryptosystem == Cryptosystem.HARDWARE_TOKEN:
			return "HW-%d" % (self["key_id"])
		return "%s-%s" % (self._cryptosystem, str(self._parameters))

class SignatureAlgorithm(object):
	_KNOWN_CRYPTOSYSTEM_SCHEME_HASHES = {
		"md2WithRsaEncryption":		(Cryptosystem.RSA, "rsaEncryption", "md2"),
		"md4WithRsaEncryption":		(Cryptosystem.RSA, "rsaEncryption", "md4"),
		"md5WithRsaEncryption":		(Cryptosystem.RSA, "rsaEncryption", "md5"),
		"sha1WithRsaEncryption":	(Cryptosystem.RSA, "rsaEncryption", "sha1"),
		"sha256WithRsaEncryption":	(Cryptosystem.RSA, "rsaEncryption", "sha256"),
		"ecdsa-with-SHA224":		(Cryptosystem.ECC, "ECDSA", "sha224"),
		"ecdsa-with-SHA256":		(Cryptosystem.ECC, "ECDSA", "sha256"),
		"ecdsa-with-SHA384":		(Cryptosystem.ECC, "ECDSA", "sha384"),
		"ecdsa-with-SHA512":		(Cryptosystem.ECC, "ECDSA", "sha512"),
	}

	def __init__(self, cryptosystem, scheme, hashfunction):
		self._cryptosystem = cryptosystem
		self._scheme = scheme
		self._hashfunction = hashfunction

	@property
	def cryptosystem(self):
		return self._cryptosystem

	@property
	def scheme(self):
		return self._scheme

	@property
	def hashfunction(self):
		return self._hashfunction

	@classmethod
	def from_sigalg_oid(cls, sig_algorithm_oid):
		assert(isinstance(sig_algorithm_oid, OID))
		if sig_algorithm_oid not in OIDDB.SignatureAlgorithms:
			raise UnknownAlgorithmException("OID %s is not a known signature algorithm identifier." % (sig_algorithm_oid))

		sig_algorithm = OIDDB.SignatureAlgorithms[sig_algorithm_oid]
		if sig_algorithm not in cls._KNOWN_CRYPTOSYSTEM_SCHEME_HASHES:
			raise UnknownAlgorithmException("Cannot determine signature scheme/hash function for %s." % (sig_algorithm))

		(cryptosystem, scheme, hashfnc) = cls._KNOWN_CRYPTOSYSTEM_SCHEME_HASHES[sig_algorithm]
		return cls(cryptosystem = cryptosystem, scheme = scheme, hashfunction = hashfnc)

	def __str__(self):
		return "SignatureAlg<%s, %s, %s>" % (self.cryptosystem, self.scheme, self.hashfunction)
