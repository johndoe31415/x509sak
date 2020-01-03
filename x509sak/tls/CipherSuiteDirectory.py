#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2019-2020 Johannes Bauer
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

import re
import collections
from .Enums import CipherSuite

def _dict_by_identifier(obj_list):
	return { obj.identifier: obj for obj in obj_list }

class VerboseCipherSuite():
	_PSEUDO_SUITES = set([
		CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
		CipherSuite.TLS_FALLBACK_SCSV,
	])

	class _CSElements():
		KeyExchange = collections.namedtuple("KeyExchange", [ "identifier", "algorithm", "pfs", "export" ])
		SigAlgorithm = collections.namedtuple("SigAlgorithm", [ "identifier", "algorithm" ])
		Cipher = collections.namedtuple("Cipher", [ "identifier", "cipher", "keylen", "opmode", "aead" ])
		PRF = collections.namedtuple("PRF", [ "identifier", "hashlen" ])

	_CIPHER_SUITE_COMPONENTS = {
		"key_exchange": _dict_by_identifier([
			_CSElements.KeyExchange(identifier = "RSA", algorithm = "RSA", pfs = False, export = False),
			_CSElements.KeyExchange(identifier = "RSA_EXPORT", algorithm = "RSA", pfs = False, export = True),
			_CSElements.KeyExchange(identifier = "DH", algorithm = "DH", pfs = False, export = False),
			_CSElements.KeyExchange(identifier = "DH_anon", algorithm = "DH", pfs = False, export = False),
			_CSElements.KeyExchange(identifier = "DH_anon_EXPORT", algorithm = "DH", pfs = False, export = True),
			_CSElements.KeyExchange(identifier = "DHE", algorithm = "DH", pfs = True, export = False),
			_CSElements.KeyExchange(identifier = "ECDH", algorithm = "ECDH", pfs = False, export = False),
			_CSElements.KeyExchange(identifier = "ECDH_anon", algorithm = "ECDH", pfs = False, export = False),
			_CSElements.KeyExchange(identifier = "ECDHE", algorithm = "ECDH", pfs = True, export = False),
			_CSElements.KeyExchange(identifier = "PSK", algorithm = "PSK", pfs = False, export = False),
			_CSElements.KeyExchange(identifier = "KRB5", algorithm = "KRB5", pfs = False, export = False),
			_CSElements.KeyExchange(identifier = "PGP_DHE", algorithm = "DH", pfs = True, export = False),
			_CSElements.KeyExchange(identifier = "PGP_RSA", algorithm = "RSA", pfs = False, export = False),
			_CSElements.KeyExchange(identifier = "KRB5_EXPORT", algorithm = "KRB5", pfs = False, export = True),	# PFS??
			_CSElements.KeyExchange(identifier = "NULL", algorithm = None, pfs = False, export = True),
		]),
		"sig_algorithm": _dict_by_identifier([
			_CSElements.SigAlgorithm(identifier = "RSA", algorithm = "RSA"),
			_CSElements.SigAlgorithm(identifier = "RSA_EXPORT", algorithm = "RSA"),
			_CSElements.SigAlgorithm(identifier = "DSS", algorithm = "DSS"),
			_CSElements.SigAlgorithm(identifier = "DSS_EXPORT", algorithm = "DSS"),
			_CSElements.SigAlgorithm(identifier = "PSK", algorithm = "PSK"),
			_CSElements.SigAlgorithm(identifier = "ECDSA", algorithm = "ECDSA"),
		]),
		"cipher": _dict_by_identifier([
			_CSElements.Cipher(identifier = "3DES_EDE_CBC", cipher = "DES", keylen = 168, opmode = "CBC", aead = False),
			_CSElements.Cipher(identifier = "AES_128_CBC", cipher = "AES", keylen = 128, opmode = "CBC", aead = False),
			_CSElements.Cipher(identifier = "AES_128_GCM", cipher = "AES", keylen = 128, opmode = "GCM", aead = True),
			_CSElements.Cipher(identifier = "AES_256_CBC", cipher = "AES", keylen = 256, opmode = "CBC", aead = False),
			_CSElements.Cipher(identifier = "AES_256_GCM", cipher = "AES", keylen = 256, opmode = "GCM", aead = True),
			_CSElements.Cipher(identifier = "CAMELLIA_128_CBC", cipher = "Camellia", keylen = 128, opmode = "CBC", aead = False),
			_CSElements.Cipher(identifier = "CAMELLIA_256_CBC", cipher = "Camellia", keylen = 256, opmode = "CBC", aead = False),
			_CSElements.Cipher(identifier = "CAST_CBC", cipher = "CAST", keylen = 128, opmode = "CBC", aead = False),
			_CSElements.Cipher(identifier = "DES40_CBC", cipher = "DES", keylen = 40, opmode = "CBC", aead = False),
			_CSElements.Cipher(identifier = "DES_CBC_40", cipher = "DES", keylen = 40, opmode = "CBC", aead = False),
			_CSElements.Cipher(identifier = "DES_CBC", cipher = "DES", keylen = 56, opmode = "CBC", aead = False),
			_CSElements.Cipher(identifier = "IDEA_CBC", cipher = "IDEA", keylen = 128, opmode = "CBC", aead = False),
			_CSElements.Cipher(identifier = "NULL", cipher = None, keylen = 0, opmode = None, aead = False),
			_CSElements.Cipher(identifier = "RC2_CBC_40", cipher = "RC2", keylen = 40, opmode = "CBC", aead = False),
			_CSElements.Cipher(identifier = "RC4_128", cipher = "RC4", keylen = 128, opmode = "STRM", aead = False),
			_CSElements.Cipher(identifier = "RC4_40", cipher = "RC4", keylen = 40, opmode = "STRM", aead = False),
			_CSElements.Cipher(identifier = "SEED_CBC", cipher = "SEED", keylen = 128, opmode = "CBC", aead = False),
			_CSElements.Cipher(identifier = "CHACHA20_POLY1305", cipher = "ChaCha20", keylen = 256, opmode = "STRM", aead = True),
		]),
		"prf": _dict_by_identifier([
			_CSElements.PRF(identifier = "RMD", hashlen = 160),
			_CSElements.PRF(identifier = "MD5", hashlen = 128),
			_CSElements.PRF(identifier = "SHA", hashlen = 160),
			_CSElements.PRF(identifier = "SHA256", hashlen = 256),
			_CSElements.PRF(identifier = "SHA384", hashlen = 384),
		]),
	}

	_CACHE = { }

	def __init__(self, ciphersuite_id):
		assert(isinstance(ciphersuite_id, CipherSuite))
		self._csid = ciphersuite_id
		self._pseudo_suite = self._csid in self._PSEUDO_SUITES

		self._key_exchange = None
		self._sig_algorithm = None
		self._cipher = None
		self._prf = None

		self._pfs = False

		if not self._pseudo_suite:
			regex = self._cipher_suite_regex
			result = regex.match(str(self._csid))
			if result is not None:
				result = result.groupdict()
				self._key_exchange = self._CIPHER_SUITE_COMPONENTS["key_exchange"].get(result["key_exchange"])
				self._sig_algorithm = self._CIPHER_SUITE_COMPONENTS["sig_algorithm"].get(result["sig_algorithm"])
				self._cipher = self._CIPHER_SUITE_COMPONENTS["cipher"].get(result["cipher"])
				self._prf = self._CIPHER_SUITE_COMPONENTS["prf"].get(result["prf"])

	@property
	def csid(self):
		return self._csid

	@property
	def key_exchange(self):
		"""Returns the key exchange algorithm."""
		return self._key_exchange

	@property
	def sig_algorithm(self):
		"""Returns the signature algorithm."""
		return self._sig_algorithm

	@property
	def cipher(self):
		"""Returns the cipher algorithm which is used for bulk encrytion."""
		return self._cipher

	@property
	def prf(self):
		"""Returns the pseudo random function."""
		return self._prf

	@property
	def provides_pfs(self):
		"""Boolean that indicates whether or not the cipher suite provides
		perfect forward secrecy (PFS)."""
		return (self.key_exchange is not None) and self.key_exchange.pfs

	@property
	def is_pseudo_suite(self):
		"""Boolean that indicates whether or not the cipher suite is a
		non-negotiable pseudo cipher suite."""
		return self._pseudo_suite

	def _cipher_suite_regex_part(self, partname, optional = False):
		elements = self._CIPHER_SUITE_COMPONENTS[partname].values()
		part = "_(?P<%s>" % (partname)
		part += "|".join(element.identifier for element in elements)
		part += ")"
		if optional:
			part = "(%s)?" % (part)
		return part

	@property
	def _cipher_suite_regex(self):
		regex = r"^CipherSuite\.TLS"
		regex += self._cipher_suite_regex_part("key_exchange")
		regex += self._cipher_suite_regex_part("sig_algorithm", optional = True)
		regex += "_WITH"
		regex += self._cipher_suite_regex_part("cipher")
		regex += self._cipher_suite_regex_part("prf")
		regex += "$"
		return re.compile(regex)

	def negotiate(self):
		if self._pseudo_suite:
			raise Exception("Will not handle pseudo cipher suite '%s'." % (str(self._pseudo_suite)))

	@classmethod
	def getsuite(cls, ciphersuite_id):
		"""Caches cipher suites so they do not have to be parsed every time.
		Otherwise identical to the regular constructor."""
		if ciphersuite_id not in cls._CACHE:
			cls._CACHE[ciphersuite_id] = VerboseCipherSuite(ciphersuite_id)
		return cls._CACHE[ciphersuite_id]

	def __str__(self):
		return "%s<Pseudo=%s, KEx = %s, Sig = %s, Cipher = %s, PRF = %s>" % (self.csid, self._pseudo_suite, self.key_exchange, self.sig_algorithm, self.cipher, self.prf)


class CipherSuiteDirectory():
	def __init__(self, csids = None):
		if csids is not None:
			self._csuites = { csid: VerboseCipherSuite.getsuite(csid) for csid in csids }
		else:
			self._csuites = { }
			for csid in CipherSuite:
				csuite = VerboseCipherSuite.getsuite(csid)
				if not csuite.is_pseudo_suite:
					self._csuites[csid] = csuite

	def filter(self, filterfnc):
		return CipherSuiteDirectory(csuite.csid for csuite in self if filterfnc(csuite))

	def filter_cipher(self, filterfnc):
		return self.filter(lambda csuite: (csuite.cipher is not None) and filterfnc(csuite.cipher))

	def filter_kex(self, filterfnc):
		return self.filter(lambda csuite: (csuite.key_exchange is not None) and filterfnc(csuite.key_exchange))

	def filter_prf(self, filterfnc):
		return self.filter(lambda csuite: (csuite.prf is not None) and filterfnc(csuite.prf))

	def filter_sig_algorithm(self, filterfnc):
		return self.filter(lambda csuite: (csuite.sig_algorithm is not None) and filterfnc(csuite.sig_algorithm))

	def kwfilter(self, cipher_name = None, cipher_keylen = None, cipher_opmode = None, kex_alg = None, kex_pfs = None, sig_alg = None):
		directory = self
		if cipher_name is not None:
			directory = directory.filter_cipher(lambda cipher: cipher.cipher == cipher_name)
		if cipher_keylen is not None:
			directory = directory.filter_cipher(lambda cipher: cipher.keylen == cipher_keylen)
		if cipher_opmode is not None:
			directory = directory.filter_cipher(lambda cipher: cipher.opmode == cipher_opmode)
		if sig_alg is not None:
			directory = directory.filter_sig_algorithm(lambda sig: sig.algorithm == sig_alg)
		if kex_alg is not None:
			directory = directory.filter_kex(lambda kex: kex.algorithm == kex_alg)
		if kex_pfs is not None:
			directory = directory.filter_kex(lambda kex: kex.pfs == kex_pfs)
		return directory

	def filter_secure(self):
		secure_ciphers = self
		secure_ciphers = secure_ciphers.filter_cipher(lambda cipher: cipher.keylen >= 128)
		secure_ciphers = secure_ciphers.filter_kex(lambda kex: kex.pfs and (not kex.export))
		secure_ciphers = secure_ciphers.filter_prf(lambda prf: prf.hashlen > 160)
		secure_ciphers = secure_ciphers.filter_sig_algorithm(lambda sig_algorithm: sig_algorithm.identifier in [ "ECDSA", "RSA" ])
		return secure_ciphers

	def __iter__(self):
		return iter(self._csuites.values())

	def __len__(self):
		return len(self._csuites)

	def dump(self):
		for (csid, suite) in self._csuites.items():
			print(suite)

	def __str__(self):
		return "CipherSuiteDirectory<%d>" % (len(self))
