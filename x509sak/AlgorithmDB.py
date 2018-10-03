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
from x509sak.OID import OIDDB

class LookupEnum(enum.Enum):
	@classmethod
	def lookup(cls, key, value):
		for item in cls:
			if getattr(item.value, key) == value:
				return item
		return None

def _to_enum(enum_name, items):
	def _escape(text):
		text = text.replace("-", "_")
		text = text.replace("/", "_")
		return text
	item_dict = { _escape(item.name): item for item in items }
	return LookupEnum(enum_name, item_dict)

Derating = collections.namedtuple("Derating", [ "security_lvl_bits", "reason" ])

HashFunction = collections.namedtuple("HashFunction", [ "name", "pretty_name", "output_bits", "derating", "oid" ])
HashFunctions = _to_enum("HashFunctions", [
	HashFunction(name = "md2", pretty_name = "MD2", output_bits = 128, derating = Derating(security_lvl_bits = 0, reason = "Søren S. Thomsen (2008). \"An improved preimage attack on MD2\""), oid = None),
	HashFunction(name = "md4", pretty_name = "MD4", output_bits = 128, derating = Derating(security_lvl_bits = 0, reason = "Yu Sasaki; et al. (2007). \"New message difference for MD4\""), oid = None),
	HashFunction(name = "md5", pretty_name = "MD5", output_bits = 128, derating = Derating(security_lvl_bits = 0, reason = "Xie Tao; Fanbao Liu & Dengguo Feng (2013). \"Fast Collision Attack on MD5\""), oid = None),
	HashFunction(name = "sha0", pretty_name = "SHA0", output_bits = 160, derating = Derating(security_lvl_bits = 0, reason = "Manuel, Stéphane; Peyrin, Thomas (2008). \"Collisions on SHA-0 in One Hour\""), oid = None),
	HashFunction(name = "sha1", pretty_name = "SHA-1", output_bits = 160, derating = Derating(security_lvl_bits = 0, reason = "Stevens, Marc; Bursztein, Elie; Karpman, Pierre; Albertini, Ange; Markov, Yarik. \"The first collision for full SHA-1\""), oid = OIDDB.HashFunctions.inverse("sha1")),
	HashFunction(name = "sha224", pretty_name = "SHA-224", output_bits = 224, derating = None, oid = OIDDB.HashFunctions.inverse("sha224")),
	HashFunction(name = "sha256", pretty_name = "SHA-256", output_bits = 256, derating = None, oid = OIDDB.HashFunctions.inverse("sha256")),
	HashFunction(name = "sha384", pretty_name = "SHA-384", output_bits = 384, derating = None, oid = OIDDB.HashFunctions.inverse("sha384")),
	HashFunction(name = "sha512", pretty_name = "SHA-512", output_bits = 512, derating = None, oid = OIDDB.HashFunctions.inverse("sha512")),
	HashFunction(name = "sha3-224", pretty_name = "SHA3-224", output_bits = 224, derating = None, oid = OIDDB.HashFunctions.inverse("sha3-224")),
	HashFunction(name = "sha3-256", pretty_name = "SHA3-256", output_bits = 256, derating = None, oid = OIDDB.HashFunctions.inverse("sha3-256")),
	HashFunction(name = "sha3-384", pretty_name = "SHA3-384", output_bits = 384, derating = None, oid = OIDDB.HashFunctions.inverse("sha3-384")),
	HashFunction(name = "sha3-512", pretty_name = "SHA3-512", output_bits = 512, derating = None, oid = OIDDB.HashFunctions.inverse("sha3-512")),
	HashFunction(name = "shake256-912", pretty_name = "Shake256-912", output_bits = 912, derating = None, oid = None),
])

Cryptosystem = collections.namedtuple("Cryptosystem", [ "name", "shortcut", "spec_parameters" ])
Cryptosystems = _to_enum("Cryptosystems", [
	Cryptosystem(name = "RSA", shortcut = "rsa", spec_parameters = [ ("bitlen", int) ]),
	Cryptosystem(name = "ECC/ECDSA", shortcut = "ecc", spec_parameters = [ ("curvename", str) ]),
	Cryptosystem(name = "ECC/EdDSA", shortcut = "eddsa", spec_parameters = [ ("curvename", str) ]),
	Cryptosystem(name = "ECC/ECDH", shortcut = "ed-ecdh", spec_parameters = [ ("curvename", str) ]),
])

SignatureFunction = collections.namedtuple("SignatureFunction", [ "name", "pretty_name", "cryptosystem" ])
SignatureFunctions = _to_enum("SignatureFunctions", [
	SignatureFunction(name = "rsa-encryption", pretty_name = "RSA", cryptosystem = Cryptosystems.RSA),
	SignatureFunction(name = "rsa-ssa-pss", pretty_name = "RSA/PSS", cryptosystem = Cryptosystems.RSA),
	SignatureFunction(name = "ecdsa", pretty_name = "ECDSA", cryptosystem = Cryptosystems.ECC_ECDSA),
	SignatureFunction(name = "eddsa", pretty_name = "EdDSA", cryptosystem = Cryptosystems.ECC_EdDSA),
])

EdDSAParams = collections.namedtuple("EdDSAParams", [ "curve", "prehash" ])

SignatureAlgorithm = collections.namedtuple("SignatureAlgorithm", [ "name", "hash_fnc", "sig_fnc", "sig_params", "oid" ])
SignatureAlgorithms = _to_enum("SignatureAlgorithms", [
	SignatureAlgorithm(name = "md2WithRsaEncryption", hash_fnc = HashFunctions.md2, sig_fnc = SignatureFunctions.rsa_encryption, sig_params = None, oid = OIDDB.SignatureAlgorithms.inverse("md2WithRsaEncryption")),
	SignatureAlgorithm(name = "md4WithRsaEncryption", hash_fnc = HashFunctions.md4, sig_fnc = SignatureFunctions.rsa_encryption, sig_params = None, oid = OIDDB.SignatureAlgorithms.inverse("md4WithRsaEncryption")),
	SignatureAlgorithm(name = "md5WithRsaEncryption", hash_fnc = HashFunctions.md5, sig_fnc = SignatureFunctions.rsa_encryption, sig_params = None, oid = OIDDB.SignatureAlgorithms.inverse("md5WithRsaEncryption")),
	SignatureAlgorithm(name = "sha1WithRsaEncryption", hash_fnc = HashFunctions.sha1, sig_fnc = SignatureFunctions.rsa_encryption, sig_params = None, oid = OIDDB.SignatureAlgorithms.inverse("sha1WithRsaEncryption")),
	SignatureAlgorithm(name = "sha256WithRsaEncryption", hash_fnc = HashFunctions.sha256, sig_fnc = SignatureFunctions.rsa_encryption, sig_params = None, oid = OIDDB.SignatureAlgorithms.inverse("sha256WithRsaEncryption")),
	SignatureAlgorithm(name = "sha384WithRsaEncryption", hash_fnc = HashFunctions.sha384, sig_fnc = SignatureFunctions.rsa_encryption, sig_params = None, oid = OIDDB.SignatureAlgorithms.inverse("sha384WithRsaEncryption")),
	SignatureAlgorithm(name = "sha512WithRsaEncryption", hash_fnc = HashFunctions.sha512, sig_fnc = SignatureFunctions.rsa_encryption, sig_params = None, oid = OIDDB.SignatureAlgorithms.inverse("sha512WithRsaEncryption")),
	SignatureAlgorithm(name = "ecdsa-with-SHA224", hash_fnc = HashFunctions.sha224, sig_fnc = SignatureFunctions.ecdsa, sig_params = None, oid = OIDDB.SignatureAlgorithms.inverse("ecdsa-with-SHA224")),
	SignatureAlgorithm(name = "ecdsa-with-SHA256", hash_fnc = HashFunctions.sha256, sig_fnc = SignatureFunctions.ecdsa, sig_params = None, oid = OIDDB.SignatureAlgorithms.inverse("ecdsa-with-SHA256")),
	SignatureAlgorithm(name = "ecdsa-with-SHA384", hash_fnc = HashFunctions.sha384, sig_fnc = SignatureFunctions.ecdsa, sig_params = None, oid = OIDDB.SignatureAlgorithms.inverse("ecdsa-with-SHA384")),
	SignatureAlgorithm(name = "ecdsa-with-SHA512", hash_fnc = HashFunctions.sha512, sig_fnc = SignatureFunctions.ecdsa, sig_params = None, oid = OIDDB.SignatureAlgorithms.inverse("ecdsa-with-SHA512")),
	SignatureAlgorithm(name = "RSASSA-PSS", hash_fnc = None, sig_fnc = SignatureFunctions.rsa_ssa_pss, sig_params = None, oid = OIDDB.SignatureAlgorithms.inverse("RSASSA-PSS")),
	SignatureAlgorithm(name = "Ed25519", hash_fnc = HashFunctions.sha512, sig_fnc = SignatureFunctions.eddsa, sig_params = EdDSAParams(curve = "Ed25519", prehash = False), oid = OIDDB.KeySpecificationAlgorithms.inverse("id-Ed25519")),
	SignatureAlgorithm(name = "Ed448", hash_fnc = HashFunctions.shake256_912, sig_fnc = SignatureFunctions.eddsa, sig_params = EdDSAParams(curve = "Ed448", prehash = False), oid = OIDDB.KeySpecificationAlgorithms.inverse("id-Ed448")),
])

PublicKeyAlgorithm = collections.namedtuple("PublicKeyAlgorithm", [ "name", "cryptosystem", "fixed_params", "oid" ])
PublicKeyAlgorithms = _to_enum("PublicKeyAlgorithms", [
	PublicKeyAlgorithm(name = "RSA", cryptosystem = Cryptosystems.RSA, fixed_params = None, oid = OIDDB.KeySpecificationAlgorithms.inverse("rsaEncryption")),
	PublicKeyAlgorithm(name = "ECC", cryptosystem = Cryptosystems.ECC_ECDSA, fixed_params = None, oid = OIDDB.KeySpecificationAlgorithms.inverse("ecPublicKey")),
	PublicKeyAlgorithm(name = "Ed25519", cryptosystem = Cryptosystems.ECC_EdDSA, fixed_params = { "prehash": False }, oid = OIDDB.KeySpecificationAlgorithms.inverse("id-Ed25519")),
	PublicKeyAlgorithm(name = "Ed448", cryptosystem = Cryptosystems.ECC_EdDSA, fixed_params = { "prehash": False }, oid = OIDDB.KeySpecificationAlgorithms.inverse("id-Ed448")),
	PublicKeyAlgorithm(name = "X25519", cryptosystem = Cryptosystems.ECC_ECDH, fixed_params = { "prehash": True }, oid = OIDDB.KeySpecificationAlgorithms.inverse("id-X25519")),
	PublicKeyAlgorithm(name = "X448", cryptosystem = Cryptosystems.ECC_ECDH, fixed_params = { "prehash": True }, oid = OIDDB.KeySpecificationAlgorithms.inverse("id-X448")),
])
