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

import collections

Derating = collections.namedtuple("Derating", [ "security_lvl_bits", "reason" ])

HashFunction = collections.namedtuple("HashFunction", [ "name", "output_bits", "derating" ])
HashFunctions = { fnc.name: fnc for fnc in [
	HashFunction(name = "md2", output_bits = 128, derating = Derating(security_lvl_bits = 0, reason = "Søren S. Thomsen (2008). \"An improved preimage attack on MD2\"")),
	HashFunction(name = "md4", output_bits = 128, derating = Derating(security_lvl_bits = 0, reason = "Yu Sasaki; et al. (2007). \"New message difference for MD4\"")),
	HashFunction(name = "md5", output_bits = 128, derating = Derating(security_lvl_bits = 0, reason = "Xie Tao; Fanbao Liu & Dengguo Feng (2013). \"Fast Collision Attack on MD5\"")),
	HashFunction(name = "sha0", output_bits = 160, derating = Derating(security_lvl_bits = 0, reason = "Manuel, Stéphane; Peyrin, Thomas (2008). \"Collisions on SHA-0 in One Hour\"")),
	HashFunction(name = "sha1", output_bits = 160, derating = Derating(security_lvl_bits = 0, reason = "Stevens, Marc; Bursztein, Elie; Karpman, Pierre; Albertini, Ange; Markov, Yarik. \"The first collision for full SHA-1\"")),
	HashFunction(name = "sha224", output_bits = 224, derating = None),
	HashFunction(name = "sha256", output_bits = 256, derating = None),
	HashFunction(name = "sha384", output_bits = 384, derating = None),
	HashFunction(name = "sha512", output_bits = 512, derating = None),
	HashFunction(name = "sha3-224", output_bits = 224, derating = None),
	HashFunction(name = "sha3-256", output_bits = 256, derating = None),
	HashFunction(name = "sha3-384", output_bits = 384, derating = None),
	HashFunction(name = "sha3-512", output_bits = 512, derating = None),
]}

SignatureFunction = collections.namedtuple("SignatureFunction", [ "name" ])
SignatureFunctions = { fnc.name: fnc for fnc in [
	SignatureFunction(name = "rsa-encryption"),
	SignatureFunction(name = "rsa-ssa-pss"),
	SignatureFunction(name = "dsa"),
	SignatureFunction(name = "ecdsa"),
]}

SignatureAlgorithm = collections.namedtuple("SignatureAlgorithm", [ "name", "hash_fnc", "sig_fnc" ])
SignatureAlgorithms = { fnc.name: fnc for fnc in [
	SignatureAlgorithm(name = "md2WithRsaEncryption", hash_fnc = HashFunctions["md2"], sig_fnc = SignatureFunctions["rsa-encryption"]),
	SignatureAlgorithm(name = "md4WithRsaEncryption", hash_fnc = HashFunctions["md4"], sig_fnc = SignatureFunctions["rsa-encryption"]),
	SignatureAlgorithm(name = "md5WithRsaEncryption", hash_fnc = HashFunctions["md5"], sig_fnc = SignatureFunctions["rsa-encryption"]),
	SignatureAlgorithm(name = "sha1WithRsaEncryption", hash_fnc = HashFunctions["sha1"], sig_fnc = SignatureFunctions["rsa-encryption"]),
	SignatureAlgorithm(name = "sha256WithRsaEncryption", hash_fnc = HashFunctions["sha256"], sig_fnc = SignatureFunctions["rsa-encryption"]),
	SignatureAlgorithm(name = "ecdsa-with-SHA224", hash_fnc = HashFunctions["sha224"], sig_fnc = SignatureFunctions["ecdsa"]),
	SignatureAlgorithm(name = "ecdsa-with-SHA256", hash_fnc = HashFunctions["sha256"], sig_fnc = SignatureFunctions["ecdsa"]),
	SignatureAlgorithm(name = "ecdsa-with-SHA384", hash_fnc = HashFunctions["sha384"], sig_fnc = SignatureFunctions["ecdsa"]),
	SignatureAlgorithm(name = "ecdsa-with-SHA512", hash_fnc = HashFunctions["sha512"], sig_fnc = SignatureFunctions["ecdsa"]),
	SignatureAlgorithm(name = "RSASSA-PSS", hash_fnc = None, sig_fnc = SignatureFunctions["rsa-ssa-pss"]),
]}
