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

class OID(object):
	def __init__(self, oid_value):
		self._oid_value = tuple(oid_value)

	def __eq__(self, other):
		return (type(self) == type(other)) and (self._oid_value == other._oid_value)

	def __neq__(self, other):
		return not (self == other)

	def __lt__(self, other):
		return (type(self) == type(other)) and (self._oid_value < other._oid_value)

	def __hash__(self):
		return hash(self._oid_value)

	@classmethod
	def from_str(cls, oid_string):
		return cls([ int(value) for value in oid_string.split(".") ])

	@classmethod
	def from_asn1(cls, oid_asn1):
		return cls.from_str(str(oid_asn1))

	def __repr__(self):
		return ".".join(str(value) for value in self._oid_value)

class OIDDB(object):
	"""Elliptic curve OIDs."""
	EllipticCurves = {
		OID.from_str("1.2.840.10045.3.0.1"): "c2pnb163v1",
		OID.from_str("1.2.840.10045.3.0.2"): "c2pnb163v2",
		OID.from_str("1.2.840.10045.3.0.3"): "c2pnb163v3",
		OID.from_str("1.2.840.10045.3.0.4"): "c2pnb176v1",
		OID.from_str("1.2.840.10045.3.0.5"): "c2tnb191v1",
		OID.from_str("1.2.840.10045.3.0.6"): "c2tnb191v2",
		OID.from_str("1.2.840.10045.3.0.7"): "c2tnb191v3",
		OID.from_str("1.2.840.10045.3.0.10"): "c2pnb208w1",
		OID.from_str("1.2.840.10045.3.0.11"): "c2tnb239v1",
		OID.from_str("1.2.840.10045.3.0.12"): "c2tnb239v2",
		OID.from_str("1.2.840.10045.3.0.13"): "c2tnb239v3",
		OID.from_str("1.2.840.10045.3.0.16"): "c2pnb272w1",
		OID.from_str("1.2.840.10045.3.0.17"): "c2pnb304w1",
		OID.from_str("1.2.840.10045.3.0.18"): "c2tnb359v1",
		OID.from_str("1.2.840.10045.3.0.19"): "c2pnb368w1",
		OID.from_str("1.2.840.10045.3.0.20"): "c2tnb431r1",
		OID.from_str("1.2.840.10045.3.1.1"): "prime192v1",
		OID.from_str("1.2.840.10045.3.1.2"): "prime192v2",
		OID.from_str("1.2.840.10045.3.1.3"): "prime192v3",
		OID.from_str("1.2.840.10045.3.1.4"): "prime239v1",
		OID.from_str("1.2.840.10045.3.1.5"): "prime239v2",
		OID.from_str("1.2.840.10045.3.1.6"): "prime239v3",
		OID.from_str("1.2.840.10045.3.1.7"): "prime256v1",
		OID.from_str("1.3.36.3.3.2.8.1.1.1"): "brainpoolP160r1",
		OID.from_str("1.3.36.3.3.2.8.1.1.2"): "brainpoolP160t1",
		OID.from_str("1.3.36.3.3.2.8.1.1.3"): "brainpoolP192r1",
		OID.from_str("1.3.36.3.3.2.8.1.1.4"): "brainpoolP192t1",
		OID.from_str("1.3.36.3.3.2.8.1.1.5"): "brainpoolP224r1",
		OID.from_str("1.3.36.3.3.2.8.1.1.6"): "brainpoolP224t1",
		OID.from_str("1.3.36.3.3.2.8.1.1.7"): "brainpoolP256r1",
		OID.from_str("1.3.36.3.3.2.8.1.1.8"): "brainpoolP256t1",
		OID.from_str("1.3.36.3.3.2.8.1.1.9"): "brainpoolP320r1",
		OID.from_str("1.3.36.3.3.2.8.1.1.10"): "brainpoolP320t1",
		OID.from_str("1.3.36.3.3.2.8.1.1.11"): "brainpoolP384r1",
		OID.from_str("1.3.36.3.3.2.8.1.1.12"): "brainpoolP384t1",
		OID.from_str("1.3.36.3.3.2.8.1.1.13"): "brainpoolP512r1",
		OID.from_str("1.3.36.3.3.2.8.1.1.14"): "brainpoolP512t1",
		OID.from_str("1.3.132.0.1"): "sect163k1",
		OID.from_str("1.3.132.0.2"): "sect163r1",
		OID.from_str("1.3.132.0.3"): "sect239k1",
		OID.from_str("1.3.132.0.4"): "sect113r1",
		OID.from_str("1.3.132.0.5"): "sect113r2",
		OID.from_str("1.3.132.0.6"): "secp112r1",
		OID.from_str("1.3.132.0.7"): "secp112r2",
		OID.from_str("1.3.132.0.8"): "secp160r1",
		OID.from_str("1.3.132.0.9"): "secp160k1",
		OID.from_str("1.3.132.0.10"): "secp256k1",
		OID.from_str("1.3.132.0.15"): "sect163r2",
		OID.from_str("1.3.132.0.16"): "sect283k1",
		OID.from_str("1.3.132.0.17"): "sect283r1",
		OID.from_str("1.3.132.0.22"): "sect131r1",
		OID.from_str("1.3.132.0.23"): "sect131r2",
		OID.from_str("1.3.132.0.24"): "sect193r1",
		OID.from_str("1.3.132.0.25"): "sect193r2",
		OID.from_str("1.3.132.0.26"): "sect233k1",
		OID.from_str("1.3.132.0.27"): "sect233r1",
		OID.from_str("1.3.132.0.28"): "secp128r1",
		OID.from_str("1.3.132.0.29"): "secp128r2",
		OID.from_str("1.3.132.0.30"): "secp160r2",
		OID.from_str("1.3.132.0.31"): "secp192k1",
		OID.from_str("1.3.132.0.32"): "secp224k1",
		OID.from_str("1.3.132.0.33"): "secp224r1",
		OID.from_str("1.3.132.0.34"): "secp384r1",
		OID.from_str("1.3.132.0.35"): "secp521r1",
		OID.from_str("1.3.132.0.36"): "sect409k1",
		OID.from_str("1.3.132.0.37"): "sect409r1",
		OID.from_str("1.3.132.0.38"): "sect571k1",
		OID.from_str("1.3.132.0.39"): "sect571r1",
		OID.from_str("2.23.43.1.4.1"): "wap-wsg-idm-ecid-wtls1",
		OID.from_str("2.23.43.1.4.3"): "wap-wsg-idm-ecid-wtls3",
		OID.from_str("2.23.43.1.4.4"): "wap-wsg-idm-ecid-wtls4",
		OID.from_str("2.23.43.1.4.5"): "wap-wsg-idm-ecid-wtls5",
		OID.from_str("2.23.43.1.4.6"): "wap-wsg-idm-ecid-wtls6",
		OID.from_str("2.23.43.1.4.7"): "wap-wsg-idm-ecid-wtls7",
		OID.from_str("2.23.43.1.4.8"): "wap-wsg-idm-ecid-wtls8",
		OID.from_str("2.23.43.1.4.9"): "wap-wsg-idm-ecid-wtls9",
		OID.from_str("2.23.43.1.4.10"): "wap-wsg-idm-ecid-wtls10",
		OID.from_str("2.23.43.1.4.11"): "wap-wsg-idm-ecid-wtls11",
		OID.from_str("2.23.43.1.4.12"): "wap-wsg-idm-ecid-wtls12",
	}

	"""KeySpecification algorithm OIDs."""
	KeySpecificationAlgorithms = {
		OID.from_str("1.2.840.113549.1.1.1"):	"rsaEncryption",
		OID.from_str("1.2.840.10045.2.1"):		"ecPublicKey",
	}

	"""Signature algorithm OIDs."""
	SignatureAlgorithms = {
		OID.from_str("1.2.840.113549.1.1.2"):	"md2WithRsaEncryption",
		OID.from_str("1.2.840.113549.1.1.3"):	"md4WithRsaEncryption",
		OID.from_str("1.2.840.113549.1.1.4"):	"md5WithRsaEncryption",
		OID.from_str("1.2.840.113549.1.1.5"):	"sha1WithRsaEncryption",
		OID.from_str("1.2.840.113549.1.1.11"):	"sha256WithRsaEncryption",
	}

	"""Relative Distinguished Name type component OIDs."""
	RDNTypes = {
		OID.from_str("2.5.4.0"):					"objectClass",
		OID.from_str("2.5.4.1"):					"aliasedEntryName",
		OID.from_str("2.5.4.2"):					"knowledgeinformation",
		OID.from_str("2.5.4.3"):					"CN",
		OID.from_str("2.5.4.4"):					"surname",
		OID.from_str("2.5.4.5"):					"serialNumber",
		OID.from_str("2.5.4.6"):					"C",
		OID.from_str("2.5.4.7"):					"L",
		OID.from_str("2.5.4.8"):					"ST",
		OID.from_str("2.5.4.9"):					"STREET",
		OID.from_str("2.5.4.10"):					"O",
		OID.from_str("2.5.4.11"):					"OU",
		OID.from_str("2.5.4.12"):					"title",
		OID.from_str("2.5.4.13"):					"description",
		OID.from_str("1.2.840.113549.1.9.1"):		"emailAddress",
		OID.from_str("0.9.2342.19200300.100.1.1"):	"UID",
		OID.from_str("0.9.2342.19200300.100.1.25"):	"DC",
	}

