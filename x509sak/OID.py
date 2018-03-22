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
		OID.from_str("1.2.840.10045.3.1.7"):	"secp256r1",
	}


	"""Cryptosystem algorithm OIDs."""
	CryptosystemAlgorithms = {
		OID.from_str("1.2.840.113549.1.1.1"):	"rsaEncryption",
		OID.from_str("1.2.840.10045.2.1"):		"ecPublicKey",
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

