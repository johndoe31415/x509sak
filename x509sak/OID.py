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

	def __repr__(self):
		return ".".join(str(value) for value in self._oid_value)

class OIDDB(object):
	"""Elliptic curve OIDs"""
	KnownCurveOIDs = {
		"1.2.840.10045.3.1.7":		"secp256r1",
	}
