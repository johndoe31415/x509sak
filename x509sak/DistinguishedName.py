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

import pyasn1.codec.der.decoder
from x509sak.OID import OID, OIDDB

class DistinguishedName(object):
	def __init__(self, oid_value_list):
		for (oid, value) in oid_value_list:
			assert(isinstance(oid, OID))
		self._oid_value_list = tuple(sorted(oid_value_list))

	@classmethod
	def from_asn1(cls, asn1):
		key_values = [ ]
		for element in asn1[0]:
			oid = OID.from_asn1(element[0]["type"])
			value = bytes(element[0]["value"])
			(value, tail) = pyasn1.codec.der.decoder.decode(value)
			value = str(value)
			key_values.append((oid, value))
		return cls(key_values)

	@property
	def rfc2253_str(self):
		def escape(text):
			if text.startswith("#"):
				text = "\\#" + text[1:]
			elif text.startswith(" "):
				text = "\\ " + text[1:]
			if text.endswith(" "):
				text = text[:-1] + "\\ "
			escape_chars = set("\\+\"<>;")
			escaped_text = [ ]
			for char in text:
				if char in escape_chars:
					escaped_text.append("\\%s" % (char))
				else:
					escaped_text.append(char)
			return "".join(escaped_text)
		return ",".join("%s=%s" % (OIDDB.RDNTypes.get(key, key), escape(value)) for (key, value) in self._oid_value_list)

	@property
	def pretty_str(self):
		return self.rfc2253_str

	def __eq__(self, other):
		return self._oid_value_list == other._oid_value_list

	def __lt__(self, other):
		return self._oid_value_list < other._oid_value_list

	def __neq__(self, other):
		return not (self == other)

	def __hash__(self):
		return hash(self._oid_value_list)

	def __str__(self):
		return "DN<%s>" % (self.rfc2253_str)
