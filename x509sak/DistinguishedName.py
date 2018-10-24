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
import pyasn1.error
import pyasn1.type.char
import pyasn1.codec.der.encoder
import pyasn1.codec.der.decoder
from pyasn1.type.char import UTF8String
from x509sak.OID import OID, OIDDB
from x509sak.Exceptions import InvalidInputException
from x509sak.SecurityEstimator import SecurityEstimator

class RelativeDistinguishedName(object):
	_RDNItem = collections.namedtuple("RDNItem", [ "oid", "derdata", "asn1", "decodable", "printable" ])

	def __init__(self, rdn_list):
		assert(isinstance(rdn_list, (tuple, list)))
		assert(all(isinstance(value[0], OID) for value in rdn_list))
		assert(all(isinstance(value[1], bytes) for value in rdn_list))
		if len(rdn_list) == 0:
			raise InvalidInputException("Empty RDN is not permitted.")
		self._rdn_list = tuple(self._decode_item(oid, derdata) for (oid, derdata) in rdn_list)

	@classmethod
	def create(cls, *key_values):
		def encode(text):
			asn1 = UTF8String(text)
			derdata = pyasn1.codec.der.encoder.encode(asn1)
			return derdata
		if (len(key_values) % 2) != 0:
			raise InvalidInputException("Length of key/values must be evenly divisible by two.")
		rdn_list = [ ]
		for (key, value) in zip(key_values[ : : 2], key_values[1 : : 2]):
			assert(isinstance(key, str))
			assert(isinstance(value, (str, bytes)))
			oid = OIDDB.RDNTypes.inverse(key)
			rdn_list.append((oid, encode(value)))
		return cls(rdn_list)

	@classmethod
	def _decode_item(cls, oid, derdata):
		try:
			(decoded_attribute_value, tail) = pyasn1.codec.der.decoder.decode(derdata)
			if len(tail) != 0:
				# Refuse to decode if there's trailing data.
				decoded_attribute_value = None
		except pyasn1.error.PyAsn1Error:
			decoded_attribute_value = None

		if isinstance(decoded_attribute_value, (pyasn1.type.char.UTF8String, pyasn1.type.char.PrintableString, pyasn1.type.char.IA5String, pyasn1.type.char.TeletexString, pyasn1.type.char.BMPString, pyasn1.type.char.UniversalString)):
			# Use the string representation
			printable_value = str(decoded_attribute_value)
		else:
			# Use the bytes representation
			printable_value = "#" + derdata.hex()

		return cls._RDNItem(oid = oid, derdata = derdata, asn1 = decoded_attribute_value, decodable = decoded_attribute_value is not None, printable = printable_value)

	@property
	def component_cnt(self):
		return len(self._rdn_list)

	def has_component(self, oid):
		assert(isinstance(oid, OID))
		return any(oid == item.oid for item in self._rdn_list)

	def get_value(self, oid):
		assert(isinstance(oid, OID))
		for item in self._rdn_list:
			if item.oid == oid:
				return item
		return None

	@property
	def rfc2253_str(self):
		def char_needs_hex_escaping(char):
			try:
				char.encode("ascii")
				codepoint = ord(char)
				return not (32 <= codepoint < 127)
			except UnicodeEncodeError:
				return True

		def escape(text):
			if isinstance(text, str):
				escaped_text = [ ]
				if text.startswith("#"):
					escaped_text.append("\\#")
					text = text[1:]
				elif text.startswith(" "):
					escaped_text.append("\\ ")
					text = text[1:]
				spc_end = text.endswith(" ")
				if spc_end:
					text = text[:-1]
				escape_chars = set("\\+\"<>;,")
				for char in text:
					if char in escape_chars:
						escaped_text.append("\\%s" % (char))
					elif char_needs_hex_escaping(char):
						escaped_text += [ "\\%02X" % (c) for c in char.encode("utf-8") ]
					else:
						escaped_text.append(char)
				if spc_end:
					escaped_text.append("\\ ")
				return "".join(escaped_text)
			else:
				# bytes handling
				return "#" + text.hex()
		return "+".join("%s=%s" % (OIDDB.RDNTypes.get(item.oid, item.oid), escape(item.printable or "/")) for item in reversed(self._rdn_list))

	@property
	def pretty_str(self):
		def escape(text):
			if (" " in text) or ("\"" in text) or ("," in text):
				return "\"%s\"" % (text.replace("\"", "\\\""))
			else:
				return text
		return ", ".join("%s = %s" % (OIDDB.RDNTypes.get(item.oid, item.oid), escape(item.printable or "/")) for item in sorted(self._rdn_list))

	def __iter__(self):
		return iter(self._rdn_list)

	def __hash__(self):
		return hash(tuple(sorted(self._rdn_list)))

	def __eq__(self, other):
		return sorted(self._rdn_list) == sorted(other._rdn_list)

	def __neq__(self, other):
		return not (self == other)

	def __str__(self):
		return "RDN<%s>" % (self.rfc2253_str)

class DistinguishedName(object):
	def __init__(self, rdns):
		assert(isinstance(rdns, (list, tuple)))
		assert(all(isinstance(rdn, RelativeDistinguishedName) for rdn in rdns))
		self._rdns = tuple(rdns)

	def get_all(self, oid):
		assert(isinstance(oid, OID))
		return [ rdn for rdn in self._rdns if rdn.has_component(oid) ]

	@classmethod
	def from_asn1(cls, asn1):
		# asn1 is of type rfc2459.Name and contains the RDNSequence
		rdn_sequence = asn1[0]

		rdns = [ ]
		for rdn in rdn_sequence:
			rdn_elements = [ ]
			for attribute_type_and_value in rdn:
				attribute_type_oid = OID.from_asn1(attribute_type_and_value[0])
				attribute_value = bytes(attribute_type_and_value[1])
				rdn_elements.append((attribute_type_oid, attribute_value))
			rdns.append(RelativeDistinguishedName(rdn_elements))
		dn = cls(rdns)
		return dn

	@property
	def rfc2253_str(self):
		return ",".join(rdn.rfc2253_str for rdn in reversed(self._rdns))

	@property
	def pretty_str(self):
		return ", ".join(rdn.pretty_str for rdn in self._rdns)

	def analyze(self, analysis_options = None):
		return SecurityEstimator.algorithm("dn", analysis_options = analysis_options).analyze(self)

	def __iter__(self):
		return iter(self._rdns)

	def __eq__(self, other):
		return self._rdns == other._rdns

	def __neq__(self, other):
		return not (self == other)

	def __lt__(self, other):
		return self._rdns < other._rdns

	def __hash__(self):
		return hash(self._rdns)

	def __str__(self):
		return "DN<%s>" % (self.rfc2253_str)
