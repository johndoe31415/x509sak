#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2019 Johannes Bauer
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

import urllib.parse
import pyasn1.codec.der.encoder
from pyasn1_modules import rfc5280
from x509sak.DistinguishedName import DistinguishedName

class ASN1GeneralNameWrapper():
	KNOWN_TYPE_NAMES = set([ "otherName", "rfc822Name", "dNSName", "x400Address", "directoryName", "ediPartyName", "uniformResourceIdentifier", "iPAddress", "registeredID" ])

	def __init__(self, name, asn1_value):
		assert(isinstance(name, str))
		assert(name in self.KNOWN_TYPE_NAMES)
		self._name = name
		self._asn1_value = asn1_value
		self._cached = None

	@property
	def name(self):
		return self._name

	@property
	def asn1_value(self):
		return self._asn1_value

	@property
	def directory_name(self):
		assert(self.name == "directoryName")
		if self._cached is None:
			self._cached = DistinguishedName.from_asn1(self.asn1_value)
		return self._cached

	@property
	def uri(self):
		assert(self.name == "uniformResourceIdentifier")
		if self._cached is None:
			self._cached = urllib.parse.urlparse(self.str_value)
		return self._cached

	@property
	def str_value(self):
		if self.name in [ "dNSName", "rfc822Name", "uniformResourceIdentifier" ]:
			result = str(self.asn1_value)
		elif (self.name == "iPAddress") and (len(self.asn1_value) == 4):
			result = ".".join(str(v) for v in self.asn1_value)
		elif (self.name == "iPAddress") and (len(self.asn1_value) == 16):
			result = ":".join("%02x" % (v) for v in self.asn1_value)
		elif self.name == "otherName":
			oid = self.asn1_value["type-id"]
			inner_value = bytes(self.asn1_value["value"])
			result = "otherName:%s:#%s" % (oid, inner_value.hex())
		elif self.name == "directoryName":
			result = self.directory_name.pretty_str
		else:
			result = "%s:#%s" % (self._name, pyasn1.codec.der.encoder.encode(self.asn1_value).hex())
		return result

	@classmethod
	def from_asn1(cls, general_name):
		for name in rfc5280.GeneralName.componentType:
			value = general_name.getComponentByName(name, None, instantiate = False)
			if value is not None:
				return cls(name, value)
		assert(False)

	def __eq__(self, other):
		return (self.name, self.asn1_value) == (other.name, other.asn1_value)

	def __neq__(self, other):
		return not (self == other)

	def __repr__(self):
		return "%s = %s" % (self.name, self.str_value)

class ASN1GeneralNamesWrapper():
	def __init__(self, general_names):
		self._names = general_names

	def filter_by_type(self, typename):
		assert(typename in ASN1GeneralNameWrapper.KNOWN_TYPE_NAMES)
		return ASN1GeneralNamesWrapper([ general_name for general_name in self if (general_name.name == typename) ])

	def get_contained_uri_scheme_set(self, ignore_case = True):
		uri_schemes = set()
		for general_name in self.filter_by_type("uniformResourceIdentifier"):
			uri_scheme = general_name.uri.scheme
			if ignore_case:
				uri_scheme = uri_scheme.lower()
			uri_schemes.add(uri_scheme)
		return uri_schemes

	@classmethod
	def from_asn1(cls, general_names):
		general_names = [ ]
		for general_name_asn1 in general_names:
			general_names.append(ASN1GeneralNameWrapper.from_asn1(general_name_asn1))
		return cls(general_names)

	def __iter__(self):
		return iter(self._names)

	def __len__(self):
		return len(self._names)

	def __repr__(self):
		return "GeneralNames<%s>" % (", ".join(str(name) for name in self))
