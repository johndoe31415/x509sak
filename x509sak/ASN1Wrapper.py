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

import pyasn1.codec.der.encoder
from pyasn1_modules import rfc5280
from x509sak.DistinguishedName import DistinguishedName

class ASN1GeneralNameWrapper():
	def __init__(self, name, asn1_value):
		assert(isinstance(name, str))
		self._name = name
		self._asn1_value = asn1_value

	@property
	def name(self):
		return self._name

	@property
	def asn1_value(self):
		return self._asn1_value

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
			dn = DistinguishedName.from_asn1(self.asn1_value)
			result = dn.pretty_str
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
