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

class ASN1NameWrapper(object):
	def __init__(self, name, value):
		self._name = name
		self._value = value

	@property
	def name(self):
		return self._name

	@property
	def value(self):
		return self._value

	@property
	def pretty_value(self):
		if self.name in [ "dNSName", "rfc822Name" ]:
			return str(self.value)
		elif (self.name == "iPAddress") and (len(self.value) == 4):
			return ".".join(str(v) for v in self.value)
		elif (self.name == "iPAddress") and (len(self.value) == 16):
			return ":".join("%02x" % (v) for v in self.value)
		else:
			return "#" + bytes(self.value).hex()

	def __eq__(self, other):
		return (self.name, self.value) == (other.name, other.value)

	def __neq__(self, other):
		return not (self == other)

	def __str__(self):
		return "%s = %s" % (self.name, self.pretty_value)
