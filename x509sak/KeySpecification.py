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

from x509sak.OID import OIDDB
from x509sak.KwargsChecker import KwargsChecker
from x509sak.AlgorithmDB import Cryptosystems

class KeySpecification(object):
	def __init__(self, cryptosystem, parameters = None):
		assert(isinstance(cryptosystem, Cryptosystems))
		if parameters is None:
			parameters = { }
		self._cryptosystem = cryptosystem
		self._parameters = dict(parameters)

		constraints = KwargsChecker(required_arguments = set(param[0] for param in self._cryptosystem.value.spec_parameters))
		constraints.check(parameters, hint = "keyspec for cryptosystem %s" % (self._cryptosystem.name))

	@property
	def cryptosystem(self):
		return self._cryptosystem

	@classmethod
	def from_cmdline_str(cls, text):
		text = text.lower()
		if text.startswith("rsa:"):
			parameters = { "bitlen": int(text[4:]) }
			return cls(Cryptosystems.RSA, parameters = parameters)
		elif text.startswith("ecc:"):
			parameters = { "curvename": text[4:] }
			return cls(Cryptosystems.ECC_ECDSA, parameters = parameters)
		elif text.startswith("eddsa:"):
			parameters = { "curvename": text[6:] }
			return cls(Cryptosystems.ECC_EdDSA, parameters = parameters)
		else:
			raise ValueError("Cannot interpret command line string '%s'." % (text))

	def __eq__(self, other):
		return (self.cryptosystem, self._parameters) == (other.cryptosystem, other._parameters)

	def __getitem__(self, key):
		return self._parameters[key]

	def __str__(self):
		if self._cryptosystem == Cryptosystems.RSA:
			return "RSA-%d" % (self["bitlen"])
		elif self._cryptosystem == Cryptosystems.ECC_ECDSA:
			return "ECC-%s" % (self["curvename"])
		elif self._cryptosystem == Cryptosystems.ECC_EdDSA:
			return "EdDSA-%s" % (self["curvename"])
		return "%s-%s" % (self._cryptosystem.name, str(self._parameters))
