#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2020-2020 Johannes Bauer
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
from pyasn1_modules import rfc3279
from x509sak.PEMDERObject import PEMDERObject

class DSAParameters(PEMDERObject):
	"""Class that allows generate deliberately broken or oddball DSA
	parameters."""
	_PEM_MARKER = "DSA PARAMETERS"
	_ASN1_MODEL = rfc3279.Dss_Parms

	@classmethod
	def create(cls, p, q, g):
		asn1 = cls._ASN1_MODEL()
		asn1["p"] = p
		asn1["q"] = q
		asn1["g"] = g
		der_data = pyasn1.codec.der.encoder.encode(asn1)
		return cls(der_data)

	@property
	def p(self):
		return int(self._asn1["p"])

	@property
	def q(self):
		return int(self._asn1["q"])

	@property
	def g(self):
		return int(self._asn1["g"])

	@property
	def L(self):
		return self.p.bit_length()

	@property
	def N(self):
		return self.q.bit_length()

	def __str__(self):
		return "DSAParameters<%d/%d>" % (self.L, self.N)
