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

import pyasn1.codec.der.encoder
from pyasn1_modules import rfc2437
from x509sak.NumberTheory import NumberTheory
from x509sak.PEMDERObject import PEMDERObject

class RSAPrivateKey(PEMDERObject):
	"""Class that allows generate deliberately broken or oddball RSA
	keypairs."""
	_PEM_MARKER = "RSA PRIVATE KEY"
	_ASN1_MODEL = rfc2437.RSAPrivateKey

	@classmethod
	def create(cls, p, q, e = 0x10001, swap_e_d = False, valid_only = True):
		n = p * q
		phi_n = (p - 1) * (q - 1)
		gcd = NumberTheory.gcd(e, phi_n)
		if (gcd != 1) and valid_only:
			raise Exception("e = 0x%x isnt't relative prime to phi(n), gcd = 0x%x." % (e, gcd))
		d = NumberTheory.modinv(e, phi_n)
		if swap_e_d:
			(e, d) = (d, e)

		exp1 = d % (p - 1)
		exp2 = d % (q - 1)
		coeff = NumberTheory.modinv(q, p)
		asn1 = cls._ASN1_MODEL()
		asn1["version"] = 0
		asn1["modulus"] = n
		asn1["publicExponent"] = e
		asn1["privateExponent"] = d
		asn1["prime1"] = p
		asn1["prime2"] = q
		asn1["exponent1"] = exp1
		asn1["exponent2"] = exp2
		asn1["coefficient"] = coeff
		der = pyasn1.codec.der.encoder.encode(asn1)
		return cls(der)

	@property
	def p(self):
		return int(self._asn1["prime1"])

	@property
	def q(self):
		return int(self._asn1["prime2"])

	@property
	def n(self):
		return int(self._asn1["modulus"])

	@property
	def e(self):
		return int(self._asn1["publicExponent"])

	@property
	def d(self):
		return int(self._asn1["privateExponent"])

	def __str__(self):
		return "RSAPrivateKey<%d bits>" % (self.n.bit_length())
