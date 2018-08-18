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
from x509sak.KeySpecification import Cryptosystem
from x509sak.PublicKey import PublicKey
from x509sak.Exceptions import KeyCorruptException

class RSAPrivateKey(PEMDERObject):
	"""Class that allows generate deliberately broken or oddball RSA
	keypairs."""
	_PEM_MARKER = "RSA PRIVATE KEY"
	_ASN1_MODEL = rfc2437.RSAPrivateKey

	@classmethod
	def create(cls, p, q, e = 0x10001, swap_e_d = False, valid_only = True, carmichael_totient = False):
		n = p * q
		if not carmichael_totient:
			totient = (p - 1) * (q - 1)
		else:
			totient = NumberTheory.lcm(p - 1, q - 1)
		gcd = NumberTheory.gcd(e, totient)
		if (gcd != 1) and valid_only:
			raise KeyCorruptException("e = 0x%x isnt't relative prime to totient, gcd = 0x%x. Either accept broken keys or fix e." % (e, gcd))
		d = NumberTheory.modinv(e, totient)
		if swap_e_d:
			(e, d) = (d, e)

		dmp1 = d % (p - 1)
		dmq1 = d % (q - 1)
		iqmp = NumberTheory.modinv(q, p)
		asn1 = cls._ASN1_MODEL()
		asn1["version"] = 0
		asn1["modulus"] = n
		asn1["publicExponent"] = e
		asn1["privateExponent"] = d
		asn1["prime1"] = p
		asn1["prime2"] = q
		asn1["exponent1"] = dmp1
		asn1["exponent2"] = dmq1
		asn1["coefficient"] = iqmp
		der = pyasn1.codec.der.encoder.encode(asn1)
		return cls(der)

	@property
	def cryptosystem(self):
		return Cryptosystem.RSA

	@property
	def pubkey(self):
		return PublicKey.create(cryptosystem = self.cryptosystem, parameters = { "n": self.n, "e": self.e })

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

	@property
	def dmp1(self):
		return int(self._asn1["exponent1"])

	@property
	def dmq1(self):
		return int(self._asn1["exponent2"])

	@property
	def iqmp(self):
		return int(self._asn1["coefficient"])

	@property
	def phi_n(self):
		"""Returns the Euler Totient phi(n)."""
		return (self.p - 1) * (self.q - 1)

	@property
	def lambda_n(self):
		"""Returns the Carmichael Totient lambda(n)."""
		return NumberTheory.lcm(self.p - 1, self.q - 1)

	def check_integrity(self, msg = 12345678987654321):
		# Assert gcd(e, phi(n)) == 1
		phi_n = (self.p - 1) * (self.q - 1)
		gcd = NumberTheory.gcd(phi_n, self.e)
		if gcd != 1:
			raise KeyCorruptException("Expected gcd(phi(n), e) to be 1, but was %d." % (gcd))

		# Truncate msg if too large for exponent
		msg = msg % self.n

		# Calculate normale signature and verify
		sig = pow(msg, self.d, self.n)
		verify = pow(sig, self.e, self.n)
		if verify != msg:
			raise KeyCorruptException("Expected verify value %d, but got %d." % (msg, verify))

		# Test that RSA-CRT constants work
		m1 = pow(msg, self.dmp1, self.p)
		m2 = pow(msg, self.dmq1, self.q)
		sig_crt = (((self.iqmp * (m1 - m2)) % self.p) * self.q) + m2
		if sig != sig_crt:
			raise KeyCorruptException("Expected same signature for naive signature as RSA-CRT signature, but former was 0x%x and latter 0x%x." % (sig, sig_crt))

	def __str__(self):
		return "RSAPrivateKey<%d bits>" % (self.n.bit_length())
