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

from pyasn1.type import namedtype, univ
from x509sak.PEMDERObject import PEMDERObject
from x509sak.OID import OID
from x509sak.Exceptions import InvalidInputException
from x509sak.AlgorithmDB import Cryptosystems, PublicKeyAlgorithms
from x509sak.PublicKey import PublicKey
from x509sak.CurveDB import CurveDB
from pyasn1_modules import rfc3280

class _EDPrivateKey(univ.Sequence):
	"""Minimalistic draft-ietf-curdle-pkix-10 implementation. Not correct
	(e.g., cannot deal with attached public keys)."""

	componentType = namedtype.NamedTypes(
		namedtype.NamedType("version", univ.Integer()),
		namedtype.NamedType("privateKeyAlgorithm", rfc3280.AlgorithmIdentifier()),
		namedtype.NamedType("privateKey", univ.OctetString()),
	)

class EDPrivateKey(PEMDERObject):
	_PEM_MARKER = "PRIVATE KEY"
	_ASN1_MODEL = _EDPrivateKey

	def _post_decode_hook(self):
		if self._asn1["privateKeyAlgorithm"]["algorithm"] is None:
			raise InvalidInputException("EdDSA private key does not contain curve OID. Cannot proceed.")

		curve_oid = OID.from_asn1(self._asn1["privateKeyAlgorithm"]["algorithm"])
		pk_alg = PublicKeyAlgorithms.lookup("oid", curve_oid)
		self._curve = CurveDB().instanciate(oid = curve_oid)
		self._prehash = pk_alg.value.fixed_params["prehash"]
		private_key = bytes(self._asn1["privateKey"])
		if (private_key[0] != 0x04) or (private_key[1] != self.curve.element_octet_cnt):
			raise InvalidInputException("EdDSA private key does start with 04 %02x, but with %02x %02x." % (self.curve.element_octet_cnt, private_key[0], private_key[1]))
		if len(private_key) != self.curve.element_octet_cnt + 2:
			raise InvalidInputException("EdDSA private key length expected to be %d octets, but was %d octets." % (self.curve.element_octet_cnt + 2, len(private_key[0])))
		self._priv = private_key[2:]

	@property
	def cryptosystem(self):
		return Cryptosystems.ECC_EdDSA

	@property
	def pubkey(self):
		(scalar, point) = self.curve.expand_secret(self.priv)
		return PublicKey.create(cryptosystem = self.cryptosystem, parameters = { "curve": self.curve, "x": point.x, "y": point.y })

	@property
	def scalar(self):
		(scalar, point) = self.curve.expand_secret(self.priv)
		return scalar

	@property
	def curve(self):
		return self._curve

	@property
	def prehash(self):
		return self._prehash

	@property
	def priv(self):
		return self._priv

	def __str__(self):
		return "EDPrivateKey<%s>" % (self.curve)
