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

from pyasn1.type import tag, namedtype, univ
from x509sak.PEMDERObject import PEMDERObject
from x509sak.Tools import ASN1Tools, ECCTools
from x509sak.OID import OID, OIDDB
from x509sak.Exceptions import InvalidInputException, UnknownAlgorithmException
from x509sak.KeySpecification import Cryptosystem
from x509sak.PublicKey import PublicKey

class _ECPrivateKey(univ.Sequence):
	"""Minimalistic RFC5915 implementation."""

	componentType = namedtype.NamedTypes(
		namedtype.NamedType("version", univ.Integer()),
		namedtype.NamedType("privateKey", univ.OctetString()),
		namedtype.NamedType("parameters", univ.ObjectIdentifier().subtype(explicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
		namedtype.NamedType("publicKey", univ.BitString().subtype(explicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
	)

class ECPrivateKey(PEMDERObject):
	_PEM_MARKER = "EC PRIVATE KEY"
	_ASN1_MODEL = _ECPrivateKey

	def _post_decode_hook(self):
		if self._asn1["parameters"] is None:
			raise InvalidInputException("ECC private key does not contain curve OID. Cannot proceed.")
		if self._asn1["publicKey"] is None:
			raise InvalidInputException("ECC private key does not contain public key. Cannot proceed.")

		curve_oid = OID.from_asn1(self._asn1["parameters"])
		curve = CurveDB().lookup_by_oid(curve_oid)
		if curve is None:
			raise UnknownAlgorithmException("Unable to determine curve for curve OID %s." % (curve_oid))
		self._curve = curve["name"]

		self._d = int.from_bytes(self._asn1["privateKey"], byteorder = "big")
		(self._x, self._y) = ECCTools.decode_enc_pubkey(ASN1Tools.bitstring2bytes(self._asn1["publicKey"]))

	@property
	def cryptosystem(self):
		return Cryptosystem.ECC

	@property
	def pubkey(self):
		return PublicKey.create(cryptosystem = self.cryptosystem, parameters = { "curve": self.curve, "x": self.x, "y": self.y })

	@property
	def curve(self):
		return self._curve

	@property
	def d(self):
		return self._d

	@property
	def x(self):
		return self._x

	@property
	def y(self):
		return self._y

	def __str__(self):
		return "ECPrivateKey<%s>" % (self.curve)
