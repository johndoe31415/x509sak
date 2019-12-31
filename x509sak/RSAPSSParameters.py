#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2019-2019 Johannes Bauer
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

import pyasn1.codec.der.decoder
import x509sak.ASN1Models as ASN1Models
from x509sak.OID import OID, OIDDB
from x509sak.AlgorithmDB import HashFunctions

class RSAPSSParameters():
	_TRAILER_FIELD_VALUES = {
		1:	0xbc,
	}

	def __init__(self, hash_algorithm_oid, mask_algorithm_oid, mask_hash_algorithm_oid, salt_length, trailer_field, asn1_tail = None):
		self._hash_algorithm_oid = hash_algorithm_oid
		self._mask_algorithm_oid = mask_algorithm_oid
		self._mask_hash_algorithm_oid = mask_hash_algorithm_oid
		self._salt_length = salt_length
		self._trailer_field = trailer_field
		self._asn1_tail = asn1_tail
		self._hash_algorithm = HashFunctions.lookup("oid", self.hash_algorithm_oid)
		self._mask_algorithm = OIDDB.RSAPSSMaskGenerationAlgorithm.get(self.mask_algorithm_oid)
		self._mask_hash_algorithm = HashFunctions.lookup("oid", self.mask_hash_algorithm_oid)

	@property
	def hash_algorithm_oid(self):
		return self._hash_algorithm_oid

	@property
	def mask_algorithm_oid(self):
		return self._mask_algorithm_oid

	@property
	def mask_hash_algorithm_oid(self):
		return self._mask_hash_algorithm_oid

	@property
	def hash_algorithm(self):
		return self._hash_algorithm

	@property
	def mask_algorithm(self):
		return self._mask_algorithm

	@property
	def mask_hash_algorithm(self):
		return self._mask_hash_algorithm

	@property
	def salt_length(self):
		return self._salt_length

	@property
	def trailer_field(self):
		return self._trailer_field

	@property
	def trailer_field_value(self):
		return self._TRAILER_FIELD_VALUES.get(self.trailer_field)

	@property
	def asn1_tail(self):
		return self._asn1_tail

	@classmethod
	def decode(cls, signature_alg_params):
		(asn1, tail) = pyasn1.codec.der.decoder.decode(signature_alg_params, asn1Spec = ASN1Models.RSASSA_PSS_Params())
		constructor_arguments = {
			"asn1_tail":	tail,
		}

		if asn1["hashAlgorithm"].hasValue():
			constructor_arguments["hash_algorithm_oid"] = OID.from_asn1(asn1["hashAlgorithm"]["algorithm"])
		else:
			# Default for RSASSA-PSS is SHA-1
			constructor_arguments["hash_algorithm_oid"] = OIDDB.HashFunctions.inverse("sha1")

		if asn1["maskGenAlgorithm"].hasValue():
			constructor_arguments["mask_algorithm_oid"] = OID.from_asn1(asn1["maskGenAlgorithm"]["algorithm"])
			(decoded_mask_parameters, tail) = pyasn1.codec.der.decoder.decode(asn1["maskGenAlgorithm"]["parameters"], asn1Spec = ASN1Models.HashAlgorithm())
			constructor_arguments["mask_hash_algorithm_oid"] = OID.from_asn1(decoded_mask_parameters["algorithm"])
		else:
			# Default for RSASSA-PSS is mgf1 with SHA-1
			constructor_arguments["mask_algorithm_oid"] = OIDDB.RSAPSSMaskGenerationAlgorithm.inverse("mgf1")
			constructor_arguments["mask_hash_algorithm_oid"] = OIDDB.HashFunctions.inverse("sha1")

		if asn1["saltLength"].hasValue():
			constructor_arguments["salt_length"] = int(asn1["saltLength"])
		else:
			constructor_arguments["salt_length"] = 20

		if asn1["trailerField"].hasValue():
			constructor_arguments["trailer_field"] = int(asn1["trailerField"])
		else:
			constructor_arguments["trailer_field"] = 1

		return cls(**constructor_arguments)

	def __str__(self):
		parts = [ ]
		parts.append("Hash=%s" % (self.hash_algorithm.name if (self.hash_algorithm is not None) else self.hash_algorithm_oid))
		parts.append("Mask=%s" % (self.mask_algorithm if (self.mask_algorithm is not None) else self.mask_algorithm_oid))
		parts.append("MaskHash=%s" % (self.mask_hash_algorithm.name if (self.mask_hash_algorithm is not None) else self.mask_hash_algorithm_oid))
		parts.append("SaltLen=%d" % (self.salt_length))
		if self.trailer_field_value is not None:
			parts.append("Trailer=#%d (0x%x)" % (self.trailer_field, self.trailer_field_value))
		else:
			parts.append("Trailer=#%d (unknown)" % (self.trailer_field))
		return "RSAPSSParameters<%s>" % (", ".join(parts))
