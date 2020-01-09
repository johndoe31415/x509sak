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

import enum
from x509sak.tls.Structure import Structure, instantiate_member as IM
from x509sak.tls.Enums import SignatureAlgorithm, HashAlgorithm

class SCTVersion(enum.IntEnum):
	v1 = 0

class SCTSignatureType(enum.IntEnum):
	certificate_timestamp = 0
	tree_hash = 1

DigitalSignature = Structure(name = "DigitalSignature", members = [
	IM("hash_algorithm",				"uint8", enum_class = HashAlgorithm),
	IM("sig_algorithm",					"uint8", enum_class = SignatureAlgorithm),
	IM("signature",						"opaque16"),
])

SignedCertificateTimestamp = Structure(name = "SignedCertificateTimestamps", members = [
	IM("sct_version",					"uint8", enum_class = SCTVersion),
	IM("log_id",						"array[32]"),
	IM("timestamp",						"uint64"),
	IM("extensions",					"opaque16"),
	DigitalSignature,
])

SignedCertificateTimestampList = Structure(name = "SignedCertificateTimestampList", members = [
	IM("payload",						"opaque16", contains_array = True, inner = Structure([
		IM("sct",							"opaque16", inner = SignedCertificateTimestamp)
	])),
])
