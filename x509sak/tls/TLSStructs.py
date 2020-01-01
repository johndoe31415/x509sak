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

from x509sak.tls.Enums import TLSVersionRecordLayer, ContentType, CipherSuite, CompressionMethod
from x509sak.tls.Structure import Structure, StructureMember as SM

RecordLayerPkt = Structure((
	SM("content_type",			"uint8", enum_class = ContentType),
	SM("record_layer_version",	"uint16", enum_class = TLSVersionRecordLayer),
	SM("payload",				"opaque16"),
))

ClientHelloPkt = Structure((
	SM("handshake_type",				"fixed[01]"),
	SM("payload",						"opaque24", inner = Structure((
		SM("handshake_protocol_version",	"uint16", enum_class = TLSVersionHandshake),
		SM("random",						"array[16]"),
		SM("session_id",					"opaque8"),
		SM("cipher_suites",					"opaque24", inner_array = True, inner = Structure((
			SM("cipher_suite",					"uint16", enum_class = CipherSuite),
		))),
		SM("compression_methods",			"opaque24", inner_array = True, inner = Structure((
			SM("compression_method"				"uint8", enum_class = CompressionMethod),
		))),
		SM("extensions",					"opaque16"),
	))),
))
