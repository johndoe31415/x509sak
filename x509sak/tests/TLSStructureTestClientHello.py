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

from x509sak.tests import BaseTest
from x509sak.tls.Enums import TLSVersion, CipherSuite, CompressionMethod, ECPointFormats, SupportedGroups, ExtensionType, ContentType, HandshakeType
from x509sak.tls.TLSStructs import ClientHelloPkt, TLSExtensionFlag, TLSExtensionServerNameIndication, TLSExtensionECPointFormats, TLSExtensionSupportedGroups, RecordLayerPkt
from x509sak.tls.DataBuffer import DataBuffer
from x509sak.HexDump import HexDump

class TLSStructureTestClientHello(BaseTest):
	def test_client_hello(self):
		"""Trying to exactly replicate a ClientHello packet we sniffed using
		Wireshark. Serialization and deserialization."""

		reference_packet = bytes.fromhex("1603010076010000720301ba616e70c10cd842eacbf26cca4bfc7e736ce718b18f90becff766fb7cff045e00000ac00ac014c009c01300ff0100003f0000001700150000126a6f68616e6e65732d62617565722e636f6d000b000403000102000a000c000a001d0017001e00190018002300000016000000170000")

		(tls_version_recordlayer, tls_version_handshake) = TLSVersion.ProtocolTLSv1_0.value
		tls_extensions = [
			(TLSExtensionServerNameIndication, TLSExtensionServerNameIndication.create("johannes-bauer.com")),
			(TLSExtensionECPointFormats, {
				"content": {
					"point_formats": [
						{ "point_format": ECPointFormats.uncompressed },
						{ "point_format": ECPointFormats.ansiX962_compressed_prime },
						{ "point_format": ECPointFormats.ansiX962_compressed_char2 },
					],
				},
			}),
			(TLSExtensionSupportedGroups, {
				"content": {
					"groups": [
						{ "group": SupportedGroups.X25519 },
						{ "group": SupportedGroups.secp256r1 },
						{ "group": SupportedGroups.X448 },
						{ "group": SupportedGroups.secp521r1 },
						{ "group": SupportedGroups.secp384r1 },
					],
				},
			}),
			(TLSExtensionFlag, { "extension_id": ExtensionType.SessionTicketTLS }),
			(TLSExtensionFlag, { "extension_id": ExtensionType.encrypt_then_mac }),
			(TLSExtensionFlag, { "extension_id": ExtensionType.extended_master_secret }),
		]
		serialized_extensions = bytes().join(extension_class.pack(extension_data) for (extension_class, extension_data) in tls_extensions)

		client_hello = {
			"payload": {
				"handshake_protocol_version":	tls_version_handshake,
				"random":						bytes.fromhex("ba616e70c10cd842eacbf26cca4bfc7e736ce718b18f90becff766fb7cff045e"),
				"session_id":					bytes.fromhex(""),
				"cipher_suites": [
					{ "cipher_suite": CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA },
					{ "cipher_suite": CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA },
					{ "cipher_suite": CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA },
					{ "cipher_suite": CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA },
					{ "cipher_suite": CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV },
				],
				"compression_methods": [
					{ "compression_method": CompressionMethod.Null },
				],
				"extensions": serialized_extensions,
			},
		}
		serialized_client_hello = ClientHelloPkt.pack(client_hello)

		record_layer_packet = {
			"content_type":				ContentType.Handshake,
			"record_layer_version":		tls_version_recordlayer,
			"payload":					serialized_client_hello,
		}
		serialized_record_layer_packet = RecordLayerPkt.pack(record_layer_packet)
		self.assertEquals(reference_packet, serialized_record_layer_packet)

		deserialized_record_layer = RecordLayerPkt.unpack(DataBuffer(reference_packet))
		self.assertEqual(record_layer_packet, deserialized_record_layer)

		deserialized_client_hello = ClientHelloPkt.unpack(DataBuffer(record_layer_packet["payload"]))
		self.assertEqual(deserialized_client_hello, client_hello)

		extension_db = DataBuffer(client_hello["payload"]["extensions"])
		for (extension_class, expected_extension) in tls_extensions:
			deserialized_extension = extension_class.unpack(extension_db)
			self.assertEqual(deserialized_extension, expected_extension)
