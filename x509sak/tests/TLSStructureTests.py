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
from x509sak.tls.Enums import TLSVersion, CipherSuite, CompressionMethod
from x509sak.tls.TLSStructs import ClientHelloPkt
from x509sak.tls.DataBuffer import DataBuffer

class TLSStructureTests(BaseTest):
	def test_client_hello(self):
		(tls_version_recordlayer, tls_version_handshake) = TLSVersion.ProtocolTLSv1_2.value
		values = {
			"payload": {
				"handshake_protocol_version":	tls_version_handshake,
				"random":						bytes.fromhex("00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"),
				"session_id":					bytes.fromhex(""),
				"cipher_suites": [
					{ "cipher_suite": CipherSuite.TLS_RSA_WITH_RC4_128_SHA },
					{ "cipher_suite": CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256 },
				],
				"compression_methods": [
					{ "compression_method": CompressionMethod.Null },
				],
				"extensions": b"",
			},
		}
#		binary_encoding = bytes.fromhex("""
#		""".replace("\n", ""))
		encoded = ClientHelloPkt.pack(values)
		decoded = ClientHelloPkt.unpack(DataBuffer(encoded))
		print(decoded)
