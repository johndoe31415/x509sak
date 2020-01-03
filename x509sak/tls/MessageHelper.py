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

import os
from x509sak.tls.Enums import TLSVersion, CipherSuite, CompressionMethod, ECPointFormats, SupportedGroups, ExtensionType
from x509sak.tls.TLSStructs import TLSExtensionECPointFormats, TLSExtensionSupportedGroups, TLSExtensionFlag
from x509sak.tls.CipherSuiteDirectory import CipherSuiteDirectory

class ClientHelloHelper():
	def __init__(self, tls_version = TLSVersion.ProtocolTLSv1_2, include_secure_renegotiation_scsv = True, cipher_suite_directory = None, allow_tls_compression = False):
		self._tls_version = tls_version
		self._include_secure_renegotiation_scsv = include_secure_renegotiation_scsv
		self._cipher_suite_directory = cipher_suite_directory
		if self._cipher_suite_directory is None:
			self._cipher_suite_directory = self._create_cipher_suite_directory()
		self._cipher_suite_directory = self._cipher_suite_directory.filter(lambda cs: not cs.is_pseudo_suite)
		self._allow_tls_compression = allow_tls_compression

	@property
	def cipher_suite_directory(self):
		return self._cipher_suite_directory

	def _create_cipher_suite_directory(self):
		csd = CipherSuiteDirectory()
		csd = csd.filter_cipher(lambda cipher: cipher.cipher in [ "AES", "ChaCha20", "DES", "Camellia", "RC4" ])
		csd = csd.filter_cipher(lambda cipher: cipher.keylen >= 128)
		csd = csd.filter_kex(lambda kex: not kex.export)
		csd = csd.filter_prf(lambda prf: prf.hashlen >= 160)
		csd = csd.filter_sig_algorithm(lambda sig_algorithm: sig_algorithm.identifier in [ "ECDSA", "RSA" ])
		return csd

	def _create_cipher_suite_list(self):
		cipher_suites = [ cs.csid for cs in self._cipher_suite_directory ]
		if self._include_secure_renegotiation_scsv:
			cipher_suites.append(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
		return cipher_suites

	def _create_compression_methods(self):
		methods = [
			CompressionMethod.Null,
		]
		if self._allow_tls_compression:
			methods += [
				CompressionMethod.Deflate,
				CompressionMethod.LZS,
			]
		return methods

	def _create_supported_groups_list(self):
		return [
			SupportedGroups.X25519,
			SupportedGroups.X448,
			SupportedGroups.secp256r1,
			SupportedGroups.secp384r1,
			SupportedGroups.secp521r1,
		]

	def _create_tls_extensions(self, server_name = None):
		tls_extensions = [ ]
		if server_name is not None:
			tls_extensions.append((TLSExtensionServerNameIndication, TLSExtensionServerNameIndication.create(server_name)))
		tls_extensions += [
			(TLSExtensionECPointFormats, {
				"content": {
					"point_formats": [
						ECPointFormats.uncompressed,
						ECPointFormats.ansiX962_compressed_prime,
						ECPointFormats.ansiX962_compressed_char2,
					],
				},
			}),
			(TLSExtensionSupportedGroups, {
				"content": {
					"groups": self._create_supported_groups_list(),
				},
			}),
			(TLSExtensionFlag, { "extension_id": ExtensionType.SessionTicketTLS }),
			(TLSExtensionFlag, { "extension_id": ExtensionType.encrypt_then_mac }),
			(TLSExtensionFlag, { "extension_id": ExtensionType.extended_master_secret }),
		]
		return tls_extensions

	def create(self, server_name = None):
		client_hello = {
			"payload": {
				"handshake_protocol_version":	self._tls_version.value[1],
				"random":						os.urandom(32),
				"session_id":					bytes(),
				"cipher_suites":				self._create_cipher_suite_list(),
				"compression_methods":			self._create_compression_methods(),
				"extensions":					self._create_tls_extensions(),
			}
		}
		return client_hello
