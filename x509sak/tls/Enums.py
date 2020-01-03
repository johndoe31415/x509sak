#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2015-2019 Johannes Bauer
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

class TLSVersionRecordLayer(enum.IntEnum):
	"""TLS version as 16 bit integer (major is high byte, minor is low
	byte) as it is used on the record layer."""
	ProtocolTLSv1_0 = 0x0301

class TLSVersionHandshake(enum.IntEnum):
	"""TLS version as 16 bit integer (major is high byte, minor is low
	byte) as it is used inside the handshake protocol."""
	ProtocolSSLv3_0 = 0x0300
	ProtocolTLSv1_0 = 0x0301
	ProtocolTLSv1_1 = 0x0302
	ProtocolTLSv1_2 = 0x0303

class TLSVersion(enum.Enum):
	"""Combination of both to achieve a speicific version."""
	ProtocolTLSv1_0 = (TLSVersionRecordLayer.ProtocolTLSv1_0, TLSVersionHandshake.ProtocolTLSv1_0)
	ProtocolTLSv1_1 = (TLSVersionRecordLayer.ProtocolTLSv1_0, TLSVersionHandshake.ProtocolTLSv1_1)
	ProtocolTLSv1_2 = (TLSVersionRecordLayer.ProtocolTLSv1_0, TLSVersionHandshake.ProtocolTLSv1_2)
	ProtocolTLSv1_3 = (TLSVersionRecordLayer.ProtocolTLSv1_0, TLSVersionHandshake.ProtocolTLSv1_2)

class ContentType(enum.IntEnum):
	"""ContentType as Sect. 6.2.1. of RFC5246"""
	ChangeCipherSpec = 20
	Alert = 21
	Handshake = 22
	ApplicationData = 23

class HandshakeType(enum.IntEnum):
	"""HandshakeType as Sect. 7.4. of RFC5246"""
	HelloRequest = 0
	ClientHello = 1
	ServerHello = 2
	Certificate = 11
	ServerKeyExchange = 12
	CertificateRequest = 13
	ServerHelloDone = 14
	CertificateVerify = 15
	ClientKeyExchange = 16
	Finished = 20

class ChangeCipherSpecType(enum.IntEnum):
	"""ChangeCipherSpec as Sect. 7.1. of RFC5246"""
	ChangeCipherSpec = 1

class TLSAlertLevel(enum.IntEnum):
	"""AlertLevel as Sect. 7.2. of RFC5246"""
	Warn = 1
	Fatal = 2

class TLSAlertDescription(enum.IntEnum):
	"""AlertDescription as Sect. 7.2. of RFC5246"""
	CloseNotify = 0
	UnexpectedMessage = 10
	BadRecordMAC = 20
	DecryptionFailedRESERVED = 21
	RecordOverflow = 22
	DecompressionFailure = 30
	HandshakeFailure = 40
	NoCertificateRESERVED = 41
	BadCertificate = 42
	UnsupportedCertificate = 43
	CertificateRevoked = 44
	CertificateExpired = 45
	CertificateUnknown = 46
	IllegalParameter = 47
	UnknownCA = 48
	AccessDenied = 49
	DecodeError = 50
	DecryptError = 51
	ExportRestrictionRESERVED = 60
	ProtocolVersion = 70
	InsufficientSecurity = 71
	InternalError = 80
	UserCanceled = 90
	NoRenegotiation = 100
	UnsupportedExtension = 110

class CipherSuite(enum.IntEnum):
	"""Cipher Suites as defined in various RFCs."""
	# RFC5246 A.5
	TLS_NULL_WITH_NULL_NULL = 0x0
	TLS_RSA_WITH_NULL_MD5 = 0x01
	TLS_RSA_WITH_NULL_SHA = 0x02
	TLS_RSA_WITH_NULL_SHA256 = 0x3B
	TLS_RSA_WITH_RC4_128_MD5 = 0x04
	TLS_RSA_WITH_RC4_128_SHA = 0x05
	TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x0A
	TLS_RSA_WITH_AES_128_CBC_SHA = 0x2F
	TLS_RSA_WITH_AES_256_CBC_SHA = 0x35
	TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x3C
	TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x3D
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x0D
	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x10
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x13
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x16
	TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x30
	TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x31
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x32
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x33
	TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x36
	TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x37
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x38
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x39
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0x3E
	TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x3F
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x40
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x67
	TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0x68
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x69
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x6A
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x6B
	TLS_DH_anon_WITH_RC4_128_MD5 = 0x18
	TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x1B
	TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x34
	TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x3A
	TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 0x6C
	TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 0x6D

	# RFC5932
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x41
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x42
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x43
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x44
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x45
	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = 0x46

	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x84
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x85
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x86
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x87
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x88
	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = 0x89

	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xBA
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0xBB
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xBC
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0xBD
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xBE
	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = 0xBF

	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0xC0
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0xC1
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0xC2
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0xC3
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0xC4
	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = 0xC5

	# RFC5288
	TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x9C
	TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x9D
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x9E
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x9F
	TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0xA0
	TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0xA1
	TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0xA2
	TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0xA3
	TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = 0xA4
	TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = 0xA5
	TLS_DH_anon_WITH_AES_128_GCM_SHA256 = 0xA6
	TLS_DH_anon_WITH_AES_256_GCM_SHA384 = 0xA7

	# RFC4785
	TLS_PSK_WITH_NULL_SHA = 0x2c
	TLS_DHE_PSK_WITH_NULL_SHA = 0x2d
	TLS_RSA_PSK_WITH_NULL_SHA = 0x2e

	# RFC5289
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256  = 0xC023
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384  = 0xC024
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC025
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC026
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xC029
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xC02A
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  = 0xC02B
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  = 0xC02C
	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02D
	TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02E
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xC031
	TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xC032

	# RFC4492
	TLS_ECDH_ECDSA_WITH_NULL_SHA = 0xC001
	TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xC002
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC003
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xC004
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xC005

	TLS_ECDHE_ECDSA_WITH_NULL_SHA = 0xC006
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xC007
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA  = 0xC008
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A

	TLS_ECDH_RSA_WITH_NULL_SHA = 0xC00B
	TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xC00C
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xC00D
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xC00E
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xC00F

	TLS_ECDHE_RSA_WITH_NULL_SHA = 0xC010
	TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xC011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014

	TLS_ECDH_anon_WITH_NULL_SHA = 0xC015
	TLS_ECDH_anon_WITH_RC4_128_SHA = 0xC016
	TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = 0xC017
	TLS_ECDH_anon_WITH_AES_128_CBC_SHA = 0xC018
	TLS_ECDH_anon_WITH_AES_256_CBC_SHA = 0xC019

	# RFC4162
	TLS_RSA_WITH_SEED_CBC_SHA = 0x96
	TLS_DH_DSS_WITH_SEED_CBC_SHA = 0x97
	TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x98
	TLS_DHE_DSS_WITH_SEED_CBC_SHA = 0x99
	TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x9A
	TLS_DH_anon_WITH_SEED_CBC_SHA = 0x9B

	# RFC5469
	TLS_RSA_WITH_DES_CBC_SHA = 0x9
	TLS_DH_DSS_WITH_DES_CBC_SHA = 0xC
	TLS_DH_RSA_WITH_DES_CBC_SHA = 0xF
	TLS_DHE_DSS_WITH_DES_CBC_SHA = 0x12
	TLS_DHE_RSA_WITH_DES_CBC_SHA = 0x15
	TLS_DH_anon_WITH_DES_CBC_SHA = 0x1A
	TLS_RSA_WITH_IDEA_CBC_SHA = 0x7

	# RFC4346
	TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x3
	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x6
	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x8
	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = 0xB
	TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = 0xE
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x11
	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x14
	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = 0x17
	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x19
	TLS_KRB5_WITH_DES_CBC_SHA = 0x1E
	TLS_KRB5_WITH_3DES_EDE_CBC_SHA = 0x1F
	TLS_KRB5_WITH_RC4_128_SHA = 0x20
	TLS_KRB5_WITH_IDEA_CBC_SHA = 0x21
	TLS_KRB5_WITH_DES_CBC_MD5 = 0x22
	TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = 0x23
	TLS_KRB5_WITH_RC4_128_MD5 = 0x24
	TLS_KRB5_WITH_IDEA_CBC_MD5 = 0x25
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x26
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x27
	TLS_KRB5_EXPORT_WITH_RC4_40_SHA = 0x28
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x29
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x2A
	TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = 0x2B

	# draft-ietf-tls-openpgp-02
	TLS_PGP_DHE_DSS_WITH_CAST_CBC_SHA = 0x101
	TLS_PGP_DHE_DSS_WITH_IDEA_CBC_SHA = 0x102
	TLS_PGP_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x103
	TLS_PGP_DHE_DSS_WITH_CAST_CBC_RMD = 0x104
	TLS_PGP_DHE_DSS_WITH_IDEA_CBC_RMD = 0x105
	TLS_PGP_DHE_DSS_WITH_3DES_EDE_CBC_RMD = 0x106
	TLS_PGP_DHE_RSA_WITH_CAST_CBC_SHA = 0x110
	TLS_PGP_RSA_WITH_CAST_CBC_SHA = 0x120
	TLS_PGP_RSA_WITH_IDEA_CBC_SHA = 0x121
	TLS_PGP_RSA_WITH_3DES_EDE_CBC_SHA = 0x122
	TLS_PGP_RSA_WITH_CAST_CBC_RMD = 0x123
	TLS_PGP_RSA_WITH_IDEA_CBC_RMD = 0x124
	TLS_PGP_RSA_WITH_3DES_EDE_CBC_RMD = 0x125
	TLS_PGP_DSA_WITH_NULL_SHA = 0x1F0

	# RFC5746
	TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0xff

	# RFC7507
	TLS_FALLBACK_SCSV = 0x5600

class CompressionMethod(enum.IntEnum):
	"""Compression method byte."""
	Null = 0
	Deflate = 1
	LZS = 64

class ExtensionType(enum.IntEnum):
	"""Extension types for hello packets."""
	server_name = 0			# [RFC6066]
	max_fragment_length = 1 	# [RFC6066]
	client_certificate_url = 2 	# [RFC6066]
	trusted_ca_keys = 3 	# [RFC6066]
	truncated_hmac = 4	# [RFC6066]
	status_request = 5 	# [RFC6066]
	user_mapping = 6 	# [RFC4681]
	client_authz = 7 	# [RFC5878]
	server_authz = 8 	# [RFC5878]
	cert_type = 9 	# [RFC6091]
	supported_groups = 10 # (renamed from "elliptic_curves") 	[RFC4492][RFC-ietf-tls-negotiated-ff-dhe-10]
	ec_point_formats = 11 	# [RFC4492]
	srp = 12 	# [RFC5054]
	signature_algorithms = 13 	# [RFC5246]
	use_srtp = 14 	# [RFC5764]
	heartbeat = 15 	# [RFC6520]
	application_layer_protocol_negotiation = 16 	# [RFC7301]
	status_request_v2 = 17 	# [RFC6961]
	signed_certificate_timestamp = 18 	# [RFC6962]
	client_certificate_type = 19 	# [RFC7250]
	server_certificate_type = 20 	# [RFC7250]
	padding = 21 # (TEMPORARY - registered 2014-03-12, expires 2016-03-12) 	[draft-ietf-tls-padding]
	encrypt_then_mac = 22 	# [RFC7366]
	extended_master_secret = 23 # (TEMPORARY - registered 2014-09-26, expires 2015-09-26) 	[draft-ietf-tls-session-hash]
	SessionTicketTLS = 35 	# [RFC4507]
	renegotiation_info = 65281 	# [RFC5746]

class HashAlgorithm(enum.IntEnum):
	# RFC 5246 7.4.1.4.1
	md5 = 1
	sha1 = 2
	sha224 = 3
	sha256 = 4
	sha384 = 5
	sha512 = 6

class SignatureAlgorithm(enum.IntEnum):
	# RFC 5246 7.4.1.4.1
	RSA = 1
	DSA = 2
	ECDSA = 3

class KeyExchangeAlgorithm(enum.IntEnum):
	# RFC 5246 7.4.3
	DHE_DSS = 1
	DHE_RSA = 2
	DH_ANON = 3
	RSA = 4
	DH_DSS = 5
	DH_RSA = 6

class SupportedGroups(enum.IntEnum):
	# RFC 4492 5.1.1
	sect163k1 = 1
	sect163r1 = 2
	sect163r2 = 3
	sect193r1 = 4
	sect193r2 = 5
	sect233k1 = 6
	sect233r1 = 7
	sect239k1 = 8
	sect283k1 = 9
	sect283r1 = 10
	sect409k1 = 11
	sect409r1 = 12
	sect571k1 = 13
	sect571r1 = 14
	secp160k1 = 15
	secp160r1 = 16
	secp160r2 = 17
	secp192k1 = 18
	secp192r1 = 19
	secp224k1 = 20
	secp224r1 = 21
	secp256k1 = 22
	secp256r1 = 23
	secp384r1 = 24
	secp521r1 = 25
	arbitrary_explicit_prime_curves = 0xFF01
	arbitrary_explicit_char2_curves = 0xFF02
	X25519 = 0x1d
	X448 = 0x1e

class ECPointFormats(enum.IntEnum):
	# RFC 4492 5.1.2
	uncompressed = 0
	ansiX962_compressed_prime = 1
	ansiX962_compressed_char2 = 2

class ServerNameType(enum.IntEnum):
	"""Server name indication TLS extension server type."""
	Hostname = 0
