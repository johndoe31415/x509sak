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

import re
import logging
import datetime
import tempfile
import base64
import enum
import pyasn1.codec.der.encoder
from pyasn1_modules import rfc2459
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.PEMDERObject import PEMDERObject
from x509sak.DistinguishedName import DistinguishedName
from x509sak.Tools import ASN1Tools
from x509sak.AlgorithmDB import SignatureAlgorithms
from x509sak.OID import OID, OIDDB
from x509sak.PublicKey import PublicKey
from x509sak.X509Extensions import X509ExtensionRegistry, X509Extensions
from x509sak.Exceptions import UnknownAlgorithmException

_log = logging.getLogger("x509sak.X509Certificate")

class X509CertificateClass(enum.IntEnum):
	CARoot = 1
	CAIntermediate = 2
	ClientServerAuth = 3
	ServerAuth = 4
	ClientAuth = 5
	Other = 6

class X509Certificate(PEMDERObject):
	_PEM_MARKER = "CERTIFICATE"
	_ASN1_MODEL = rfc2459.Certificate
	_CERT_VERIFY_REGEX = re.compile(r"error (?P<error_code>\d+) at (?P<depth>\d+) depth lookup:(?P<reason>.*)")

	def _post_decode_hook(self):
		self._extensions = None

	@property
	def signed_payload(self):
		return pyasn1.codec.der.encoder.encode(self._asn1["tbsCertificate"])

	@property
	def signature_algorithm(self):
		algorithm_oid = OID.from_asn1(self._asn1["signatureAlgorithm"]["algorithm"])
		sig_alg = SignatureAlgorithms.lookup("oid", algorithm_oid)
		if sig_alg is None:
			raise UnknownAlgorithmException("Unknown signature OID %s." % (algorithm_oid))
		return sig_alg

	@property
	def version(self):
		return int(self._asn1["tbsCertificate"]["version"]) + 1

	@property
	def serial(self):
		return int(self._asn1["tbsCertificate"]["serialNumber"])

	@property
	def pubkey(self):
		pubkey_asn1 = self._asn1["tbsCertificate"]["subjectPublicKeyInfo"]
		return PublicKey.from_asn1(pubkey_asn1)

	@property
	def subject(self):
		return DistinguishedName.from_asn1(self._asn1["tbsCertificate"]["subject"])

	@property
	def issuer(self):
		return DistinguishedName.from_asn1(self._asn1["tbsCertificate"]["issuer"])

	@property
	def valid_not_before(self):
		return ASN1Tools.parse_datetime(str(self._asn1["tbsCertificate"]["validity"]["notBefore"].getComponent()))

	@property
	def valid_not_after(self):
		return ASN1Tools.parse_datetime(str(self._asn1["tbsCertificate"]["validity"]["notAfter"].getComponent()))

	@property
	def subject_unique_id(self):
		return self._asn1["tbsCertificate"]["subjectUniqueID"].asInteger() if self._asn1["tbsCertificate"]["subjectUniqueID"].hasValue() else None

	@property
	def issuer_unique_id(self):
		return self._asn1["tbsCertificate"]["issuerUniqueID"].asInteger() if self._asn1["tbsCertificate"]["issuerUniqueID"].hasValue() else None

	@property
	def signature_alg_oid(self):
		signature_alg_oid = OID.from_str(str(self._asn1["signatureAlgorithm"]["algorithm"]))
		return signature_alg_oid

	@property
	def signature_alg_params(self):
		if self._asn1["signatureAlgorithm"]["parameters"].hasValue():
			return bytes(self._asn1["signatureAlgorithm"]["parameters"])
		else:
			return None

	@property
	def signature(self):
		signature = ASN1Tools.bitstring2bytes(self._asn1["signatureValue"])
		return signature

	@property
	def extensions(self):
		if self._extensions is None:
			self._extensions = self._get_extensions()
		return self._extensions

	def is_time_valid(self, now = None):
		if now is None:
			now = datetime.datetime.utcnow()
		return self.valid_not_before <= now <= self.valid_not_after

	def seconds_until_expires(self, now = None):
		if now is None:
			now = datetime.datetime.utcnow()
		return (self.valid_not_after - now).total_seconds()

	def _get_extensions(self):
		result = [ ]
		if self._asn1["tbsCertificate"]["extensions"] is not None:
			for extension in self._asn1["tbsCertificate"]["extensions"]:
				oid = OID.from_asn1(extension["extnID"])
				critical = bool(extension["critical"])
				value = bytes(extension["extnValue"])
				result.append(X509ExtensionRegistry.create(oid, critical, value))
		return X509Extensions(result)

	@property
	def is_selfsigned(self):
		return self.signed_by(self)

	def signed_by(self, potential_issuer, verbose_failure = False):
		with tempfile.NamedTemporaryFile(prefix = "subject_", suffix = ".crt") as subject, tempfile.NamedTemporaryFile(prefix = "issuer_", suffix = ".crt") as issuer:
			self.write_pemfile(subject.name)
			potential_issuer.write_pemfile(issuer.name)

			cmd = [ "openssl", "verify", "-CApath", "/dev/null" ]
			cmd += [ "-check_ss_sig", "-CAfile", issuer.name, subject.name ]
			result = SubprocessExecutor(cmd, on_failure = "pass").run()
			if result.successful:
				return True
			else:
				# Maybe the certificate signature was okay, but the complete
				# chain couldn't be established. This would still count as a
				# successful verification, however.
				match = self._CERT_VERIFY_REGEX.search(result.stdouterr_text)
				if match:
					match = match.groupdict()
					(error_code, depth) = (int(match["error_code"]), int(match["depth"]))
					chain_valid = (error_code == 2) and (depth == 1)
					if (not chain_valid) and verbose_failure:
						print("Certificate verification error, error_code %d, depth = %d. %s not signed by %s." % (error_code, depth, self, potential_issuer))
						result.dump()
					return chain_valid
				else:
					# If in doubt, reject.
					if verbose_failure:
						print("Certificate verification error. %s not signed by %s." % (self, potential_issuer))
						result.dump()
					return False

	def dump_pem(self, f = None):
		print("# Subject : %s" % (self.subject.pretty_str), file = f)
		print("# Issuer  : %s" % (self.issuer.pretty_str), file = f)
		print("# Validity: %s UTC - %s UTC" % (self.valid_not_before.strftime("%Y-%m-%d %H:%M:%S"), self.valid_not_after.strftime("%Y-%m-%d %H:%M:%S")), file = f)
		print("# Hash    : %s" % (self.hashval.hex()), file = f)
		print(self.to_pem_data(), file = f)
		print(file = f)

	@property
	def is_ca_certificate(self):
		if len(self.extensions) == 0:
			return True
		else:
			# RFC5280, 4.2: "A certificate MUST NOT include more than one
			# instance of a particular extension." -- we assume the certificate
			# is sane and elect to get the first extension.
			basic_constraints = self.extensions.get_first(OIDDB.X509Extensions.inverse("BasicConstraints"))
			if basic_constraints is None:
				# RFC5280, 4.2.1.9: "If the basic constraints extension is not present in a
				# version 3 certificate, or the extension is present but the cA boolean
				# is not asserted, then the certified public key MUST NOT be used to
				# verify certificate signatures.
				if self.version < 3:
					return True
				else:
					return False
			else:
				return basic_constraints.is_ca

	def classify(self):
		if self.is_ca_certificate:
			if self.is_selfsigned:
				return X509CertificateClass.CARoot
			else:
				return X509CertificateClass.CAIntermediate
		else:
			eku = self.extensions.get_first(OIDDB.X509Extensions.inverse("ExtendedKeyUsage"))
			if eku is not None:
				(client, server) = (eku.client_auth, eku.server_auth)
				if client and server:
					return X509CertificateClass.ClientServerAuth
				elif client:
					return X509CertificateClass.ClientAuth
				elif server:
					return X509CertificateClass.ServerAuth
			return X509CertificateClass.Other

	def __str__(self):
		return "X509Certificate<subject = %s, issuer = %s>" % (self.subject.rfc2253_str, self.issuer.rfc2253_str)
