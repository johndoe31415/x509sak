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
import tempfile
import pyasn1.codec.der.encoder
from pyasn1_modules import rfc2459
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.PEMDERObject import PEMDERObject
from x509sak.DistinguishedName import DistinguishedName
from x509sak.Tools import CmdTools, ASN1Tools
from x509sak.KeySpecification import SignatureAlgorithm
from x509sak.OID import OID
from x509sak.PublicKey import PublicKey
from x509sak.X509Extensions import X509ExtensionRegistry, X509Extensions

_log = logging.getLogger("x509sak.X509Certificate")

class X509Certificate(PEMDERObject):
	_PEM_MARKER = "CERTIFICATE"
	_ASN1_MODEL = rfc2459.Certificate
	_CERT_VERIFY_REGEX = re.compile(r"error (?P<error_code>\d+) at (?P<depth>\d+) depth lookup:(?P<reason>.*)")

	@property
	def signed_payload(self):
		return pyasn1.codec.der.encoder.encode(self._asn1["tbsCertificate"])

	@property
	def signature_algorithm(self):
		algorithm_oid = OID.from_asn1(self._asn1["signatureAlgorithm"]["algorithm"])
		return SignatureAlgorithm.from_sigalg_oid(algorithm_oid)

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
		return ASN1Tools.parse_datetime(str(self._asn1["tbsCertificate"]["validity"]["notBefore"]["utcTime"])) or ASN1Tools.parse_datetime(str(self._asn1["tbsCertificate"]["validity"]["notBefore"]["generalTime"]))

	@property
	def valid_not_after(self):
		return ASN1Tools.parse_datetime(str(self._asn1["tbsCertificate"]["validity"]["notAfter"]["utcTime"])) or ASN1Tools.parse_datetime(str(self._asn1["tbsCertificate"]["validity"]["notAfter"]["generalTime"]))

	def get_extensions(self):
		print("=" * 120)
		result = [ ]
		if self._asn1["tbsCertificate"]["extensions"] is not None:
			for extension in self._asn1["tbsCertificate"]["extensions"]:
				oid = OID.from_asn1(extension["extnID"])
				critical = bool(extension["critical"])
				value = bytes(extension["extnValue"])
				print(oid, value.hex())
				result.append(X509ExtensionRegistry.create(oid, critical, value))
		return X509Extensions(result)

	def is_selfsigned(self):
		return self.signed_by(self)

	def signed_by(self, potential_issuer):
		with tempfile.NamedTemporaryFile(prefix = "subject_", suffix = ".crt") as subject, tempfile.NamedTemporaryFile(prefix = "issuer_", suffix = ".crt") as issuer:
			self.write_pemfile(subject.name)
			potential_issuer.write_pemfile(issuer.name)

			cmd = [ "openssl", "verify", "-CApath", "/dev/null" ]
			cmd += [ "-check_ss_sig", "-CAfile", issuer.name, subject.name ]
			_log.debug("Executing: %s", CmdTools.cmdline(cmd))
			(success, output) = SubprocessExecutor.run(cmd, exception_on_failure = False, return_stdout = True)
			if success:
				return True
			else:
				# Maybe the certificate signature was okay, but the complete
				# chain couldn't be established. This would still count as a
				# successful verification, however.
				result = self._CERT_VERIFY_REGEX.search(output.decode())
				if result:
					result = result.groupdict()
					(error_code, depth) = (int(result["error_code"]), int(result["depth"]))
					if (error_code == 2) and (depth == 1):
						return True
					else:
						return False
				else:
					# If in doubt, reject.
					return False

	def dump_pem(self, f = None):
		print("# Subject : %s" % (self.subject.pretty_str), file = f)
		print("# Issuer  : %s" % (self.issuer.pretty_str), file = f)
		print("# Validity: %s UTC - %s UTC" % (self.valid_not_before.strftime("%Y-%m-%d %H:%M:%S"), self.valid_not_after.strftime("%Y-%m-%d %H:%M:%S")), file = f)
		print("# Hash    : %s" % (self.hashval.hex()), file = f)
		print(self.to_pem_data(), file = f)
		print(file = f)

	def __str__(self):
		return "X509Certificate<subject = %s, issuer = %s>" % (self.subject.rfc2253_str, self.issuer.rfc2253_str)
