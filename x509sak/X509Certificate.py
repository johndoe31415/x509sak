#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2017-2017 Johannes Bauer
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

import datetime
import logging
import tempfile
from x509sak.SubprocessExecutor import SubprocessExecutor
from .PEMDERObject import PEMDERObject
from .DistinguishedName import DistinguishedName
from .Tools import CmdTools, ASN1Tools
from pyasn1_modules import rfc2459

_log = logging.getLogger("x509sak.X509Certificate")

class X509Certificate(PEMDERObject):
	_PEM_MARKER = "CERTIFICATE"
	_ASN1_MODEL = rfc2459.Certificate()

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

	def is_selfsigned(self):
		return self.signed_by(self, partial_chain = False)

	def signed_by(self, potential_issuer, partial_chain = True):
		with tempfile.NamedTemporaryFile(prefix = "subject_", suffix = ".crt") as subject, tempfile.NamedTemporaryFile(prefix = "issuer_", suffix = ".crt") as issuer:
			self.write_pemfile(subject.name)
			potential_issuer.write_pemfile(issuer.name)

			cmd = [ "openssl", "verify", "-no-CAfile", "-no-CApath" ]
			if partial_chain:
				cmd += [ "-partial_chain" ]
			cmd += [ "-check_ss_sig", "-CAfile", issuer.name, subject.name ]
			_log.debug("Executing: %s", CmdTools.cmdline(cmd))
			return SubprocessExecutor.run(cmd, exception_on_failure = False)

	def dump_pem(self, f = None):
		print("# Subject : %s" % (self.subject.pretty_str), file = f)
		print("# Issuer  : %s" % (self.issuer.pretty_str), file = f)
		print("# Validity: %s UTC - %s UTC" % (self.valid_not_before.strftime("%Y-%m-%d %H:%M:%S"), self.valid_not_after.strftime("%Y-%m-%d %H:%M:%S")), file = f)
		print("# Hash    : %s" % (self.hashval.hex()), file = f)
		print(self.to_pem_data(), file = f)
		print(file = f)

	def __str__(self):
		return "X509Certificate<subject = %s, issuer = %s>" % (self.subject.rfc2253_str, self.issuer.rfc2253_str)
