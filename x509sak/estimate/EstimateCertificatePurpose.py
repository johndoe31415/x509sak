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

from x509sak.OID import OIDDB
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, AnalysisOptions, Verdict, Commonness
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements
from x509sak.Tools import ValidationTools

@BaseEstimator.register
class PurposeEstimator(BaseEstimator):
	_ALG_NAME = "purpose"

	def _judge_name(self, certificate, name):
		judgements = SecurityJudgements()
		rdns = certificate.subject.get_all(OIDDB.RDNTypes.inverse("CN"))
		have_valid_cn = False
		if len(rdns) > 0:
			found_rdn = None
			for rdn in rdns:
				value = rdn.get_value(OIDDB.RDNTypes.inverse("CN"))
				if ValidationTools.validate_domainname_template_match(value.printable_value, name):
					found_rdn = rdn
					break
			if found_rdn is not None:
				if found_rdn.component_cnt == 1:
					judgements += SecurityJudgement(JudgementCode.Cert_CN_Match, "Common name (CN) matches '%s'." % (name), commonness = Commonness.COMMON)
				else:
					judgements += SecurityJudgement(JudgementCode.Cert_CN_Match_MultiValue_RDN, "Common name (CN) matches '%s', but is part of a multi-valued RDN: %s" % (name, found_rdn.pretty_str), commonness = Commonness.HIGHLY_UNUSUAL)
			else:
				judgements += SecurityJudgement(JudgementCode.Cert_CN_NoMatch, "No common name (CN) matches '%s'." % (name), commonness = Commonness.UNUSUAL)

		have_valid_san = False
		extension = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("SubjectAlternativeName"))
		if extension is not None:
			for san_name in extension.get_all("dNSName"):
				if ValidationTools.validate_domainname_template_match(san_name.str_value, name):
					have_valid_san = True
					judgements += SecurityJudgement(JudgementCode.Cert_SAN_Match, "Subject Alternative Name matches '%s'." % (name), commonness = Commonness.COMMON)
					break
			else:
				judgements += SecurityJudgement(JudgementCode.Cert_SAN_NoMatch, "No Subject Alternative Name X.509 extension matches '%s'." % (name), commonness = Commonness.UNUSUAL)
		else:
			judgements += SecurityJudgement(JudgementCode.Cert_No_SAN_Present, "No Subject Alternative Name X.509 extension present in the certificate.", commonness = Commonness.UNUSUAL)

		if (not have_valid_cn) and (not have_valid_san):
			judgements += SecurityJudgement(JudgementCode.Cert_Name_Verification_Failed, "Found neither valid common name (CN) nor valid subject alternative name (SAN).", commonness = Commonness.HIGHLY_UNUSUAL, verdict = Verdict.NO_SECURITY)

		return judgements

	def _judge_purpose(self, certificate, purpose):
		judgements = SecurityJudgements()
		ku_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("KeyUsage"))
		eku_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("ExtendedKeyUsage"))
		ns_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("NetscapeCertificateType"))

		if purpose in [ AnalysisOptions.CertificatePurpose.TLSServerCertificate, AnalysisOptions.CertificatePurpose.TLSClientCertificate ]:
			if certificate.is_ca_certificate:
				judgements += SecurityJudgement(JudgementCode.Cert_Unexpectedly_CA_Cert, "Certificate is a valid CA certificate even though it's supposed to be a TLS client/server.", commonness = Commonness.HIGHLY_UNUSUAL, verdict = Verdict.NO_SECURITY)

		if ku_ext is not None:
			if purpose == AnalysisOptions.CertificatePurpose.CACertificate:
				must_have = set([ "keyCertSign" ])
				may_have = set([ "cRLSign", "digitalSignature" ])
				may_not_have = set([ "encipherOnly", "decipherOnly" ])
			elif purpose in [ AnalysisOptions.CertificatePurpose.TLSClientCertificate, AnalysisOptions.CertificatePurpose.TLSServerCertificate ]:
				must_have = set([ "keyAgreement" ])
				may_have = set([ "keyEncipherment" ])
				may_not_have = set([ "encipherOnly", "decipherOnly", "keyCertSign", "cRLSign" ])
			else:
				raise NotImplementedError(purpose)

			present_flags = ku_ext.flags

			missing_must_haves = must_have - present_flags
			if len(missing_must_haves) > 0:
				judgements += SecurityJudgement(JudgementCode.Cert_KU_MissingKeyUsage, "Certificate with purpose %s should have at least KeyUsage %s, but %s is missing." % (purpose.name, ", ".join(sorted(must_have)), ", ".join(sorted(missing_must_haves))), commonness = Commonness.HIGHLY_UNUSUAL)

			excess_flags = present_flags - must_have - may_have - may_not_have
			if len(excess_flags) > 0:
				judgements += SecurityJudgement(JudgementCode.Cert_KU_UnusualKeyUsage, "For certificate with purpose %s it is uncommon to have KeyUsage %s." % (purpose.name, ", ".join(sorted(excess_flags))), commonness = Commonness.UNUSUAL)

			present_may_not_haves = present_flags & may_not_have
			if len(present_may_not_haves) > 0:
				judgements += SecurityJudgement(JudgementCode.Cert_KU_ExcessKeyUsage, "Certificate with purpose %s must not have any KeyUsage %s. This certificate has %s." % (purpose.name, ", ".join(sorted(may_not_have)), ", ".join(sorted(present_may_not_haves))), commonness = Commonness.HIGHLY_UNUSUAL)


		if eku_ext is not None:
			if (purpose == AnalysisOptions.CertificatePurpose.TLSClientCertificate) and (not eku_ext.client_auth):
				judgements += SecurityJudgement(JudgementCode.Cert_EKU_NoClientAuth, "Certificate is supposed to be a client certificate and has an Extended Key Usage extension, but no clientAuth flag set within that extension.", commonness = Commonness.UNUSUAL)

			if (purpose == AnalysisOptions.CertificatePurpose.TLSServerCertificate) and (not eku_ext.server_auth):
				judgements += SecurityJudgement(JudgementCode.Cert_EKU_NoServerAuth, "Certificate is supposed to be a server certificate and has an Extended Key Usage extension, but no serverAuth flag set within that extension.", commonness = Commonness.UNUSUAL)

		if ns_ext is not None:
			if (purpose == AnalysisOptions.CertificatePurpose.TLSClientCertificate) and (not ns_ext.ssl_client):
				judgements += SecurityJudgement(JudgementCode.Cert_NSCT_NoSSLClient, "Certificate is supposed to be a client certificate and has an Netscape Certificate Type extension, but no sslClient flag set within that extension.", commonness = Commonness.UNUSUAL)

			if (purpose == AnalysisOptions.CertificatePurpose.TLSServerCertificate) and (not ns_ext.ssl_server):
				judgements += SecurityJudgement(JudgementCode.Cert_NSCT_NoSSLServer, "Certificate is supposed to be a server certificate and has an Netscape Certificate Type extension, but no sslServer flag set within that extension.", commonness = Commonness.UNUSUAL)

			if (purpose == AnalysisOptions.CertificatePurpose.CACertificate) and not any(flag in ns_ext.flags for flag in [ "sslCA", "emailCA", "objCA" ]):
				judgements += SecurityJudgement(JudgementCode.Cert_NSCT_NoCA, "Certificate is supposed to be a CA certificate and has an Netscape Certificate Type extension, but neither sslCA/emailCA/objCA flag set within that extension.", commonness = Commonness.UNUSUAL)

		if purpose == AnalysisOptions.CertificatePurpose.CACertificate:
			if not certificate.is_ca_certificate:
				judgements += SecurityJudgement(JudgementCode.Cert_Unexpectedly_No_CA_Cert, "Certificate is not a valid CA certificate even though it's supposed to be.", commonness = Commonness.HIGHLY_UNUSUAL, verdict = Verdict.NO_SECURITY)

		return judgements

	def analyze(self, certificate):
		result = [ ]

		if self._analysis_options.fqdn is not None:
			analysis = {
				"type":			"name_match",
				"name":			self._analysis_options.fqdn,
				"security":		self._judge_name(certificate, self._analysis_options.fqdn),
			}
			result.append(analysis)

		for purpose in self._analysis_options.purposes:
			analysis = {
				"type":			"purpose_match",
				"purpose":		purpose,
				"security":		self._judge_purpose(certificate, purpose),
			}
			result.append(analysis)

		return result
