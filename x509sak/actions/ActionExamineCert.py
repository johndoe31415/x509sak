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

import json
import datetime
import collections
from x509sak.BaseAction import BaseAction
from x509sak import X509Certificate
from x509sak.Tools import JSONTools
from x509sak.estimate import SecurityEstimator, AnalysisOptions, Commonness, Verdict, Compatibility
from x509sak.estimate.Judgement import SecurityJudgements
from x509sak.ConsolePrinter import ConsolePrinter
from x509sak.FileWriter import FileWriter
from x509sak.OpenSSLTools import OpenSSLTools

class ActionExamineCert(BaseAction):
	_CrtSource = collections.namedtuple("CrtSource", [ "source", "source_type", "crts" ])

	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)
		if self._args.in_format in [ "pemcrt", "dercrt", "host" ]:
			crt_sources = self._load_certificates()
			analysis = self._analyze_certificates(crt_sources)
		elif self._args.in_format == "json":
			analysis = self._read_json()
		else:
			raise NotImplementedError(self._args.in_format)

		output = self._args.output or "-"
		with FileWriter(output, "w") as f:
			self._show_analysis(f, analysis)

	def _check_purposes(self):
		purposes = [ AnalysisOptions.CertificatePurpose(purpose) for purpose in self._args.purpose ]
		if (len(self._args.purpose) == 0) and (self._args.in_format == "host") and (not self._args.no_automatic_host_check):
			purposes.append(AnalysisOptions.CertificatePurpose.TLSServerCertificate)
		return purposes

	def _check_name(self, crt_source):
		if (self._args.server_name is None) and (self._args.in_format == "host") and (not self._args.no_automatic_host_check):
			host_port = crt_source.source.split(":")
			return host_port[0]
		else:
			return self._args.server_name

	def _load_certificates(self):
		sources = [ ]
		for crt_filename in self._args.infiles:
			if self._args.in_format == "pemcrt":
				self._log.debug("Reading PEM certificate from %s", crt_filename)
				crts = X509Certificate.read_pemfile(crt_filename)
			elif self._args.in_format == "dercrt":
				self._log.debug("Reading DER certificate from %s", crt_filename)
				crts = [ X509Certificate.read_derfile(crt_filename) ]
			elif self._args.in_format == "host":
				host_port = crt_filename.split(":", maxsplit = 1)
				if len(host_port) == 1:
					host_port.append("443")
				(host, port) = host_port
				port = int(port)
				self._log.debug("Querying TLS server at %s port %d", host, port)
				crts = [ OpenSSLTools.get_tls_server_cert(host, port) ]
			else:
				raise NotImplementedError(self._args.in_format)
			source = self._CrtSource(source = crt_filename, crts = crts, source_type = self._args.in_format)
			sources.append(source)
		return sources

	def _analyze_certificates(self, crt_sources):
		utcnow = datetime.datetime.utcnow()
		analyses = {
			"timestamp_utc":	utcnow,
			"data":				[ ],
		}
		for crt_source in crt_sources:
			for (crtno, crt) in enumerate(crt_source.crts, 1):
				analysis_options = {
					"rsa_testing":			AnalysisOptions.RSATesting.Fast if self._args.fast_rsa else AnalysisOptions.RSATesting.Full,
					"include_raw_data":		self._args.include_raw_data,
					"purposes":				self._check_purposes(),
					"fqdn":					self._check_name(crt_source),
					"utcnow":				utcnow,
				}
				analysis_options = AnalysisOptions(**analysis_options)
				analysis = SecurityEstimator.handler("certificate")(analysis_options = analysis_options).analyze(crt)
				analysis = JSONTools.translate(analysis)
				analysis["source"] = {
					"name":			crt_source.source,
					"srctype":		crt_source.source_type,
					"cert_no":		crtno,
					"certs_total":	len(crt_source.crts),
				}
				analyses["data"].append(analysis)
		return analyses

	def _read_json(self):
		merged_analyses = None
		for json_filename in self._args.infiles:
			with open(json_filename) as f:
				analyses = json.load(f)
				if merged_analyses is None:
					merged_analyses = analyses
				else:
					merged_analyses["data"] += analyses["data"]
		return merged_analyses

	@staticmethod
	def _fmt_textual_verdict(judgement):
		textual_verdict = [ ]
		if judgement.bits is not None:
			textual_verdict.append("%d bits" % (judgement.bits))
		if judgement.verdict is not None:
			textual_verdict.append({
				Verdict.BEST_IN_CLASS:					"best-in-class security",
				Verdict.HIGH:							"high security",
				Verdict.MEDIUM:							"medium security",
				Verdict.WEAK:							"weak security",
				Verdict.BROKEN:							"broken security",
				Verdict.NO_SECURITY:					"no security",
			}[judgement.verdict])
		if judgement.commonness is not None:
			textual_verdict.append({
				Commonness.COMMON:						"common",
				Commonness.FAIRLY_COMMON:				"fairly common",
				Commonness.UNUSUAL:						"unusual",
				Commonness.HIGHLY_UNUSUAL:				"highly unusual",
			}[judgement.commonness])
		if judgement.compatibility is not None:
			textual_verdict.append({
				Compatibility.FULLY_COMPLIANT:			"fully standards compliant",
				Compatibility.LIMITED_SUPPORT:			"limited support",
				Compatibility.STANDARDS_VIOLATION:		"standards violation",
			}[judgement.compatibility])

		if len(textual_verdict) == 0:
			return None
		else:
			return ", ".join(textual_verdict)

	@staticmethod
	def _fmt_color(judgement):
		color = "end"
		if judgement.verdict in [ Verdict.BEST_IN_CLASS, Verdict.HIGH ]:
			color = "good"
		if (judgement.verdict == Verdict.MEDIUM) or (judgement.commonness == Commonness.UNUSUAL) or (judgement.compatibility in [ Compatibility.LIMITED_SUPPORT ]):
			color = "warn"
		if (judgement.verdict in [ Verdict.WEAK, Verdict.BROKEN ]) or (judgement.commonness == Commonness.HIGHLY_UNUSUAL):
			color = "error"
		if (judgement.verdict == Verdict.NO_SECURITY) or (judgement.compatibility == Compatibility.STANDARDS_VIOLATION):
			color = "insecure"
		return color

	def _fmt_security_judgement(self, judgement):
		color = self._fmt_color(judgement)
		text = "%s: %s" % (judgement.topic, judgement.text)

		textual_verdict = self._fmt_textual_verdict(judgement)
		if textual_verdict is not None:
			text = "%s {%s}" % (text, textual_verdict)
		return "<%s>%s<end>" % (color, text)

	def _print_security_judgements(self, printer, judgements_data, indent = ""):
		judgements = SecurityJudgements.from_dict(judgements_data)
		if len(judgements) == 0:
			printer.print("%sNo comments regarding this check." % (indent))
		elif len(judgements) == 1:
			printer.print("%s%s" % (indent, self._fmt_security_judgement(judgements[0])))
		else:
			for (jid, judgement) in enumerate(judgements, 1):
				printer.print("%s%d / %d: %s" % (indent, jid, len(judgements), self._fmt_security_judgement(judgement)))

			summary_judgement = judgements.summary_judgement()
			color = self._fmt_color(summary_judgement)
			printer.print("%s    -> Summary: <%s>%s<end>" % (indent, color, self._fmt_textual_verdict(summary_judgement)))

	@staticmethod
	def _fmt_time(isotime):
		ts = datetime.datetime.strptime(isotime, "%Y-%m-%dT%H:%M:%SZ")
		return ts.strftime("%c UTC")

	def _print_analysis(self, printer, analyses):
		for analysis in analyses["data"]:
			printer.heading("Metadata")
			if analysis["source"]["certs_total"] == 1:
				printer.print("Source : %s" % (analysis["source"]["name"]))
			else:
				printer.print("Source : %s (certificate %d of %d)" % (analysis["source"]["name"], analysis["source"]["cert_no"], analysis["source"]["certs_total"]))
			printer.print("Issuer : %s" % (analysis["issuer"]["pretty"]))
			if len(analysis["issuer"]["security"]["components"]) > 0:
				self._print_security_judgements(printer, analysis["issuer"]["security"], indent = "  ")
			printer.print("Subject: %s" % (analysis["subject"]["pretty"]))
			if len(analysis["subject"]["security"]["components"]) > 0:
				self._print_security_judgements(printer, analysis["subject"]["security"], indent = "  ")
			if len(analysis["security"]["components"]) > 0:
				printer.print("Misc observations:")
				self._print_security_judgements(printer, analysis["security"], indent = "  ")
			printer.print()

			printer.heading("Validity")
			printer.print("Valid from : %s" % (self._fmt_time(analysis["validity"]["not_before"]["iso"])))
			printer.print("Valid until: %s" % (self._fmt_time(analysis["validity"]["not_after"]["iso"])))
			printer.print("Lifetime   : %.1f years" % (analysis["validity"]["validity_days"] / 365))
			self._print_security_judgements(printer, analysis["validity"]["security"], indent = "  ")
			printer.print()

			printer.heading("Public Key")
			printer.print("Used cryptography: %s" % (analysis["pubkey"]["pretty"]))
			self._print_security_judgements(printer, analysis["pubkey"]["security"], indent = "    ")
			printer.print()

			printer.heading("Signature")
			printer.print("Signature algorithm: %s" % (analysis["signature"]["pretty"]))
			self._print_security_judgements(printer, analysis["signature"]["security"], indent = "    ")
			if "hash_fnc" in analysis["signature"]:
				printer.print("Hash function      : %s" % (analysis["signature"]["hash_fnc"]["name"]))
				self._print_security_judgements(printer, analysis["signature"]["hash_fnc"]["security"], indent = "    ")
			if "sig_fnc" in analysis["signature"]:
				printer.print("Signature function : %s" % (analysis["signature"]["sig_fnc"]["name"]))
				self._print_security_judgements(printer, analysis["signature"]["sig_fnc"]["security"], indent = "    ")
			printer.print()

			printer.heading("X.509 Extensions")
			self._print_security_judgements(printer, analysis["extensions"]["security"], indent = "    ")
			printer.print()

			if len(analysis["purpose"]) > 0:
				printer.heading("Certificate Purpose")
				for purpose_check in analysis["purpose"]:
					if purpose_check["type"] == "name_match":
						printer.print("   Name match '%s':" % (purpose_check["name"]))
						self._print_security_judgements(printer, purpose_check["security"], indent = "       ")
					elif purpose_check["type"] == "purpose_match":
						printer.print("   Purpose %s:" % (purpose_check["purpose"]))
						self._print_security_judgements(printer, purpose_check["security"], indent = "       ")
					else:
						raise NotImplementedError(purpose_check["type"])
				printer.print()

	def _show_analysis(self, output, analyses):
		if self._args.out_format == "ansitext":
			printer = ConsolePrinter(output).add_subs({
				"<good>":		"\x1b[32m",
				"<warn>":		"\x1b[33m",
				"<error>":		"\x1b[31m",
				"<insecure>":	"\x1b[41m",
				"<end>":		"\x1b[0m",
			})
			self._print_analysis(printer, analyses)
		elif self._args.out_format == "text":
			printer = ConsolePrinter(output).add_subs({
				"<good>":		"",
				"<warn>":		"",
				"<error>":		"",
				"<insecure>":	"",
				"<end>":		"",
			})
			self._print_analysis(printer, analyses)
		elif self._args.out_format == "json":
			JSONTools.write_to_fp(analyses, output)
		else:
			raise NotImplementedError(self._args.out_format)
