#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2019 Johannes Bauer
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
from x509sak.ConsolePrinter import ConsolePrinter
from x509sak.estimate.Judgement import SecurityJudgements
from x509sak.estimate import Verdict, Commonness, Compatibility

class AnalysisPrinter():
	def __init__(self, outfile, analyses, **kwargs):
		self._outfile = outfile
		self._analyses = analyses
		self._kwargs = kwargs

	def print(self, analyses):
		raise NotImplementedError("Method not overriden.")

class AnalysisPrinterText(AnalysisPrinter):
	def _create_printer(self, use_ansi):
		if use_ansi:
			return ConsolePrinter(self._outfile).add_subs({
				"<good>":		"\x1b[32m",
				"<warn>":		"\x1b[33m",
				"<error>":		"\x1b[31m",
				"<insecure>":	"\x1b[41m",
				"<end>":		"\x1b[0m",
			})
		else:
			return ConsolePrinter(self._outfile).add_subs({
				"<good>":		"",
				"<warn>":		"",
				"<error>":		"",
				"<insecure>":	"",
				"<end>":		"",
			})

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
				Compatibility.STANDARDS_DEVIATION:		"standards deviation",
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
		if (judgement.verdict == Verdict.MEDIUM) or (judgement.commonness == Commonness.UNUSUAL) or (judgement.compatibility == Compatibility.LIMITED_SUPPORT):
			color = "warn"
		if (judgement.compatibility == Compatibility.STANDARDS_DEVIATION) and (judgement.standard is not None):
			if judgement.standard.deviation_type == StandardDeviationType.RECOMMENDATION:
				color = "warn"
			elif judgement.standard.deviation_type == StandardDeviationType.VIOLATION:
				color = "error"
			else:
				raise NotImplementedError(judgement.standard.deviation_type)
		if (judgement.verdict in [ Verdict.WEAK, Verdict.BROKEN ]) or (judgement.commonness == Commonness.HIGHLY_UNUSUAL):
			color = "error"
		if (judgement.verdict == Verdict.NO_SECURITY) or (judgement.compatibility == Compatibility.STANDARDS_DEVIATION):
			color = "insecure"
		return color

	def _fmt_security_judgement(self, judgement):
		color = self._fmt_color(judgement)
		text = "%s: %s" % (judgement.topic, judgement.text)

		if (judgement.compatibility == Compatibility.STANDARDS_DEVIATION) and (judgement.standard is not None):
			if judgement.standard.deviation_type == StandardDeviationType.RECOMMENDATION:
				text += " This goes against the recommendation of %s." % (judgement.standard)
			elif judgement.standard.deviation_type == StandardDeviationType.VIOLATION:
				text += " This is in violation of %s." % (judgement.standard)
			else:
				raise NotImplementedError(judgement.standard.deviation_type)

		textual_verdict = self._fmt_textual_verdict(judgement)
		if textual_verdict is not None:
			text = "%s {%s}" % (text, textual_verdict)
		return "<%s>%s<end>" % (color, text)

	def _print_security_judgements(self, judgements_data, indent = ""):
		judgements = SecurityJudgements.from_dict(judgements_data)
		if len(judgements) == 0:
			self._printer.print("%sNo comments regarding this check." % (indent))
		elif len(judgements) == 1:
			self._printer.print("%s%s" % (indent, self._fmt_security_judgement(judgements[0])))
		else:
			for (jid, judgement) in enumerate(judgements, 1):
				self._printer.print("%s%d / %d: %s" % (indent, jid, len(judgements), self._fmt_security_judgement(judgement)))

			summary_judgement = judgements.summary_judgement()
			color = self._fmt_color(summary_judgement)
			self._printer.print("%s    -> Summary: <%s>%s<end>" % (indent, color, self._fmt_textual_verdict(summary_judgement)))

	@staticmethod
	def _fmt_time(isotime):
		ts = datetime.datetime.strptime(isotime, "%Y-%m-%dT%H:%M:%SZ")
		return ts.strftime("%c UTC")

	def _print_analysis(self, analysis):
		self._printer.heading("Metadata")
		if analysis["source"]["certs_total"] == 1:
			self._printer.print("Source : %s" % (analysis["source"]["name"]))
		else:
			self._printer.print("Source : %s (certificate %d of %d)" % (analysis["source"]["name"], analysis["source"]["cert_no"], analysis["source"]["certs_total"]))
		self._printer.print("Issuer : %s" % (analysis["issuer"]["pretty"]))
		if len(analysis["issuer"]["security"]["components"]) > 0:
			self._print_security_judgements(printer, analysis["issuer"]["security"], indent = "  ")
		self._printer.print("Subject: %s" % (analysis["subject"]["pretty"]))
		if len(analysis["subject"]["security"]["components"]) > 0:
			self._print_security_judgements(printer, analysis["subject"]["security"], indent = "  ")
		if len(analysis["security"]["components"]) > 0:
			self._printer.print("Misc observations:")
			self._print_security_judgements(printer, analysis["security"], indent = "  ")
		self._printer.print()

		self._printer.heading("Validity")
		self._printer.print("Valid from : %s" % (self._fmt_time(analysis["validity"]["not_before"]["iso"])))
		self._printer.print("Valid until: %s" % (self._fmt_time(analysis["validity"]["not_after"]["iso"])))
		self._printer.print("Lifetime   : %.1f years" % (analysis["validity"]["validity_days"] / 365))
		self._print_security_judgements(analysis["validity"]["security"], indent = "  ")
		self._printer.print()

		self._printer.heading("Public Key")
		self._printer.print("Used cryptography: %s" % (analysis["pubkey"]["pretty"]))
		self._print_security_judgements(analysis["pubkey"]["security"], indent = "    ")
		self._printer.print()

		self._printer.heading("Signature")
		self._printer.print("Signature algorithm: %s" % (analysis["signature"]["pretty"]))
		self._print_security_judgements(analysis["signature"]["security"], indent = "    ")
		if "hash_fnc" in analysis["signature"]:
			self._printer.print("Hash function      : %s" % (analysis["signature"]["hash_fnc"]["name"]))
			self._print_security_judgements(analysis["signature"]["hash_fnc"]["security"], indent = "    ")
		if "sig_fnc" in analysis["signature"]:
			self._printer.print("Signature function : %s" % (analysis["signature"]["sig_fnc"]["name"]))
			self._print_security_judgements(analysis["signature"]["sig_fnc"]["security"], indent = "    ")
		self._printer.print()

		self._printer.heading("X.509 Extensions")
		self._print_security_judgements(analysis["extensions"]["security"], indent = "    ")
		self._printer.print()

		if len(analysis["purpose"]) > 0:
			self._printer.heading("Certificate Purpose")
			for purpose_check in analysis["purpose"]:
				if purpose_check["type"] == "name_match":
					self._printer.print("   Name match '%s':" % (purpose_check["name"]))
					self._print_security_judgements(purpose_check["security"], indent = "       ")
				elif purpose_check["type"] == "purpose_match":
					self._printer.print("   Purpose %s:" % (purpose_check["purpose"]))
					self._print_security_judgements(purpose_check["security"], indent = "       ")
				else:
					raise NotImplementedError(purpose_check["type"])
			self._printer.print()

	def print(self, use_ansi = False):
		self._printer = self._create_printer(use_ansi)
		for analysis in self._analyses["data"]:
			self._print_analysis(analysis)
