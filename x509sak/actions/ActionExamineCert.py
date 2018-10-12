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

import datetime
from x509sak.BaseAction import BaseAction
from x509sak import X509Certificate
from x509sak.Tools import JSONTools
from x509sak.SecurityEstimator import AnalysisOptions
from x509sak.ConsolePrinter import ConsolePrinter
from x509sak.SecurityJudgement import Commonness, Verdict

class ActionExamineCert(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		self._printer = ConsolePrinter()
		if not self._args.no_ansi:
			self._printer.add_subs({
				"<good>":		"\x1b[32m",
				"<warn>":		"\x1b[33m",
				"<error>":		"\x1b[31m",
				"<insecure>":	"\x1b[41m",
				"<end>":		"\x1b[0m",
			})
		else:
			self._printer.add_subs({
				"<good>":		"",
				"<warn>":		"",
				"<error>":		"",
				"<insecure>":	"",
				"<end>":		"",
			})

		analyses = [ ]
		for crt_filename in self._args.crt_filenames:
			self._log.debug("Reading %s", crt_filename)
			crts = X509Certificate.read_pemfile(crt_filename)
			for (crtno, crt) in enumerate(crts, 1):
				if len(crts) > 1:
					print("%s #%d:" % (crt_filename, crtno))
				else:
					print("%s:" % (crt_filename))
				analysis_options = {
					"rsa_testing":			AnalysisOptions.RSATesting.Fast if self._args.fast_rsa else AnalysisOptions.RSATesting.Full,
					"include_raw_data":		self._args.include_raw_data,
					"purposes":				[ AnalysisOptions.CertificatePurpose(purpose) for purpose in self._args.purpose ],
					"fqdn":					self._args.server_name,
				}
				analysis_options = AnalysisOptions(**analysis_options)
				analysis = self._analyze_crt(crt, analysis_options = analysis_options)
				analysis["source"] = {
					"filename":		crt_filename,
					"index":		crtno - 1,
				}
				analyses.append(analysis)

		if self._args.write_json:
			JSONTools.write_to_file(analyses, self._args.write_json)

	def _fmt_textual_verdict(self, judgement):
		textual_verdict = [ ]
		if judgement.bits is not None:
			textual_verdict.append("%d bits" % (judgement.bits))
		if judgement.verdict is not None:
			textual_verdict.append({
				Verdict.BEST_IN_CLASS:		"best-in-class security",
				Verdict.HIGH:				"high security",
				Verdict.MEDIUM:				"medium security",
				Verdict.WEAK:				"weak security",
				Verdict.BROKEN:				"broken security",
				Verdict.NO_SECURITY:		"no security",
			}[judgement.verdict])
		if judgement.commonness is not None:
			textual_verdict.append({
				Commonness.COMMON:			"common",
				Commonness.FAIRLY_COMMON:	"fairly common",
				Commonness.UNUSUAL:			"unusual",
				Commonness.HIGHLY_UNUSUAL:	"highly unusual",
			}[judgement.commonness])

		if len(textual_verdict) == 0:
			return None
		else:
			return ", ".join(textual_verdict)

	def _fmt_color(self, judgement):
		color = "end"
		if judgement.verdict in [ Verdict.BEST_IN_CLASS, Verdict.HIGH ]:
			color = "good"
		if (judgement.verdict == Verdict.MEDIUM) or (judgement.commonness == Commonness.UNUSUAL):
			color = "warn"
		if (judgement.verdict in [ Verdict.WEAK, Verdict.BROKEN ]) or (judgement.commonness == Commonness.HIGHLY_UNUSUAL):
			color = "error"
		if judgement.verdict == Verdict.NO_SECURITY:
			color = "insecure"
		return color

	def _fmt_verdict(self, judgement):
		color = self._fmt_color(judgement)
		textual_verdict = self._fmt_textual_verdict(judgement)
		if textual_verdict is None:
			text = judgement.text
		else:
			text = "%s {%s}" % (judgement.text, textual_verdict)
		return "<%s>%s<end>" % (color, text)

	def _print_verdict(self, judgements, indent = ""):
		component_cnt = judgements.component_cnt
		if component_cnt == 0:
			self._printer.print("%sNo comments regarding this check." % (indent))
		elif component_cnt == 1:
			self._printer.print("%s%s" % (indent, self._fmt_verdict(judgements)))
		else:
			for (jid, judgement) in enumerate(judgements, 1):
				self._printer.print("%s%d / %d: %s" % (indent, jid, component_cnt, self._fmt_verdict(judgement)))
			color = self._fmt_color(judgements)
			self._printer.print("%s    -> Summary: <%s>%s<end>" % (indent, color, self._fmt_textual_verdict(judgements)))

	def _fmt_time(self, isotime):
		ts = datetime.datetime.strptime(isotime, "%Y-%m-%dT%H:%M:%SZ")
		return ts.strftime("%c UTC")

	def _analyze_crt(self, crt, analysis_options = None):
		analysis = crt.analyze(analysis_options = analysis_options)
		if self._args.print_raw:
			print(JSONTools.serialize(analysis))
		else:
			self._printer.heading("Metadata")
			self._printer.print("Issuer : %s" % (analysis["issuer"]["pretty"]))
			self._printer.print("Subject: %s" % (analysis["subject"]["pretty"]))
			self._printer.print()

			self._printer.heading("Validity")
			self._printer.print("Valid from : %s" % (self._fmt_time(analysis["validity"]["not_before"]["iso"])))
			self._printer.print("Valid until: %s" % (self._fmt_time(analysis["validity"]["not_after"]["iso"])))
			self._printer.print("Lifetime   : %.1f years" % (analysis["validity"]["validity_days"] / 365))
			self._print_verdict(analysis["validity"]["security"], indent = "  ")
			self._printer.print()

			self._printer.heading("Public Key")
			self._printer.print("Used cryptography: %s" % (analysis["pubkey"]["pretty"]))
			self._print_verdict(analysis["pubkey"]["security"], indent = "    ")
			self._printer.print()

			self._printer.heading("Signature")
			self._printer.print("Signature algorithm: %s" % (analysis["signature"]["pretty"]))
			self._printer.print("Hash function      : %s" % (analysis["signature"]["hash_fnc"]["name"]))
			self._print_verdict(analysis["signature"]["hash_fnc"]["security"], indent = "    ")
			self._printer.print("Signature function : %s" % (analysis["signature"]["sig_fnc"]["name"]))
			self._print_verdict(analysis["signature"]["sig_fnc"]["security"], indent = "    ")
			self._printer.print()

			self._printer.heading("X.509 Extensions")
			self._print_verdict(analysis["extensions"]["security"], indent = "    ")
			self._printer.print()

			if len(analysis["purpose"]) > 0:
				self._printer.heading("Certificate Purpose")
				for purpose_check in analysis["purpose"]:
					if purpose_check["type"] == "name_match":
						self._printer.print("   Name match '%s':" % (purpose_check["name"]))
						self._print_verdict(purpose_check["security"], indent = "       ")
					elif purpose_check["type"] == "purpose_match":
						self._printer.print("   Purpose %s:" % (purpose_check["purpose"].name))
						self._print_verdict(purpose_check["security"], indent = "       ")
					else:
						raise NotImplementedError(purpose_check["type"])
				self._printer.print()
		return analysis
