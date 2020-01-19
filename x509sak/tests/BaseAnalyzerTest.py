#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2020-2020 Johannes Bauer
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
from x509sak.tests import BaseTest
from x509sak.estimate import JudgementCode
from x509sak.X509Certificate import X509Certificate
from x509sak.tests import ResourceFileLoader
from x509sak.CertificateAnalyzer import CertificateAnalyzer
from x509sak.Tools import FileLockTools
from x509sak.Exceptions import UnexpectedFileContentException

class BaseAnalyzerTest(BaseTest):
	def _update_stats_file(self, certname, parent_certname, encountered_codes, checked_codes):
		stats_filename = ".examinecert_stats.json"
		with FileLockTools.lock(stats_filename):
			try:
				with open(stats_filename) as f:
					stats = json.load(f)
			except (FileNotFoundError, json.JSONDecodeError):
				stats = { }

			if "encountered_codes" not in stats:
				stats["encountered_codes"] = { }
			for encountered_code in encountered_codes:
				if encountered_code not in stats["encountered_codes"]:
					stats["encountered_codes"][encountered_code] = [ certname, parent_certname ]

			if "checked_codes" not in stats:
				stats["checked_codes"] = { }
			for checked_code in checked_codes:
				if checked_code not in stats["checked_codes"]:
					stats["checked_codes"][checked_code] = [ certname, parent_certname ]

			with open(stats_filename, "w") as f:
				json.dump(stats, f)

	def _test_examine_x509test_resultcode(self, certname, expect_present = None, expect_absent = None, parent_certname = None, fast_rsa = True, host_check = None, include_raw = False, purpose = None, expect_parse_failure = False):
		if expect_present is None:
			expect_present = tuple()
		if not isinstance(expect_present, (list, tuple)):
			expect_present = (expect_present, )

		if expect_absent is None:
			expect_absent = tuple()
		if not isinstance(expect_absent, (list, tuple)):
			expect_absent = (expect_absent, )

		# Plausibilize we're not chasing non-existing judgement codes -- don't
		# check the empty string because we often use that for debugging and
		# it's *obviously* wrong.

		if expect_present != ("", ):
			self.assertTrue(all(getattr(JudgementCode, codename, None) is not None for codename in expect_present))
		if expect_absent != ("", ):
			self.assertTrue(all(getattr(JudgementCode, codename, None) is not None for codename in expect_absent))

		if expect_parse_failure:
			with self.assertRaises(UnexpectedFileContentException):
				X509Certificate.from_pem_data(ResourceFileLoader.load_data(certname))
			return

		certificates = X509Certificate.from_pem_data(ResourceFileLoader.load_data(certname))
		crt_sources = [ CertificateAnalyzer.CertSource(crts = certificates, source = "internal", source_type = "pemcert") ]
		if parent_certname is not None:
			ca_certificate = CertificateAnalyzer.CertSource(crts = X509Certificate.from_pem_data(ResourceFileLoader.load_data(parent_certname)), source = "internal", source_type = "pemcert")
		else:
			ca_certificate = None

		analysis_params = {
			"fast_rsa":				fast_rsa,
			"include_raw_data":		include_raw,
		}
		if host_check is not None:
			analysis_params.update({
				"entity_name":	host_check,
				"purposes":		[ "tls-server" ],
			})
		elif purpose is not None:
			analysis_params["purposes"] = [ purpose ]
		cert_analyzer = CertificateAnalyzer(**analysis_params)
		analyses = cert_analyzer.analyze(crt_sources, ca_certificate)

		encountered_codes = CertificateAnalyzer.extract_codes_from_json(analyses)

		# If we're in debugging mode, update the consolidated JSON stat file
		if self._produce_statistics:
			self._update_stats_file(certname = certname, parent_certname = parent_certname, encountered_codes = encountered_codes, checked_codes = expect_present)
		for code in expect_present:
			self.assertIn(code, encountered_codes)
		for code in expect_absent:
			self.assertNotIn(code, encountered_codes)
