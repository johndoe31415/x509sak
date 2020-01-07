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

import datetime
import collections
from x509sak.estimate import SecurityEstimator, AnalysisOptions
from x509sak.Tools import JSONTools

class CertificateAnalyzer():
	CertSource = collections.namedtuple("CertSource", [ "source", "source_type", "crts" ])

	def __init__(self, entity_name = None, fast_rsa = False, purposes = None, include_raw_data = False):
		self._entity_name = entity_name
		self._fast_rsa = fast_rsa
		self._purposes = purposes if (purposes is not None) else [ ]
		self._purposes = list(sorted(AnalysisOptions.CertificatePurpose(purpose) for purpose in set(self._purposes)))
		self._include_raw_data = include_raw_data

	def analyze(self, crt_sources, root_certificate):
		assert(isinstance(crt_source, self.CertSource) for crt_source in crt_sources)
		assert(isinstance(root_certificate, (type(None), self.CertSource)))
		utcnow = datetime.datetime.utcnow()
		analyses = {
			"timestamp_utc":	utcnow,
			"data":				[ ],
		}
		for crt_source in crt_sources:
			for (crtno, crt) in enumerate(crt_source.crts, 1):
				analysis_options = {
					"rsa_testing":			AnalysisOptions.RSATesting.Fast if self._fast_rsa else AnalysisOptions.RSATesting.Full,
					"include_raw_data":		self._include_raw_data,
					"purposes":				self._purposes,
					"fqdn":					self._entity_name,
					"utcnow":				utcnow,
				}
				if root_certificate is not None:
					root_crt = root_certificate.crts[0]
				else:
					root_crt = None
				analysis_options = AnalysisOptions(**analysis_options)
				analysis = SecurityEstimator.handler("certificate")(analysis_options = analysis_options).analyze(crt, root_crt)
				analysis = JSONTools.translate(analysis)
				analysis["source"] = {
					"name":			crt_source.source,
					"srctype":		crt_source.source_type,
					"cert_no":		crtno,
					"certs_total":	len(crt_source.crts),
				}
				if root_certificate is not None:
					analysis["root_source"] = {
						"name":			root_certificate.source,
						"srctype":		root_certificate.source_type,
					}
				analyses["data"].append(analysis)
		return analyses

	@classmethod
	def extract_codes_from_json(cls, data):
		def recurse_through_data(data, result):
			if result is None:
				result = set()
			if isinstance(data, list):
				for item in data:
					recurse_through_data(item, result)
			elif isinstance(data, dict):
				if "code" in data:
					result.add(data["code"])
				for (key, value) in data.items():
					recurse_through_data(value, result)

		result = set()
		recurse_through_data(data, result)
		return result
