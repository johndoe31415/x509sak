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

import json
import datetime
import collections
from x509sak.BaseAction import BaseAction
from x509sak import X509Certificate
from x509sak.Tools import JSONTools
from x509sak.estimate import SecurityEstimator, AnalysisOptions
from x509sak.FileWriter import FileWriter
from x509sak.OpenSSLTools import OpenSSLTools
from x509sak.AnalysisPrinter import AnalysisPrinterText

class ActionExamineCert(BaseAction):
	_CrtSource = collections.namedtuple("CrtSource", [ "source", "source_type", "crts" ])

	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)
		if self._args.parent_certificate is None:
			parent_ca_cert = None
		else:
			if self._args.in_format == "dercrt":
				# CA cert in DER form if host certificate is also in DER form
				crt = X509Certificate.read_derfile(self._args.parent_certificate)
			else:
				# CA cert in PEM form for all other cases
				crt = X509Certificate.read_pemfile(self._args.parent_certificate)[0]
			parent_ca_cert = self._CrtSource(source = self._args.parent_certificate, source_type = "pemcrt" if (self._args.in_format != "dercrt") else "dercrt", crts = [ crt ])
		if self._args.in_format in [ "pemcrt", "dercrt", "host" ]:
			crt_sources = self._load_certificates()
			analysis = self._analyze_certificates(crt_sources, parent_ca_cert)
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

	def _analyze_certificates(self, crt_sources, root_certificate):
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

	def _show_analysis(self, output, analyses):
		if self._args.out_format in [ "ansitext", "text" ]:
			use_ansi = (self._args.out_format == "ansitext")
			AnalysisPrinterText(output, analyses).print(use_ansi = use_ansi)
		elif self._args.out_format == "json":
			JSONTools.write_to_fp(analyses, output, pretty = self._args.pretty_json)
		else:
			raise NotImplementedError(self._args.out_format)
