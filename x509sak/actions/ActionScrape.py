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

import os
import re
import base64
import collections
import hashlib
import sys
import datetime
import pyasn1.codec.der.decoder
from pyasn1_modules import rfc2459, rfc2437
import x509sak.ASN1Models
from x509sak.BaseAction import BaseAction
from x509sak.ScrapeEngine import ScrapeEngine
from x509sak.Tools import PEMDataTools, JSONTools
from x509sak.KwargsChecker import KwargsChecker
from x509sak.Intervals import Intervals, Interval

class _DERSanityCheck():
	class SanityCheckFailedException(Exception): pass

	@classmethod
	def check_rsa_key(cls, asn1):
		if asn1["prime1"] * asn1["prime2"] != asn1["modulus"]:
			raise cls.SanityCheckFailedException("Product p * q is not equal to modulus n; likely not a valid RSA private key.")

	@classmethod
	def check_ec_key(cls, asn1):
		if len(asn1["privateKey"]) <= 8:
			raise cls.SanityCheckFailedException("Short (%d bytes) private key scalar; likely not a valid ECC private key." % (len(asn1["privateKey"])))

	@classmethod
	def check_dsa_sig(cls, asn1):
		r_bitlen = int(asn1["r"]).bit_length()
		if r_bitlen <= 64:
			raise cls.SanityCheckFailedException("Short (%d bit) DSA r value; likely not a valid DSA signature." % (r_bitlen))

class ActionScrapeStats():
	_FRIENDLY_DATA_TYPE = {
		"crt":				"X.509 Certificate",
		"openssh_key":		"OpenSSH Private Key",
		"dsa_key":			"DSA Private Key",
		"rsa_key":			"RSA Private Key",
		"ec_key":			"ECC Private Key",
		"pubkey":			"Public Key",
		"crl":				"Certificate Revocation List",
		"csr":				"Certificate Signing Request",
		"unknown":			"Unknown",
	}
	_Finding = collections.namedtuple("Finding", [ "offset", "length", "data_type", "extension", "action", "filename" ])

	def __init__(self, args):
		self._args = args
		self._findings = [ ]
		self._start_time = datetime.datetime.utcnow()
		self._end_time = None
		self._end_offset = None
		self._active_der_types = None
		self._pem_potential_match = 0
		self._pem_successful_decode = 0
		self._der_potential_match = 0
		self._der_attempted_decode = 0
		self._der_successful_decode = 0
		self._der_passed_plausibility = 0
		self._der_failed_plausibility = 0

	def set_active_der_types(self, active_der_types):
		self._active_der_types = active_der_types

	def pem_potential_match(self):
		self._pem_potential_match += 1

	def pem_successful_decode(self):
		self._pem_successful_decode += 1

	def der_potential_match(self):
		self._der_potential_match += 1

	def der_attempt_decode(self):
		self._der_attempted_decode += 1

	def der_successful_decode(self):
		self._der_successful_decode += 1

	def der_passed_plausibility(self):
		self._der_passed_plausibility += 1

	def der_failed_plausibility(self):
		self._der_failed_plausibility += 1

	def record_finding(self, offset, length, data_type, extension, action, filename = None):
		self._findings.append(self._Finding(offset = offset, length = length, data_type = data_type, extension = extension, action = action, filename = filename))

	def finish(self, end_offset):
		self._end_time = datetime.datetime.utcnow()
		self._end_offset = end_offset

	def as_dict(self):
		return {
			"meta": {
				"filename":			self._args.filename,
				"start_offset":		self._args.seek_offset,
				"end_offset":		self._end_offset,
				"start_time_utc":	self._start_time,
				"end_time_utc":		self._end_time,
				"time_secs":		round((self._end_time - self._start_time).total_seconds()),
			},
			"analysis": {
				"pem": {
					"potential_match":		self._pem_potential_match,
					"successful_decode":	self._pem_successful_decode,
				},
				"der": {
					"active_types":			self._active_der_types,
					"potential_match":		self._der_potential_match,
					"attempted_decode":		self._der_attempted_decode,
					"successful_decode":	self._der_successful_decode,
					"passed_plausibility":	self._der_passed_plausibility,
					"failed_plausibility":	self._der_failed_plausibility,
				},
			},
			"findings": [ {
				"offset":		finding.offset,
				"length":		finding.length,
				"data_type":	finding.data_type,
				"extension":	finding.extension,
				"action":		finding.action,
			} for finding in self._findings	],
		}

	def dump(self, f = None):
		if f is None:
			f = sys.stderr
		stats = self.as_dict()
		print("Statistics of scraping %s" % (stats["meta"]["filename"]), file = f)
		print(file = f)
		print("Range      : From 0x%x to 0x%x" % (stats["meta"]["start_offset"], stats["meta"]["end_offset"]), file = f)
		print("Time       : From %s UTC to %s UTC" % (stats["meta"]["start_time_utc"].strftime("%Y-%m-%d %H:%M:%S"), stats["meta"]["end_time_utc"].strftime("%Y-%m-%d %H:%M:%S")), file = f)
		data_mib = (stats["meta"]["end_offset"] - stats["meta"]["start_offset"]) / 1024 / 1024

		if stats["meta"]["time_secs"] > 0.1:
			avg = "%.1f MiB/sec" % (data_mib / stats["meta"]["time_secs"])
		else:
			avg = "N/A"
		print("Processed  : %.0f MiB, average speed %s" % (data_mib, avg), file = f)
		print("PEM matches: %d offsets analyzed, %d successful PEM decodings" % (stats["analysis"]["pem"]["potential_match"], stats["analysis"]["pem"]["successful_decode"]), file = f)
		print("DER matches: %d offsets analyzed, %d attempted DER decodings total, %d successful DER decodings, %d also passed plausibility check" % (stats["analysis"]["der"]["potential_match"], stats["analysis"]["der"]["attempted_decode"], stats["analysis"]["der"]["successful_decode"], stats["analysis"]["der"]["passed_plausibility"]), file = f)
		print("DER types  : %s" % (", ".join(stats["analysis"]["der"]["active_types"])), file = f)
		written = sum(1 for finding in stats["findings"] if finding["action"] == "written")
		zero_length = sum(1 for finding in stats["findings"] if finding["action"] == "discard:zero_length")
		non_unique = sum(1 for finding in stats["findings"] if finding["action"] == "discard:non_unique")
		nested = sum(1 for finding in stats["findings"] if finding["action"] == "discard:nested")
		print("Findings   : %d total, %d written to disk, %d discarded" % (len(stats["findings"]), written, len(stats["findings"]) - written), file = f)
		print("Discards   : %d discarded because zero-length, %d because nested, %d because non-unique" % (zero_length, nested, non_unique), file = f)

		if written > 0:
			print(file = f)
			print("%-30s %s" % ("Data type", "Found"), file = f)
			stats_by_type = collections.Counter(finding["data_type"] for finding in stats["findings"] if finding["action"] == "written")
			for (data_type, counter) in stats_by_type.items():
				print("%-30s %d" % (self._FRIENDLY_DATA_TYPE.get(data_type, data_type), counter), file = f)

class ActionScrape(BaseAction):
	_DERHandler = collections.namedtuple("DERHandler", [ "asn1_spec", "data_type", "extension", "pem_marker", "sanity_check_fn", "precedence" ])
	_PEM_BEGIN = re.compile("^-----BEGIN (?P<marker>[ A-Za-z0-9]+)-----")
	_MARKERS = {
		"CERTIFICATE":				"crt",
		"OPENSSH PRIVATE KEY":		"openssh_key",
		"DSA PRIVATE KEY":			"dsa_key",
		"RSA PRIVATE KEY":			"rsa_key",
		"EC PRIVATE KEY":			"ec_key",
		"PUBLIC KEY":				"pubkey",
		"X509 CRL":					"crl",
		"CERTIFICATE REQUEST":		"csr",
		"NEW CERTIFICATE REQUEST":	"csr",
	}
	_DER_CLASSES = {
		handler_class.data_type: handler_class for handler_class in (
			_DERHandler(asn1_spec = rfc2459.Certificate(), data_type = "crt", extension = "der", pem_marker = "CERTIFICATE", sanity_check_fn = None, precedence = 10),
			_DERHandler(asn1_spec = rfc2437.RSAPrivateKey(), data_type = "rsa_key", extension = "der", pem_marker = "RSA PRIVATE KEY", sanity_check_fn = _DERSanityCheck.check_rsa_key, precedence = 20),
			_DERHandler(asn1_spec = rfc2459.DSAPrivateKey(), data_type = "dsa_key", extension = "der", pem_marker = "DSA PRIVATE KEY", sanity_check_fn = None, precedence = 20),
			_DERHandler(asn1_spec = rfc2459.SubjectPublicKeyInfo(), data_type = "pubkey", extension = "der", pem_marker = "PUBLIC KEY", sanity_check_fn = None, precedence = 30),
			_DERHandler(asn1_spec = x509sak.ASN1Models.ECPrivateKey(), data_type = "ec_key", extension = "der", pem_marker = "EC PRIVATE KEY", sanity_check_fn = _DERSanityCheck.check_ec_key, precedence = 20),
			_DERHandler(asn1_spec = x509sak.ASN1Models.PFX(), data_type = "pkcs12", extension = "p12", pem_marker = None, sanity_check_fn = None, precedence = 0),
			_DERHandler(asn1_spec = x509sak.ASN1Models.DSASignature(), data_type = "dsa_sig", extension = "der", pem_marker = None, sanity_check_fn = _DERSanityCheck.check_dsa_sig, precedence = 40),
	)}
	handler_classes = sorted(list(_DER_CLASSES.keys()))

	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		# Plausibilize input parameters
		kwargs_checker = KwargsChecker(optional_arguments = set(self._DER_CLASSES.keys()))
		kwargs_checker.check(self._args.include_dertype, hint = "DER classes to be included")
		kwargs_checker.check(self._args.exclude_dertype, hint = "DER classes to be excluded")

		# Plausibilize output directory
		if os.path.exists(self._args.outdir) and (not self._args.force):
			raise Exception("Directory %s already exists. Remove it first or use --force." % (self._args.outdir))
		try:
			os.makedirs(self._args.outdir)
		except FileExistsError:
			pass

		# Determine active DERHandler classes
		if len(self._args.include_dertype) == 0:
			active_der_types = set(self._DER_CLASSES.keys())
		else:
			active_der_types = set(self._args.include_dertype)
		active_der_types -= set(self._args.exclude_dertype)
		self._active_der_types = [ self._DER_CLASSES[class_name] for class_name in active_der_types ]
		self._active_der_types.sort(key = lambda handler: (handler.precedence, handler.data_type))

		self._stats = ActionScrapeStats(self._args)
		self._stats.set_active_der_types([ handler_class.data_type for handler_class in self._active_der_types ])

		self._matches = Intervals()
		self._hashes = set()
		engine = ScrapeEngine(self._args.filename)
		if not self._args.no_pem:
			engine.search(self._find_pem, b"-----BEGIN ", min_length = 52, max_length = 32 * 1024)
		if (not self._args.no_der) and (len(self._active_der_types) > 0):
			self._log.debug("Looking for %d DER type(s): %s", len(self._active_der_types), ", ".join(handler.data_type for handler in self._active_der_types))
			engine.search(self._find_der, bytes.fromhex("30"), min_length = 2, max_length = 32 * 1024)
		end_offset = engine.commence(start_offset = self._args.seek_offset, length = self._args.analysis_length, progress_callback = self._progress_callback)
		self._stats.finish(end_offset)
		self._stats.dump()
		if self._args.write_json is not None:
			JSONTools.write_to_file(self._stats.as_dict(), self._args.write_json)

	def _progress_callback(self, position, total_length, elapsed_secs):
		self._log.debug("Scan at %.0f MiB of %.0f MiB, %.1f%%. Average speed %.1f MiB/sec", position / 1024 / 1024, total_length / 1024 / 1024, position / total_length * 100, position / 1024 / 1024 / elapsed_secs)

	def _is_nested_match(self, offset, length):
		if self._args.extract_nested:
			# Completely disregard if we've already captured this.
			return False
		interval = Interval.begin_length(offset, length)
		if self._matches.fully_contained_in_subinterval(interval):
			# We already have this match.
			return True
		else:
			self._matches.add(interval)
			return False

	def _is_known_blob(self, data):
		if self._args.allow_non_unique_blobs:
			# We record the exact same file twice, always.
			return False
		blob_hash = hashlib.sha256(data).digest()
		if blob_hash in self._hashes:
			return True
		else:
			self._hashes.add(blob_hash)
			return False

	def _record_finding(self, offset, data_type, extension, data, encode_pem_marker = None, orig_extension = None):
		if orig_extension is None:
			orig_extension = data_type

		if len(data) == 0:
			self._stats.record_finding(offset, len(data), data_type, orig_extension, "discard:zero_length")
			return

		if self._is_nested_match(offset, len(data)):
			self._stats.record_finding(offset, len(data), data_type, orig_extension, "discard:nested")
			self._log.debug("Found %s/%s at offset 0x%x, length %d bytes, not recording nested match.", data_type, orig_extension, offset, len(data))
			return

		if self._is_known_blob(data):
			self._stats.record_finding(offset, len(data), data_type, orig_extension, "discard:non-unique")
			self._log.debug("Found %s/%s at offset 0x%x, length %d bytes, not recording non-unique match.", data_type, orig_extension, offset, len(data))
			return

		filename_args = {
			"otype":	orig_extension,
			"type":		data_type,
			"offset":	offset,
			"ext":		extension,
		}
		filename = self._args.outdir + "/" + (self._args.outmask % filename_args)
		self._stats.record_finding(offset, len(data), data_type, orig_extension, "written", filename)
		self._log.info("Found %s/%s at offset 0x%x, length %d bytes, saved as %s", data_type, orig_extension, offset, len(data), filename)

		if encode_pem_marker is not None:
			output_data = (PEMDataTools.data2pem(data, encode_pem_marker) + "\n").encode()
		else:
			output_data = data
		with open(filename, "wb") as f:
			f.write(output_data)

	def _find_pem(self, offset, data):
		self._stats.pem_potential_match()
		textdata = data.decode("ascii", errors = "ignore")
		result = self._PEM_BEGIN.match(textdata)
		if result is None:
			return
		result = result.groupdict()
		marker = result["marker"]
		full_re = re.compile("-----BEGIN %s-----(?P<pem_data>.*?)-----END %s-----" % (marker, marker), flags = re.DOTALL | re.MULTILINE)
		result = full_re.match(textdata)
		if result is None:
			return
		result = result.groupdict()
		pem_data = result["pem_data"]
		pem_data = pem_data.replace("\r", "")
		pem_data = pem_data.replace("\n", "")
		pem_data = pem_data.replace("\t", "")
		pem_data = pem_data.replace(" ", "")
		der_data = base64.b64decode(pem_data)

		self._stats.pem_successful_decode()
		data_type = self._MARKERS.get(marker, "unknown")
		self._record_finding(offset = offset, data_type = data_type, extension = "pem", data = der_data, encode_pem_marker = marker)

	def _find_der(self, offset, data):
		self._stats.der_potential_match()

		for der_candidate in self._active_der_types:
			try:
				self._stats.der_attempt_decode()
				(asn1, tail) = pyasn1.codec.der.decoder.decode(data, asn1Spec = der_candidate.asn1_spec)
				if len(tail) == 0:
					asn1_data = data
				else:
					asn1_data = data[:-len(tail)]
				self._stats.der_successful_decode()

				if (not self._args.disable_der_sanity_checks) and (der_candidate.sanity_check_fn is not None):
					# We want sanity checks enabled and for the successfully
					# deserialized ASN.1 blob there is a handler registered.
					# Execute it (it'll throw an exception on failure, which
					# we'll catch).
					der_candidate.sanity_check_fn(asn1)
				self._stats.der_passed_plausibility()

				if self._args.keep_original_der or (der_candidate.pem_marker is None):
					# Should not or cannot re-encode as PEM, write DER file
					self._record_finding(offset = offset, data_type = der_candidate.data_type, extension = der_candidate.extension, data = asn1_data)
				else:
					self._record_finding(offset = offset, data_type = der_candidate.data_type, extension = "pem", data = asn1_data, encode_pem_marker = der_candidate.pem_marker, orig_extension = der_candidate.extension)

			except pyasn1.error.PyAsn1Error as e:
				pass
			except _DERSanityCheck.SanityCheckFailedException as e:
				self._log.debug("Potential %s blob encountered at offset 0x%x, but failed sanity check: %s", der_candidate.data_type, offset, str(e))
				self._stats.der_failed_plausibility()
