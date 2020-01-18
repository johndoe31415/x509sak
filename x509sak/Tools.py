#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2020 Johannes Bauer
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
import json
import enum
import pkgutil
import gzip
import time
import textwrap
import datetime
import pprint
import collections
import urllib.parse
import pyasn1.type.univ
import pyasn1.codec.der.encoder
import pyasn1.codec.der.decoder
from x509sak.Exceptions import UnexpectedFileContentException, InvalidUsageException, InvalidInputException

class PEMDataTools():
	@classmethod
	def pem2data(cls, pem_text, marker, ignore_errors = False):
		line_begin = "-----BEGIN %s-----" % (marker)
		line_end = "-----END %s-----" % (marker)
		result = [ ]
		data = None
		for line in pem_text.split("\n"):
			line = line.rstrip("\r")
			if data is not None:
				if line == line_end:
					# Finished!
					result.append(base64.b64decode("".join(data)))
					data = None
				else:
					data.append(line)
			else:
				if line == line_begin:
					data = [ ]

		if (len(result) == 0) and (not ignore_errors):
			if data is None:
				raise UnexpectedFileContentException("No begin marker found: Not a %s?" % (marker))
			else:
				raise UnexpectedFileContentException("No end marker found. %s data incomplete?" % (marker))
		return result

	@classmethod
	def data2pem(cls, data, marker):
		if marker is None:
			raise InvalidUsageException("Cannot encode object in PEM without a given marker.")

		line_begin = "-----BEGIN %s-----" % (marker)
		line_end = "-----END %s-----" % (marker)
		lines = [ line_begin ]
		lines += textwrap.wrap(base64.b64encode(data).decode("ascii"), width = 64)
		lines.append(line_end)
		return "\n".join(lines)

class CmdTools():
	_ENV_ALWAYS_EXPORT = [ "SOFTHSM2_CONF", "COVERAGE_FILE" ]

	@classmethod
	def cmdline(cls, cmd, env = None):
		if env is None:
			env = { }
		else:
			env = dict(env)
		for varname in cls._ENV_ALWAYS_EXPORT:
			if (varname in os.environ) and (varname not in env):
				env[varname] = os.environ[varname]

		def escape(text):
			if (" " in text) or ("\"" in text) or ("'" in text) or (";" in text) or ("&" in text) or ("*" in text):
				return "'%s'" % (text.replace("'", "\'"))
			else:
				return text
		command = " ".join(escape(arg) for arg in cmd)

		if env is None:
			return command
		else:
			env_string = " ".join("%s=%s" % (key, escape(value)) for (key, value) in sorted(env.items()))
			return (env_string + " " + command).lstrip()

class ASN1Tools():
	_REGEX_UTCTime = re.compile(r"(?P<year>\d{2})(?P<month>\d{2})(?P<day>\d{2})(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})Z")
	_REGEX_GeneralizedTime = re.compile(r"(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})Z")
	_DecodedASN1 = collections.namedtuple("DecodedASN1", [ "asn1", "tail", "flags", "original_der", "encoded_der" ])

	@classmethod
	def parse_datetime(cls, datetime_str):
		try:
			result = cls._REGEX_UTCTime.fullmatch(datetime_str)
			if result is not None:
				result = { key: int(value) for (key, value) in result.groupdict().items() }
				if result["year"] >= 50:
					result["year"] += 1900
				else:
					result["year"] += 2000
				return datetime.datetime(result["year"], result["month"], result["day"], result["hour"], result["minute"], result["second"])

			result = cls._REGEX_GeneralizedTime.fullmatch(datetime_str)
			if result is not None:
				result = { key: int(value) for (key, value) in result.groupdict().items() }
				return datetime.datetime(result["year"], result["month"], result["day"], result["hour"], result["minute"], result["second"])
		except ValueError:
			pass
		return None

	@classmethod
	def bitstring2bytes(cls, bitstr):
		if (len(bitstr) % 8) != 0:
			raise Exception("Unable to decode ASN.1 BitString to bytes. Size not a multiple of 8: %d" % (len(bitstr)))
		bytes_data = bytearray()
		for i in range(0, len(bitstr), 8):
			byte_data = bitstr[i : i + 8]
			value = sum(bitval << bitpos for (bitpos, bitval) in enumerate(reversed(byte_data)))
			bytes_data.append(value)
		return bytes(bytes_data)

	@classmethod
	def bytes2bitstring(cls, bytedata):
		bitstring = [ ]
		for bytevalue in bytedata:
			for bit in reversed(range(8)):
				bitstring.append((bytevalue >> bit) & 1)
		return pyasn1.type.univ.BitString(bitstring)

	@classmethod
	def bitstring_is_empty(cls, bitstr):
		return (len(bitstr) == 0) or (set(bitstr) == set([ 0 ]))

	@classmethod
	def bitstring_has_trailing_zeros(cls, bitstr):
		return (len(bitstr) > 0) and (bitstr[len(bitstr) - 1] == 0)

	@classmethod
	def bitstring_highbit(cls, bitstr):
		if len(bitstr) == 0:
			return None
		for bit in range(len(bitstr) - 1, -1, -1):
			if bitstr[bit] == 1:
				return bit
		return None

	@classmethod
	def redecode(cls, asn1, asn1_spec):
		encoded_asn1 = pyasn1.codec.der.encoder.encode(asn1)
		return pyasn1.codec.der.decoder.decode(encoded_asn1, asn1Spec = asn1_spec)

	@classmethod
	def safe_decode(cls, der_data, asn1_spec = None):
		result = {
			"asn1": None,
			"tail": None,
			"flags": set(),
			"original_der": der_data,
			"encoded_der": None,
		}
		try:
			(result["asn1"], result["tail"]) = pyasn1.codec.der.decoder.decode(der_data, asn1Spec = asn1_spec)
			result["encoded_der"] = pyasn1.codec.der.encoder.encode(result["asn1"])
			if result["encoded_der"] != der_data:
				result["flags"].add("non-der")
		except pyasn1.error.PyAsn1Error:
			result["flags"].add("undecodable")
		return cls._DecodedASN1(**result)

class ECCTools():
	@classmethod
	def decode_enc_pubkey(cls, enc_pubkey):
		if enc_pubkey[0] != 0x04:
			raise Exception("Unable to decode compressed (0x%x) EC key." % (enc_pubkey[0]))
		if (len(enc_pubkey) % 2) != 1:
			raise Exception("Unable to determine correct splitting of %d-bytes inner EC key." % (len(enc_pubkey)))
		bytelen = len(enc_pubkey) // 2
		x = int.from_bytes(enc_pubkey[1 : 1 + bytelen], byteorder = "big")
		y = int.from_bytes(enc_pubkey[1 + bytelen : ], byteorder = "big")
		return (x, y)

class PathTools():
	@classmethod
	def find(cls, search_path, filename):
		directories = search_path.split(":")
		for directory in directories:
			if not directory.endswith("/"):
				directory += "/"
			full_filename = directory + filename
			if os.path.isfile(directory + filename):
				return full_filename
		return None

class DateTimeTools():
	@classmethod
	def strfmt_iso(cls, timestamp):
		"""timestamp.strftime("%Y-%m-%dT%H:%M:%S") produces for years less than
		4 digits no leading zeros. This is something that strptime then cannot
		parse anymore. We therefore implement it ourselves."""
		return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (timestamp.year, timestamp.month, timestamp.day, timestamp.hour, timestamp.minute, timestamp.second)

class JSONTools():
	@classmethod
	def translate(cls, obj):
		if isinstance(obj, dict):
			translated = { key: cls.translate(value) for (key, value) in obj.items() }
		elif isinstance(obj, (list, tuple)):
			translated = [ cls.translate(value) for value in obj ]
		elif isinstance(obj, set):
			translated = sorted(cls.translate(value) for value in obj)
		elif isinstance(obj, enum.IntEnum):
			translated = {
				"name":		obj.name,
				"value":	obj.value,
			}
		elif isinstance(obj, datetime.datetime):
			return obj.strftime("%Y-%m-%d %H:%M:%S")
		else:
			dict_converter = getattr(obj, "to_dict", None)
			if dict_converter is not None:
				translated = cls.translate(dict_converter())
			else:
				translated = obj
		return translated

	class Encoder(json.JSONEncoder):
		def iterencode(self, obj, _one_shot = False):
			# We need to have a pre-translate step because the stupid Python
			# standard encoder supplies no way of intercepting known data types
			# such as int. IntEnum is an instance of int, unfortunately,
			# therefore it's always encoded as a number.
			obj = JSONTools.translate(obj)
			return super().iterencode(obj, _one_shot)

	@classmethod
	def serialize(cls, data):
		return json.dumps(data, indent = 4, sort_keys = True, cls = cls.Encoder)

	@classmethod
	def write_to_fp(cls, data, fp, pretty = False):
		if pretty:
			json.dump(data, fp = fp, indent = 4, sort_keys = True, cls = cls.Encoder)
		else:
			json.dump(data, fp = fp, separators = (',', ':'), cls = cls.Encoder)
		print(file = fp)

	@classmethod
	def write_to_file(cls, data, filename):
		with open(filename, "w") as fp:
			cls.write_to_fp(data, fp)

	@classmethod
	def load_internal(cls, pkgname, filename):
		data = pkgutil.get_data(pkgname, filename)
		if filename.endswith(".gz"):
			data = gzip.decompress(data)
		# Older Python versions (3.5, running on Travis-CI) require this to be
		# str, not bytes.
		data = data.decode("ascii")
		return json.loads(data)

class TextTools():
	@classmethod
	def sp(cls, count, singular, plural = None):
		if plural is None:
			plural = singular + "s"
		if count == 1:
			return "one %s" % (singular)
		else:
			return "%d %s" % (count, plural)

	@classmethod
	def abbreviate(cls, text, to_length):
		if len(text) <= to_length:
			return text
		else:
			textlen = to_length - 3
			tail = round(textlen / 4)
			head = textlen - tail
			if tail + head >= len(text):
				# Only abbreviate tail
				return text[ : (to_length - 3)] + "..."
			else:
				# Abbreviate head and tail
				return text[ : head] + "..." + text[-tail : ]

class ValidationTools():
	_DOMAIN_NAME_RE = re.compile(r"([-a-zA-Z0-9]+\.)*[-a-zA-Z0-9]+")
	_EMAIL_ADDRESS_RE = re.compile(r"(?P<mailbox>[-a-zA-Z0-9.!#$%&'*+/=?^_`{|}~]+)@(?P<domainname>.*)")
	_URI_RE = re.compile(r"(?P<scheme>[a-z]+):(?P<authority>/*[-a-zA-Z0-9+%_.:,=;@\[\]]+)?(?P<path>/[-a-zA-Z0-9+%_.:,=;@/]+)?(?P<query>\?[-a-zA-Z0-9+%_.:,=;@/?#]*)?")
	_LABEL_RE = re.compile(r"(?P<left>[-a-zA-Z0-9]*)(?P<wildcard>\*)?(?P<right>[-a-zA-Z0-9]*)")

	class DomainnameTemplateValidationResult(enum.IntEnum):
		Valid = 0
		InvalidCharacter = 1
		MoreThanOneWildcard = 2
		FullWildcardNotLeftmost = 3
		WildcardInInternationalDomain = 4

	@classmethod
	def validate_email_address(cls, email_address):
		"""Validate an email address according to a subset of RFC5322; i.e., we
		don't even accept all RFC5322 mail addresses and even less all RFC822
		email addresses here. This means that (technically) valid email
		addresses will fail this check."""
		match = cls._EMAIL_ADDRESS_RE.fullmatch(email_address)
		if match is not None:
			match = match.groupdict()
			return cls.validate_domainname(match["domainname"])
		else:
			return False

	@classmethod
	def validate_domainname(cls, domainname):
		return cls._DOMAIN_NAME_RE.fullmatch(domainname) is not None

	@classmethod
	def validate_domainname_template(cls, domainname_template):
		labels = domainname_template.lower().split(".")
		seen_wildcard = False
		for (lid, label) in enumerate(labels):
			result = cls._LABEL_RE.fullmatch(label)
			if result is None:
				return (cls.DomainnameTemplateValidationResult.InvalidCharacter, label)
			result = result.groupdict()

			if result["wildcard"] is not None:
				if label.startswith("xn--"):
					return (cls.DomainnameTemplateValidationResult.WildcardInInternationalDomain, label)

				if seen_wildcard:
					return (cls.DomainnameTemplateValidationResult.MoreThanOneWildcard, label)
				seen_wildcard = True

				if (result["left"] == "") and (result["right"] == ""):
					if lid != 0:
						return (cls.DomainnameTemplateValidationResult.FullWildcardNotLeftmost, label)
		return (cls.DomainnameTemplateValidationResult.Valid, domainname_template)

	@classmethod
	def _escape_regex(cls, text):
		for escape_char in "\\*.+?()[]":
			text = text.replace(escape_char, "\\" + escape_char)
		return text

	@classmethod
	def validate_domainname_template_match(cls, template, domainname):
		template_re = cls._escape_regex(template.lower()).replace("\\*", r"[-a-z0-9]*")
		match = re.fullmatch(template_re, domainname.lower())
		return match is not None

	@classmethod
	def validate_uri(cls, uri):
		if cls._URI_RE.fullmatch(uri) is None:
			return False
		split_uri = urllib.parse.urlsplit(uri)
		if split_uri.scheme == "":
			return False
		if split_uri.scheme in [ "http", "https" ]:
			return (split_uri.netloc != "") and ((split_uri.path == "") or (split_uri.path.startswith("/")))
		else:
			return True

class PaddingTools():
	@classmethod
	def unpad_pkcs1(cls, data):
		if data[0] != 1:
			raise InvalidInputException("PKCS#1 padding must start with 0x01")

		i = 0
		last_char = None
		for i in range(1, len(data)):
			if data[i] == 0xff:
				continue
			elif data[i] == 0x0:
				# Finished
				last_char = i
				break
			else:
				raise InvalidInputException("PKCS#1 padding must be either 0xff or 0x00 at offset %d, was 0x%02x" % (i, data[i]))

		if last_char is None:
			raise InvalidInputException("PKCS#1 padding does not seem to contain data.")
		return data[i + 1:]

class FileLockTools():
	class _FileLockObject():
		def __init__(self, lock_dir):
			self._lock_dir = lock_dir

		def __enter__(self):
			return self

		def __exit__(self, *args):
			try:
				os.rmdir(self._lock_dir)
			except FileNotFoundError:
				pass

	@classmethod
	def lock(cls, filename, retry = 0.25):
		filename = os.path.realpath(filename)
		lock_name = os.path.dirname(filename) + "/." + os.path.basename(filename) + ".lock"
		while True:
			try:
				os.mkdir(lock_name)
				# Acquired lock
				break
			except FileExistsError:
				# Other process holds lock
				time.sleep(retry)
		return FileLockTools._FileLockObject(lock_name)

class DebugTools():
	@classmethod
	def pprint(cls, data):
		pprint.PrettyPrinter().pprint(data)
