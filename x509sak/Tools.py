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

import os
import re
import base64
import textwrap
import datetime
import pyasn1.type.univ
from x509sak.Exceptions import InvalidInputException

class PEMDataTools(object):
	@classmethod
	def pem2data(cls, pem_text, marker):
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

		if len(result) == 0:
			if data is None:
				raise Exception("No begin marker found: Not a %s?" % (marker))
			else:
				raise Exception("No end marker found. %s data incomplete?" % (marker))
		return result

	@classmethod
	def data2pem(cls, data, marker):
		line_begin = "-----BEGIN %s-----" % (marker)
		line_end = "-----END %s-----" % (marker)
		lines = [ line_begin ]
		lines += textwrap.wrap(base64.b64encode(data).decode("ascii"), width = 64)
		lines.append(line_end)
		return "\n".join(lines)

class CmdTools(object):
	@classmethod
	def cmdline(cls, cmd, env = None):
		def escape(text):
			if (" " in text) or ("\"" in text):
				return "\"%s\"" % (text.replace("\"", "\\\""))
			else:
				return text
		command = " ".join(escape(arg) for arg in cmd)

		if env is None:
			return command
		else:
			env_string = " ".join("%s=%s" % (key, escape(value)) for (key, value) in sorted(env.items()))
			return env_string + " " + command

class ASN1Tools(object):
	_REGEX_UTCTime = re.compile(r"(?P<year>\d{2})(?P<month>\d{2})(?P<day>\d{2})(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})Z")
	_REGEX_GeneralizedTime = re.compile(r"(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})Z")

	@classmethod
	def parse_datetime(cls, datetime_str):
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

class ECCTools(object):
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

class PathTools(object):
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

class MiscTools(object):
	@classmethod
	def verify_kwargs(cls, required_kwargs, given_kwargs, hint = "Method"):
		assert(isinstance(required_kwargs, set))
		assert(isinstance(given_kwargs, dict))

		missing_parameters = required_kwargs - given_kwargs.keys()
		if len(missing_parameters) > 0:
			raise InvalidInputException("%s requires parameters: %s" % (hint, ", ".join(sorted(missing_parameters))))

		excess_parameters = set(given_kwargs.keys()) - required_kwargs
		if len(excess_parameters) > 0:
			raise InvalidInputException("%s does not understand parameters: %s" % (hint, ", ".join(sorted(excess_parameters))))
