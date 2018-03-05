#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2017-2017 Johannes Bauer
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

import re
import base64
import textwrap
import datetime

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
	def cmdline(cls, cmd):
		def escape(text):
			if (" " in text) or ("\"" in text):
				return "\"%s\"" % (text.replace("\"", "\\\""))
			else:
				return text
		return " ".join(escape(arg) for arg in cmd)

class ASN1Tools(object):
	_REGEX_UTCTime = re.compile("(?P<year>\d{2})(?P<month>\d{2})(?P<day>\d{2})(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})Z")
	_REGEX_GeneralizedTime = re.compile("(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})Z")

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
