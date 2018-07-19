#!/usr/bin/python3
#	ratched - TLS connection router that performs a man-in-the-middle attack
#	Copyright (C) 2017-2017 Johannes Bauer
#
#	This file is part of ratched.
#
#	ratched is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	ratched is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with ratched; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>
import re

class Patcher(object):
	def __init__(self, filename, filetype = "c"):
		assert(filetype in [ "c", "markdown" ])
		self._filename = filename
		self._filetype = filetype

	def _begin_re_str(self, key):
		return {
			"c":		r"/\* Begin of %s -- auto-generated, do not edit! \*/\n" % (key),
			"markdown":	r"\[//\]: # \(Begin of %s -- auto-generated, do not edit!\)" % (key),
		}[self._filetype]

	def _end_re_str(self, key):
		return {
			"c":		r"[\t ]*/\* End of %s -- auto-generated, do not edit! \*/" % (key),
			"markdown":	r"\[//\]: # \(End of %s -- auto-generated, do not edit!\)" % (key),
		}[self._filetype]

	def regex(self, key):
		regex = re.compile("(?P<begin>" + self._begin_re_str(key) + ")(?P<text>.*?)(?P<end>" + self._end_re_str(key) + ")", flags = re.DOTALL)
		return regex

	def patch(self, key, value):
		text = self.read()
		regex = self.regex(key)
		def substitute(match):
			groups = match.groupdict()
			return groups["begin"] + value + groups["end"]
		text = regex.sub(lambda match: substitute(match), text)
		with open(self._filename, "w") as f:
			f.write(text)

	def read(self):
		with open(self._filename) as f:
			text = f.read()
		return text
