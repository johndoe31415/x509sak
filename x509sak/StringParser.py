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

import enum
from x509sak.Exceptions import InvalidInputException

class StringParseException(InvalidInputException): pass

class StringParser():
	class ParseCode(enum.IntEnum):
		RegularChar = 0
		ControlChar = 1

	def __init__(self, escape_chars, meta_character = "\\"):
		self._escape_chars = set(escape_chars)
		self._meta_char = meta_character
		self._escape_chars.add(meta_character)

	def parse(self, input_string):
		index = 0
		while index < len(input_string):
			next_char = input_string[index]
			if next_char == self._meta_char:
				index += 1
				if index == len(input_string):
					raise StringParseException("Got escape metacharacter at end of string, with nothing to follow.")
				escaped_char = input_string[index]
				if escaped_char not in self._escape_chars:
					raise StringParseException("Got unexpectedly an escaped character '%s'. Escaped are only %s." %	(escaped_char, ", ".join(self._escape_chars)))
				yield (self.ParseCode.RegularChar, escaped_char)
			elif next_char in self._escape_chars:
				yield (self.ParseCode.ControlChar, next_char)
			else:
				yield (self.ParseCode.RegularChar, next_char)
			index += 1

	def escape(self, parsed_string):
		result = [ ]
		for (char_type, char) in parsed_string:
			if (char_type == self.ParseCode.RegularChar) and (char in self._escape_chars):
				result.append("%s%s" % (self._meta_char, char))
			else:
				result.append(char)
		return "".join(result)

	def split(self, input_string, control_char, reassemble = False):
		split_data = [ ]
		split_char = (self.ParseCode.ControlChar, control_char)
		for next_char in self.parse(input_string):
			if next_char != split_char:
				# Just append
				if len(split_data) == 0:
					split_data.append([ ])
				split_data[-1].append(next_char)
			else:
				split_data.append([ ])
		if reassemble:
			split_data = [ self.escape(item) for item in split_data ]
		return split_data
