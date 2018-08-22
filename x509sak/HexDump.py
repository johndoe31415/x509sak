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

class HexDump(object):
	def __init__(self):
		self._format = "full"
		self._width = 16
		self._spacers = [ 4, 8, 8 ]
		self._misschar = " "
		self._noasciichar = "."
		self._addr = True
		self._strrep = True
		assert(len(self._misschar) == 1)
		assert(len(self._noasciichar) == 1)

	def _dumpline(self, offset, data):
		line = ""

		if self._addr:
			line += "%6x   " % (offset)

		for charindex in range(self._width):
			if charindex >= len(data):
				char = self._misschar * 3
			else:
				char = " %02x" % (data[charindex])

			line += char
			for spacer in self._spacers:
				if ((charindex + 1) % spacer) == 0:
					line += " "

		if self._strrep:
			line += "|"
			for charindex in range(self._width):
				if charindex >= len(data):
					char = self._misschar
				else:
					if (32 < data[charindex] < 127):
						char = bytes([ data[charindex] ]).decode("latin1")
					else:
						char = self._noasciichar
				line += char
			line += "|"

		return line

	def as_lines(self, data):
		assert(isinstance(data, (bytes, bytearray)))
		yield from (self._dumpline(i, data[i : i + self._width]) for i in range(0, len(data), self._width))

	def as_str(self, data):
		return "\n".join(self.as_lines(data))

	def dump(self, data, fp = None):
		print(self.as_str(data), file = fp)
