#!/usr/bin/python3
#
#	HexDump - Dump data in hex format
#	Copyright (C) 2011-2013 Johannes Bauer
#
#	This file is part of jpycommon.
#
#	jpycommon is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	jpycommon is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with jpycommon; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>
#
#	File UUID 941e5121-2571-4c39-a58b-975600045055

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

	def _dumpline(self, offset, data, markers = None):
		if markers is None:
			markers = { }
		line = ""

		if self._addr:
			line += "%6x   " % (offset)

		for charindex in range(self._width):
			if charindex >= len(data):
				char = self._misschar * 3
			else:
				char = markers.get(offset + charindex, " ")
				char += "%02x" % (data[charindex])

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

	def dumpstr(self, data, markers = None):
		return [ self._dumpline(i, data[i : i + self._width], markers) for i in range(0, len(data), self._width) ]

	def dump(self, data, markers = None):
		for line in self.dumpstr(data, markers):
			print(line)

if __name__ == "__main__":
	mydata = "Hallo das ist ein cooler Test und hier sehe ich den utf8 Ümläut!".encode("utf-8")
	dumper = HexDump()
	dumper.dump(mydata)
