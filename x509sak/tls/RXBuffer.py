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

class RXBuffer():
	def __init__(self):
		self._data = bytearray()

	def get_all(self):
		return self.get(len(self))

	def read_from(self, source, until):
		while True:
			if until(self):
				break
			data = source(self)
			if len(data) > 0:
				self += data

	def have_bytes(self, count):
		return len(self._data) >= count

	def have_line(self):
		return self._data.find(b"\n") != -1

	def get(self, length):
		if len(self._data) < length:
			return None
		else:
			chunk = self._data[:length]
			self._data = self._data[length:]
			return chunk

	def getline(self):
		index = self._data.find(b"\n")
		if index == -1:
			return None
		else:
			return self.get(index + 1)

	def __iadd__(self, data):
		self._data += data
		return self

	def __len__(self):
		return len(self._data)
