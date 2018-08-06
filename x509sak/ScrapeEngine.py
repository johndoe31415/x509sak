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
import collections

class ScrapeEngine(object):
	_Pattern = collections.namedtuple("Pattern", [ "callback", "pattern", "min_length", "max_length" ])

	def __init__(self, filename):
		self._filename = filename
		self._patterns = [ ]
		self._chunk_size = 1024 * 1024
		self._last_chunk_offsets = set()

	def search(self, callback, pattern, min_length = 0, max_length = 4096):
		pattern = self._Pattern(callback = callback, pattern = pattern, min_length = min_length, max_length = max_length)
		self._patterns.append(pattern)

	def _search_pattern(self, pattern, offset, data, trackback):
		results = { }
		search_offset = 0
		while True:
			found_index = data.find(pattern.pattern, search_offset)
			if (found_index == -1) or (found_index >= len(data) - trackback):
				break
			abs_offset = offset + found_index
			results[abs_offset] = pattern
			search_offset = found_index + 1
		return results

	def _search_chunk(self, start_offset, data, trackback):
		results = { }
		for pattern in self._patterns:
			results.update(self._search_pattern(pattern, start_offset, data, trackback))

		for (offset, pattern) in results.items():
			if offset in self._last_chunk_offsets:
				continue
			relative_offset = offset - start_offset
			found_data = data[relative_offset : relative_offset + pattern.max_length]
			if len(found_data) > pattern.min_length:
				pattern.callback(offset, found_data)
		self._last_chunk_offsets = set(results.keys())

	def commence(self):
		trackback = max(pattern.max_length for pattern in self._patterns)
		with open(self._filename, "rb") as f:
			while True:
				try:
					f.seek(-trackback, os.SEEK_CUR)
				except OSError:
					pass
				offset = f.tell()
				chunk = f.read(self._chunk_size + trackback)
				if len(chunk) == trackback:
					# No more data left
					break
				self._search_chunk(offset, chunk, trackback)
