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
import time
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

	def _search_pattern(self, pattern, offset, data, ignore_tail_bytes):
		results = { }
		search_offset = 0
		while True:
			found_index = data.find(pattern.pattern, search_offset)
			if (found_index == -1) or (found_index >= len(data) - ignore_tail_bytes):
				break
			abs_offset = offset + found_index
			results[abs_offset] = pattern
			search_offset = found_index + 1
		return results

	def _search_chunk(self, start_offset, data, ignore_tail_bytes):
		results = { }
		for pattern in self._patterns:
			results.update(self._search_pattern(pattern, start_offset, data, ignore_tail_bytes))
		for (offset, pattern) in results.items():
			if offset in self._last_chunk_offsets:
				continue
			relative_offset = offset - start_offset
			found_data = data[relative_offset : relative_offset + pattern.max_length]
			if len(found_data) > pattern.min_length:
				pattern.callback(offset, found_data)
		self._last_chunk_offsets = set(results.keys())

	def commence(self, start_offset = 0, length = None, progress_callback = None):
		t0 = time.time()
		trackback = max(pattern.max_length for pattern in self._patterns)

		chunk_count = 0
		with open(self._filename, "rb") as f:
			# EOF position = actual end-of-file
			f.seek(0, os.SEEK_END)
			eof_position = f.tell()

			if length is not None:
				# But can be shorter
				eof_position = min(eof_position, start_offset + length)
			f.seek(start_offset)

			# Then seek through whole file
			at_eof = False
			while not at_eof:
				offset = f.tell()
				chunk = f.read(self._chunk_size + trackback)
				at_eof = (offset + len(chunk)) >= eof_position
				if not at_eof:
					ignore_tail_bytes = trackback
				else:
					ignore_tail_bytes = 0
				self._search_chunk(offset, chunk, ignore_tail_bytes)
				chunk_count += 1
				if (progress_callback is not None) and ((chunk_count % 100) == 0):
					progress_callback(position = offset + len(chunk) - start_offset, total_length = eof_position - start_offset, elapsed_secs = time.time() - t0)
			end_offset = f.tell()
		return end_offset
