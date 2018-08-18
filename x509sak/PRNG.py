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

import time
import hashlib

class PRNG(object):
	def __init__(self, seed = None):
		self._seed = seed
		self._buffer = bytearray()
		self.reset()

	def get(self, length):
		self._fill_buffer(length)
		(result, self._buffer) = (self._buffer[ : length], self._buffer[length : ])
		return result

	def _fill_buffer(self, length):
		while len(self._buffer) < length:
			self._buffer += self._next_chunk()

	def reset(self):
		self.init_state(self._seed or b"123456789")

	def init_state(self, state):
		raise NotImplementedError("init_state")

	def _next_chunk(self):
		raise NotImplementedError("_next_chunk")

	def profile(self, min_time_secs = 3):
		t0 = time.time()
		length = 0
		while True:
			data = self.get(128 * 1024)
			length += len(data)
			t1 = time.time()
			tdiff = t1 - t0
			if tdiff > min_time_secs:
				break
		print("%d bytes in %.1f secs: %.1f MBytes/sec" % (length, tdiff, length / tdiff / 1e6))

	def write_fp(self, fp, length):
		remaining = length
		while remaining > 0:
			chunk_size = min(1024 * 1024, remaining)
			data = self.get(chunk_size)
			fp.write(data)
			remaining -= len(data)

	def write_file(self, filename, length):
		with open(filename, "wb") as f:
			self.write_fp(f, length)

	def write_bracketed(self, filename, prefix_len, data, suffix_len):
		with open(filename, "wb") as f:
			self.write_fp(f, prefix_len)
			f.write(data)
			self.write_fp(f, suffix_len)

class HashedPRNG(PRNG):
	"""This PRNG is *not* a CSPRNG. It's intended purely for testing
	purposes."""

	_HASHFNC = hashlib.sha512

	def init_state(self, initial_state):
		self._state = self._HASHFNC(initial_state).digest()

	def _next_chunk(self):
		result = self._state
		self._state = self._HASHFNC(self._state).digest()
		return result
