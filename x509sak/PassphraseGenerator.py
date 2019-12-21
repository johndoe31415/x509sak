#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2019 Johannes Bauer
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
import string

class PassphraseGenerator():
	def __init__(self, alphabets):
		self._alphabets = alphabets

	@classmethod
	def all_ascii(cls):
		return cls([ string.ascii_lowercase + string.ascii_uppercase + string.digits ])

	@classmethod
	def non_ambiguous(cls):
		remove_chars = (
			"0Oo",
			"1ilI",
			"2Z",
			"6G",
			"8B",
			"9g",
			"uv",
			"UV",
		)
		alphabet = set(string.ascii_lowercase + string.ascii_uppercase + string.digits)
		for remove_chunk in remove_chars:
			alphabet -= set(remove_chunk)
		return cls([ tuple(alphabet) ])

	@classmethod
	def pronouncible(cls):
		vovels = set("aeiou")
		consonants = set(string.ascii_lowercase) - vovels
		return cls([ tuple(consonants), tuple(vovels) ])

	@staticmethod
	def rand_int(bits):
		assert(isinstance(bits, int))
		assert(bits > 0)

		# Round up to full bytes first
		byte_cnt = (bits + 7) // 8
		rand_bytes = bytearray(os.urandom(byte_cnt))
		assert(len(rand_bytes) == byte_cnt)

		if (bits % 8) != 0:
			# Truncate most significant byte
			want_bits = bits % 8
			mask = (1 << want_bits) - 1
			rand_bytes[0] &= mask

		# Convert to integer and check we did the right thing.
		intvalue = int.from_bytes(rand_bytes, byteorder = "big")
		assert(0 <= intvalue < (2 ** bits))
		return intvalue

	# TODO: Is there a more efficient algorithm to do this? Probably so, but
	# one that involves no floating point maths?
	@staticmethod
	def max_digits_in_radix(bits, new_radix):
		assert(bits > 0)
		maxvalue = 2 ** bits
		length = 1
		curvalue = new_radix
		while curvalue < maxvalue:
			length += 1
			curvalue *= new_radix
		return length

	def max_digits(self, bits):
		assert(bits > 0)
		maxvalue = 2 ** bits
		length = 0
		curvalue = 1
		while curvalue < maxvalue:
			alphasize = len(self._alphabets[length % len(self._alphabets)])
			length += 1
			curvalue *= alphasize
		return length

	def gen_passphrase(self, bits):
		intvalue = self.rand_int(bits)
		pw_len = self.max_digits(bits)
		passphrase = [ ]
		for i in range(pw_len):
			alphabet = self._alphabets[i % len(self._alphabets)]
			(intvalue, charno) = divmod(intvalue, len(alphabet))
			passphrase.append(alphabet[charno])
		assert(intvalue == 0)
		return "".join(passphrase)
