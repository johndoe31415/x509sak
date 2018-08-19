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

import collections
from x509sak.tests import BaseTest

class MultiplicationBitsTests(BaseTest):
	@staticmethod
	def _enumerate_bit_values(bits):
		return range(2 ** (bits - 1), 2 ** bits)

	@staticmethod
	def _set_msb_bits(value, bitcnt, bitvalue):
		assert(bitcnt <= bitvalue.bit_length())
		bits = value.bit_length()
		shift = max((bits - bitcnt), 0)
		mask = ((1 << bitcnt) - 1) << shift
		value = value & ~mask
		value = value | (bitvalue << shift)
		return value

	def _set_msb_bits_11(self, value):
		return self._set_msb_bits(value, 2, 0b11)

	def _set_msb_bits_111(self, value):
		return self._set_msb_bits(value, 3, 0b111)

	def test_msb_bits(self):
		self.assertEqual(self._set_msb_bits(0b100000000, 3, 0b101), 0b101000000)
		self.assertEqual(self._set_msb_bits(0b100000000, 4, 0b1011), 0b101100000)
		self.assertEqual(self._set_msb_bits(0b100000000, 6, 0b101101), 0b101101000)
		self.assertEqual(self._set_msb_bits(0, 3, 0b101), 0b101)

	def test_enumerate_bitvalues(self):
		bit = 4
		values = list(self._enumerate_bit_values(bit))
		bitlengths = list(set(value.bit_length() for value in values))
		self.assertEqual(bitlengths, [ bit ])
		self.assertEqual((values[0] - 1).bit_length(), bit - 1)
		self.assertEqual(values[0].bit_length(), bit)
		self.assertEqual(values[-1].bit_length(), bit)
		self.assertEqual((values[-1] + 1).bit_length(), bit + 1)

	def test_multiply_two(self):
		bit = 4
		values = self._enumerate_bit_values(4)
		for p in values:
			for q in values:
				if q < p:
					continue
				n = (self._set_msb_bits_11(p)) * (self._set_msb_bits_11(q))
				self.assertEqual(n.bit_length(), 2 * bit)

	def test_multiply_any_three(self):
		bit = 4
		values = self._enumerate_bit_values(bit)

		bits = collections.Counter()
		for p in values:
			for q in values:
				for r in values:
					q_ = (2 * self._set_msb_bits_111(p) * (self._set_msb_bits_111(q))) + 1
					n = q_ * self._set_msb_bits_111(r)
					length = n.bit_length()
					bits[length] += 1
		self.assertEqual(len(bits), 1)

	def test_multiply_pq_three(self):
		bit = 4
		values = self._enumerate_bit_values(bit)

		bits = collections.Counter()
		for p in values:
			for q in values:
				p = self._set_msb_bits(p, 3, 0b111)
				q = self._set_msb_bits(q, 3, 0b111)
				q_ = (2 * p * q) + 1
				n = p * q_
				length = n.bit_length()
				bits[length] += 1
		self.assertEqual(len(bits), 1)
