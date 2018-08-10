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

from x509sak.tests import BaseTest
from x509sak.PassphraseGenerator import PassphraseGenerator

class PassphraseGeneratorTests(BaseTest):
	def test_passphrase_integers(self):
		for bits in range(1, 10):
			maxvalue = 2 ** bits
			for _ in range(100):
				intvalue = PassphraseGenerator.rand_int(bits)
				self.assertGreaterEqual(intvalue, 0)
				self.assertLess(intvalue, maxvalue)

	def test_max_radix_bits(self):
		for i in range(1, 20):
			self.assertEqual(PassphraseGenerator.max_digits_in_radix(i, 2), i)
			self.assertEqual(PassphraseGenerator.max_digits_in_radix(i, 4), (i + 1) // 2)
			self.assertEqual(PassphraseGenerator.max_digits_in_radix(i, 8), (i + 2) // 3)
			self.assertEqual(PassphraseGenerator.max_digits_in_radix(i, 256), (i + 7) // 8)

		self.assertEqual(PassphraseGenerator.max_digits_in_radix(10, 26), 3)
		self.assertEqual(PassphraseGenerator.max_digits_in_radix(20, 26), 5)
		self.assertEqual(PassphraseGenerator.max_digits_in_radix(30, 26), 7)
		self.assertEqual(PassphraseGenerator.max_digits_in_radix(40, 26), 9)
		self.assertEqual(PassphraseGenerator.max_digits_in_radix(50, 26), 11)
		self.assertEqual(PassphraseGenerator.max_digits_in_radix(60, 26), 13)
		self.assertEqual(PassphraseGenerator.max_digits_in_radix(70, 26), 15)
		self.assertEqual(PassphraseGenerator.max_digits_in_radix(140, 26), 30)
		self.assertEqual(PassphraseGenerator.max_digits_in_radix(150, 26), 32)
		self.assertEqual(PassphraseGenerator.max_digits_in_radix(230, 26), 49)
		self.assertEqual(PassphraseGenerator.max_digits_in_radix(240, 26), 52)
		self.assertEqual(PassphraseGenerator.max_digits_in_radix(500, 26), 107)

	def test_passphrase_gen(self):
		for ppg in [ PassphraseGenerator.all_ascii(), PassphraseGenerator.non_ambiguous(), PassphraseGenerator.pronouncible() ]:
			passphrase = ppg.gen_passphrase(20)
			for _ in range(100):
				new_passphrase = ppg.gen_passphrase(20)
				self.assertEqual(len(passphrase), len(new_passphrase))
