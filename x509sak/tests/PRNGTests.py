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

import hashlib
from x509sak.PRNG import HashedPRNG
from x509sak.tests.BaseTest import BaseTest

class PRNGTests(BaseTest):
	def test_prng(self):
		prng = HashedPRNG(b"foobar")
		first = prng.get(128)
		prng.reset()
		second = prng.get(128)
		self.assertEqual(first, second)

	def test_pattern(self):
		data = HashedPRNG(b"foobar").get(1024)
		self.assertEqual(hashlib.md5(data).hexdigest(), "acc988f3788299f2bd603c38902ae0a7")
		data = HashedPRNG(b"barfoo").get(1024)
		self.assertEqual(hashlib.md5(data).hexdigest(), "fe06bbd9bf3988af7b3f2d12b20bd583")

	def test_beginning(self):
		data = HashedPRNG(b"foobar").get(1024)
		for l in range(len(data) + 1):
			part = HashedPRNG(b"foobar").get(l)
			self.assertEqual(part, data[:l])

	def test_twoparts(self):
		data = HashedPRNG(b"foobar").get(256)
		for l in range(len(data) + 1):
			prng = HashedPRNG(b"foobar")
			part1 = prng.get(l)
			part2 = prng.get(len(data) - l)
			self.assertEqual(data, part1 + part2)
