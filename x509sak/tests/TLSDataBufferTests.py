#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2019-2019 Johannes Bauer
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
from x509sak.tls.DataBuffer import DataBuffer, DataBufferException

class TLSDataBufferTests(BaseTest):
	def test_simple(self):
		db = DataBuffer()
		db += bytes.fromhex("11 22 33")
		db.append(bytes.fromhex("44 55"))
		self.assertEquals(db.get(1), bytes.fromhex("11"))
		self.assertEquals(db.get(3), bytes.fromhex("22 33 44"))
		with self.assertRaises(DataBufferException):
			db.get(3)
		self.assertEquals(db.get(1), bytes.fromhex("55"))
		with self.assertRaises(DataBufferException):
			db.get(1)

	def test_inited(self):
		db = DataBuffer(b"ABC")
		self.assertEquals(db.get(3), bytes.fromhex("41 42 43"))
