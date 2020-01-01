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
from x509sak.tls.TLSStruct import TLSStruct
from x509sak.tls.DataBuffer import DataBuffer, NotEnoughDataException
from x509sak.Exceptions import ProgrammerErrorException, InvalidInputException

class TLSStructTests(BaseTest):
	_BASE_STRUCT = TLSStruct((
		("first", "u8"),
		("second", "u16"),
		("third", "u24"),
	), name = "TestStructure")

	def test_basic_packing(self):
		self.assertEquals(self._BASE_STRUCT.pack({
			"first":	0xaa,
			"second":	0xabcd,
			"third":	0x112233,
		}), bytes.fromhex("aa ab cd 11 22 33"))

	def test_packing_errors(self):
		with self.assertRaises(ProgrammerErrorException):
			# Missing member
			self._BASE_STRUCT.pack({
				"first":	0xaa,
				"third":	0x112233,
			})
		with self.assertRaises(InvalidInputException):
			# Out of bounds value
			self._BASE_STRUCT.pack({
				"first":	256,
				"second":	0xabcd,
				"third":	0x112233,
			})

	def test_basic_unpacking(self):
		self.assertEquals(self._BASE_STRUCT.unpack(DataBuffer.fromhex("aa ab cd 11 22 33")), {
			"first":	0xaa,
			"second":	0xabcd,
			"third":	0x112233,
		})

	def test_position_advanced(self):
		db = DataBuffer.fromhex("aa ab cd 11 22 33")
		self._BASE_STRUCT.unpack(db)
		self.assertEquals(db.offset, 6)

	def test_position_unchanged(self):
		# Either unpacking works and offset is advanced or it remains the same
		# after unpacking, no halfways things.
		db = DataBuffer.fromhex("00 aa ab cd 11 22")
		db.offset = 1
		with self.assertRaises(NotEnoughDataException):
			self._BASE_STRUCT.unpack(db)
		self.assertEquals(db.offset, 1)

#	def test_opaque_packing(self):
#		structure = TLSStruct((("data", "opaque8"), ))
#		self.assertEquals(structure.pack({ "data": b"foobar" }), b"\x06foobar")

	def test_opaque_unpacking(self):
		structure = TLSStruct((("data", "opaque8"), ))
		self.assertEquals(structure.unpack(DataBuffer(b"\x06foobar")), { "data": b"foobar" })

		structure = TLSStruct((("data", "opaque16"), ))
		self.assertEquals(structure.unpack(DataBuffer(b"\x00\x09foobar123trail")), { "data": b"foobar123" })

		structure = TLSStruct((("data", "opaque24"), ))
		self.assertEquals(structure.unpack(DataBuffer(b"\x00\x00\x0cfoobar123321blubb")), { "data": b"foobar123321" })
