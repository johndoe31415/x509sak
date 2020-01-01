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

import enum
from x509sak.tests import BaseTest
from x509sak.tls.Structure import Structure, StructureMember as SM, instantiate_member as IM
from x509sak.tls.DataBuffer import DataBuffer, NotEnoughDataException
from x509sak.Exceptions import ProgrammerErrorException, InvalidInputException

class _FooEnum(enum.IntEnum):
	Foo = 123
	Bar = 234
	Moo = 99

class TLSStructTests(BaseTest):
	_BASE_STRUCT = Structure((
		IM("first", "uint8"),
		IM("second", "uint16"),
		IM("third", "uint24"),
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
		with self.assertRaises(ProgrammerErrorException):
			# Duplicate member name
			structure = Structure((
				IM("data", "uint8"),
				IM("foo", "uint8"),
				IM("data", "uint8"),
			))

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

	def test_opaque_packing(self):
		structure = Structure((SM("data", "opaque8"), ))
		self.assertEquals(structure.pack({ "data": b"foobar" }), b"\x06foobar")

		structure = Structure((SM("data", "opaque16"), ))
		self.assertEquals(structure.pack({ "data": b"foobar999" }), b"\x00\x09foobar999")

		structure = Structure((SM("data", "opaque24"), ))
		self.assertEquals(structure.pack({ "data": b"foobar999123" }), b"\x00\x00\x0cfoobar999123")

	def test_opaque_unpacking(self):
		structure = Structure((SM("data", "opaque8"), ))
		self.assertEquals(structure.unpack(DataBuffer(b"\x06foobar")), { "data": b"foobar" })

		structure = Structure((SM("data", "opaque16"), ))
		self.assertEquals(structure.unpack(DataBuffer(b"\x00\x09foobar123trail")), { "data": b"foobar123" })

		structure = Structure((SM("data", "opaque24"), ))
		self.assertEquals(structure.unpack(DataBuffer(b"\x00\x00\x0cfoobar123321blubb")), { "data": b"foobar123321" })

	def test_array_packing(self):
		structure = Structure((
			IM("int1", "uint8"),
			SM("data", "array[6]"),
			IM("int2", "uint8"),
		))
		self.assertEquals(structure.pack({
			"int1": 0xaa,
			"data": b"foobar",
			"int2": 0xbb,
		}), bytes.fromhex("aa") + b"foobar" + bytes.fromhex("bb"))

		with self.assertRaises(InvalidInputException):
			# No padding defined, must fail
			structure.pack({
				"int1": 0xaa,
				"data": b"foo",
				"int2": 0xbb,
			})

		# With padding byte
		structure = Structure((
			IM("int1", "uint8"),
			SM("data", "array[6, ab]"),
			IM("int2", "uint8"),
		))
		self.assertEquals(structure.pack({
			"int1": 0xaa,
			"data": b"foobar",
			"int2": 0xbb,
		}), bytes.fromhex("aa") + b"foobar" + bytes.fromhex("bb"))
		self.assertEquals(structure.pack({
			"int1": 0xaa,
			"data": b"foo",
			"int2": 0xbb,
		}), bytes.fromhex("aa") + b"foo" + bytes.fromhex("ab ab ab bb"))

	def test_array_unpacking(self):
		structure = Structure((
			IM("int1", "uint8"),
			SM("data", "array[6, ab]"),
			IM("int2", "uint8"),
		))
		self.assertEquals(structure.unpack(DataBuffer(b"\xaafoobar\xbb")), { "data": b"foobar", "int1": 0xaa, "int2": 0xbb })

	def test_integer_enum(self):
		structure = Structure((
			IM("a", "uint8", enum_class = _FooEnum),
			IM("b", "uint16", enum_class = _FooEnum),
			IM("c", "uint32", enum_class = _FooEnum),
			IM("d", "uint32", enum_class = _FooEnum, strict_enum = True),
		))

		orig_values = {
			"a":	_FooEnum.Foo,
			"b":	_FooEnum.Moo,
			"c":	_FooEnum.Bar,
			"d":	1234,
		}
		with self.assertRaises(InvalidInputException):
			data = structure.pack(orig_values)

		orig_values["d"] = _FooEnum.Moo
		data = structure.pack(orig_values)
		db = DataBuffer(data)
		decoded_values = structure.unpack(db)
		self.assertEquals(orig_values, decoded_values)

		orig_values["b"] = 1
		data = structure.pack(orig_values)
		db = DataBuffer(data)
		decoded_values = structure.unpack(db)
		self.assertEquals(orig_values, decoded_values)
