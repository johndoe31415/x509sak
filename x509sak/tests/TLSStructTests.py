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
from x509sak.Exceptions import ProgrammerErrorException, InvalidInputException

class TLSStructTests(BaseTest):
	def test_basic_packing(self):
		structure = TLSStruct((
			("first", "u8"),
			("second", "u16"),
			("third", "u24"),
		), name = "TestStructure")
		self.assertEquals(structure.pack({
			"first":	0xaa,
			"second":	0xabcd,
			"third":	0x112233,
		}), bytes.fromhex("aa ab cd 11 22 33"))

	def test_packing_errors(self):
		structure = TLSStruct((
			("first", "u8"),
			("second", "u16"),
			("third", "u24"),
		), name = "TestStructure")
		with self.assertRaises(ProgrammerErrorException):
			# Missing member
			structure.pack({
				"first":	0xaa,
				"third":	0x112233,
			})
		with self.assertRaises(InvalidInputException):
			# Out of bounds value
			structure.pack({
				"first":	256,
				"second":	0xabcd,
				"third":	0x112233,
			})
