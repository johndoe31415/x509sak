#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2020-2020 Johannes Bauer
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
from x509sak.StringParser import StringParser, StringParseException

class StringParserTests(BaseTest):
	def test_unescaped(self):
		self.assertEqual(list(StringParser(escape_chars = ";").parse("foo")), [ (0, "f"), (0, "o"), (0, "o") ])

	def test_escaped(self):
		self.assertEqual(list(StringParser(escape_chars = ";").parse(r"foo\;bar")), [ (0, "f"), (0, "o"), (0, "o"), (0, ";"), (0, "b"), (0, "a"), (0, "r")])

	def test_control(self):
		self.assertEqual(list(StringParser(escape_chars = ";").parse(r"foo;bar")), [ (0, "f"), (0, "o"), (0, "o"), (1, ";"), (0, "b"), (0, "a"), (0, "r")])

	def test_end_of_string(self):
		with self.assertRaises(StringParseException):
			list(StringParser(escape_chars = ";").parse("foo;bar\\"))

	def test_no_escape_expected(self):
		with self.assertRaises(StringParseException):
			list(StringParser(escape_chars = ";").parse(r"foo\bar"))

	def test_split_basic(self):
		sstr = StringParser(escape_chars = ";").split("foo;bar", control_char = ";")
		self.assertEqual(len(sstr), 2)
		self.assertEqual(sstr[0], [ (0, "f"), (0, "o"), (0, "o") ])
		self.assertEqual(sstr[1], [ (0, "b"), (0, "a"), (0, "r") ])

	def test_split_meta(self):
		sstr = StringParser(escape_chars = ";+").split("f+o;bar", control_char = ";")
		self.assertEqual(len(sstr), 2)
		self.assertEqual(sstr[0], [ (0, "f"), (1, "+"), (0, "o") ])
		self.assertEqual(sstr[1], [ (0, "b"), (0, "a"), (0, "r") ])

	def test_split_escaped_meta(self):
		sstr = StringParser(escape_chars = ";+").split("f\\+o;bar", control_char = ";")
		self.assertEqual(len(sstr), 2)
		self.assertEqual(sstr[0], [ (0, "f"), (0, "+"), (0, "o") ])
		self.assertEqual(sstr[1], [ (0, "b"), (0, "a"), (0, "r") ])

	def test_split_recombine_meta(self):
		sp = StringParser(escape_chars = ";+")
		sstr = sp.split("f+o;bar", control_char = ";")
		self.assertEqual(len(sstr), 2)
		self.assertEqual(sp.escape(sstr[0]), "f+o")
		self.assertEqual(sp.escape(sstr[1]), "bar")

	def test_split_recombine_escaped_meta(self):
		sp = StringParser(escape_chars = ";+")
		sstr = sp.split("f\\+o;bar", control_char = ";")
		self.assertEqual(len(sstr), 2)
		self.assertEqual(sp.escape(sstr[0]), "f\\+o")
		self.assertEqual(sp.escape(sstr[1]), "bar")

	def test_split_recombine_meta_reassemble(self):
		sp = StringParser(escape_chars = ";+")
		sstr = sp.split("f+o;bar", control_char = ";", reassemble = True)
		self.assertEqual(len(sstr), 2)
		self.assertEqual(sstr[0], "f+o")
		self.assertEqual(sstr[1], "bar")

	def test_split_recombine_escaped_meta_reassemble(self):
		sp = StringParser(escape_chars = ";+")
		sstr = sp.split("f\\+o;bar", control_char = ";", reassemble = True)
		self.assertEqual(len(sstr), 2)
		self.assertEqual(sstr[0], "f\\+o")
		self.assertEqual(sstr[1], "bar")
