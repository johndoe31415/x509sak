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
from x509sak.SubprocessExecutor import SubprocessExecutor

class SubprocessExecutorTests(BaseTest):
	def test_basic_stdout(self):
		result = SubprocessExecutor([ "echo", "foobar" ]).run()
		self.assertEqual(result.stdout, b"foobar\n")
		self.assertEqual(result.stderr, b"")
		self.assertEqual(result.stdout_text, "foobar\n")
		self.assertEqual(result.stderr_text, "")
		self.assertEqual(result.stdouterr, b"foobar\n")
		self.assertEqual(result.stdouterr_text, "foobar\n")

	def test_basic_stdin(self):
		result = SubprocessExecutor([ "cat" ], stdin = b"mookoo").run()
		self.assertEqual(result.stdout, b"mookoo")
		self.assertEqual(result.stderr, b"")
		self.assertEqual(result.stdout_text, "mookoo")
		self.assertEqual(result.stderr_text, "")
		self.assertEqual(result.stdouterr, b"mookoo")
		self.assertEqual(result.stdouterr_text, "mookoo")

	def test_basic_stderr(self):
		result = SubprocessExecutor([ "cat", "/fdisohjfdiso" ], success_return_codes = [ 1 ]).run()
		self.assertEqual(result.stdout, b"")
		self.assertIn(b"such file or directory", result.stderr)
		self.assertEqual(result.stdout_text, "")
		self.assertIn("such file or directory", result.stderr_text)
		self.assertIn(b"such file or directory", result.stdouterr)
		self.assertIn("such file or directory", result.stdouterr_text)
