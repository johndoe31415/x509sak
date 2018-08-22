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

import io
from x509sak.tests import BaseTest
from x509sak.HexDump import HexDump

class HexDumpTests(BaseTest):
	def test_hexdump(self):
		hexstr = HexDump().as_str("fööbar".encode("utf-8"))
		self.assertIn("66 c3 b6 c3", hexstr)
		self.assertIn("f....bar", hexstr)

	def test_hexdump_fp(self):
		f = io.StringIO()
		HexDump().dump("barfö".encode("utf-8"), fp = f)
		hexstr = f.getvalue()
		self.assertIn("62 61 72 66  c3 b6", hexstr)
		self.assertIn("barf..", hexstr)
