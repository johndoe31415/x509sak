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

import os
import unittest
import pkgutil
import gzip
from x509sak import X509Certificate

class BaseTest(unittest.TestCase):
	def __init__(self, *args, **kwargs):
		unittest.TestCase.__init__(self, *args, **kwargs)
		if "X509SAK_COVERAGE" not in os.environ:
			self._x509sak = [ os.path.realpath("x509sak.py") ]
		else:
			self._x509sak = [ "coverage", "run", "--append", "--omit", "/usr/*", os.path.realpath("x509sak.py") ]

	@staticmethod
	def _load_data(filename):
		data = pkgutil.get_data("x509sak.tests.data", filename)
		if filename.endswith(".gz"):
			data = gzip.decompress(data)
		return data

	def _load_text(self, filename):
		return self._load_data(filename).decode("ascii")

	def _load_crt(self, crtname):
		x509_text = self._load_text(crtname)
		cert = X509Certificate.from_pem_data(x509_text)[0]
		return cert

	def _load_pubkey(self, crtname):
		return self._load_crt(crtname).pubkey
