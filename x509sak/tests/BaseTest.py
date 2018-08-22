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
import tempfile
from x509sak import X509Certificate
from x509sak.PublicKey import PublicKey

class ResourceFileLoader(object):
	def __init__(self, *resource_names):
		self._data = [ self.load_data(resource_name) for resource_name in resource_names ]
		self._tempfiles = None

	@classmethod
	def load_data(cls, filename, auto_decompress = True):
		data = pkgutil.get_data("x509sak.tests.data", filename)
		if auto_decompress and filename.endswith(".gz"):
			data = gzip.decompress(data)
		return data

	def __enter__(self):
		self._tempfiles = [ tempfile.NamedTemporaryFile(mode = "wb") for i in range(len(self._data)) ]
		for (data, tmpfile) in zip(self._data, self._tempfiles):
			tmpfile.write(data)
			tmpfile.flush()
		filenames = [ tmpfile.name for tmpfile in self._tempfiles ]
		if len(filenames) == 1:
			return filenames[0]
		else:
			return filenames

	def __exit__(self, *args):
		for tmpfile in self._tempfiles:
			tmpfile.close()

class BaseTest(unittest.TestCase):
	def __init__(self, *args, **kwargs):
		unittest.TestCase.__init__(self, *args, **kwargs)
		if "X509SAK_COVERAGE" not in os.environ:
			self._x509sak = [ os.path.realpath("x509sak.py") ]
		else:
			self._x509sak = [ "coverage", "run", "--append", "--omit", "/usr/*", os.path.realpath("x509sak.py") ]

	@staticmethod
	def _load_data(filename):
		return ResourceFileLoader.load_data(filename, auto_decompress = True)

	def _load_text(self, filename):
		return self._load_data(filename).decode("ascii")

	def _load_crt(self, crtname):
		x509_text = self._load_text(crtname)
		cert = X509Certificate.from_pem_data(x509_text)[0]
		return cert

	def _load_pubkey(self, crtname):
		return self._load_crt(crtname).pubkey

	def _load_raw_pubkey(self, keyname):
		return PublicKey.from_pem_data(self._load_data(keyname))[0]
