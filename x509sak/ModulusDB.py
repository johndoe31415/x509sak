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

import pkgutil
import hashlib
import collections
import gzip
import base64
import json
from x509sak.Exceptions import InvalidInternalDataException

class ModulusDB(object):
	_ModulusMatch = collections.namedtuple("ModulusMatch", [ "hash", "text" ])
	_DB_DATA = None

	def __init__(self):
		if self._DB_DATA is None:
			self._DB_DATA = self._load_db_data()

	def _load_json(self, pkgname, filename):
		data = pkgutil.get_data(pkgname, filename)
		if filename.endswith(".gz"):
			data = gzip.decompress(data)
		return json.loads(data)

	@staticmethod
	def _hash_int(n):
		n_text = "%x" % (n)
		hashval = hashlib.md5(n_text.encode("ascii")).digest()
		return hashval

	@staticmethod
	def _decode_hash(hashstr):
		return base64.b64decode(hashstr + "==")

	def _load_db_data(self):
		db_data = { }
		for filename in [ "rsa.json", "debian.json.gz" ]:
			data = self._load_json("x509sak.data.moduli", filename)
			for entry in data:
				if "text" not in entry:
					raise InvalidInternalDataException("Modulus database requires text for given modulus, not present for entry: %s" % (str(entry)))
				if "n" in entry:
					# Directly hash modulus
					db_data[self._hash_int(entry["n"])] = entry["text"]
				elif "md5" in entry:
					# Decode modulus
					db_data[self._decode_hash(entry["md5"])] = entry["text"]
				else:
					raise InvalidInternalDataException("Modulus database requires either 'n' or 'md5' for given modulus, not present for entry: %s" % (str(entry)))
		return db_data

	def find(self, n):
		n_hash = self._hash_int(n)
		if n_hash in self._DB_DATA:
			return self._ModulusMatch(hash = n_hash, text = self._DB_DATA[n_hash])
