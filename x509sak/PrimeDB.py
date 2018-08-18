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

import random

class PrimeDB(object):
	def __init__(self, directory):
		self._directory = directory
		if not self._directory.endswith("/"):
			self._directory += "/"
		self._primes = { }

	def _get_filename(self, primetype, bitlen):
		assert(primetype in [ "2msb", "3msb" ])
		filename = self._directory + "primes_%s_%d.txt" % (primetype, bitlen)
		return filename

	def _load_primes(self, primetype, bitlen):
		filename = self._get_filename(primetype, bitlen)
		primes = [ ]
		with open(filename) as f:
			for line in f:
				if line.startswith("#"):
					continue
				p = int(line.rstrip("\r\n"), 16)
				primes.append(p)
			random.shuffle(primes)
		self._primes[(primetype, bitlen)] = primes

	def get(self, bitlen, primetype = "2msb"):
		key = (primetype, bitlen)
		if key not in self._primes:
			try:
				self._load_primes(primetype, bitlen)
			except FileNotFoundError:
				pass
		if (key not in self._primes) or (len(self._primes[key]) == 0):
			raise Exception("Primes of type %s with bitlength %d exhausted in database. Generate these primes and save them in a file called \"%s\". Execute: primegen/primegen -b %d -p %s" % (primetype, bitlen, self._get_filename(primetype, bitlen), bitlen, primetype))
		return self._primes[key].pop()
