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
import random

class PrimeDB(object):
	def __init__(self, directory = "."):
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

	def add_prime(self, prime):
		if prime.bit_length() < 8:
			raise NotImplementedError("We're not interesting in tiny primes.")
		msb_2_set = ((prime >> (prime.bit_length() - 2)) & 1) == 1
		msb_3_set = ((prime >> (prime.bit_length() - 3)) & 1) == 1
		if msb_2_set and msb_3_set:
			prime_type = "3msb"
		elif msb_2_set:
			prime_type = "2msb"
		else:
			prime_type = "1msb"
		key = (prime_type, prime.bit_length())
		if key not in self._primes:
			self._primes[key] = [ ]
		self._primes[key].append(prime)
		return self

	def add(self, *primes):
		for prime in primes:
			self.add_prime(prime)
		return self

	def write(self, overwrite_files = False):
		for ((primetype, bitlen), primes) in self._primes.items():
			filename = self._get_filename(primetype, bitlen)
			if (len(primes) > 0) and (overwrite_files or (not os.path.exists(filename))):
				with open(filename, "w") as f:
					for prime in primes:
						print("%x" % (prime), file = f)

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
