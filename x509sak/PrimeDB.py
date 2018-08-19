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
import logging
from x509sak.SubprocessExecutor import SubprocessExecutor

_log = logging.getLogger("x509sak.PrimeDB")

class PrimeDB(object):
	def __init__(self, directory = ".", generator_program = None):
		self._directory = directory
		self._generator = generator_program
		if not self._directory.endswith("/"):
			self._directory += "/"
		self._primes = { }

	def _get_filename(self, bitlen, primetype):
		assert(primetype in [ "2msb", "3msb" ])
		filename = self._directory + "primes_%s_%d.txt" % (primetype, bitlen)
		return filename

	def _load_primes(self, bitlen, primetype, offset = 0):
		filename = self._get_filename(bitlen, primetype)
		primes = [ ]
		with open(filename) as f:
			f.seek(offset)
			for line in f:
				if line.startswith("#"):
					continue
				p = int(line.rstrip("\r\n"), 16)
				primes.append(p)
			random.shuffle(primes)
		self._primes[(bitlen, primetype)] = primes

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
		key = (prime.bit_length(), prime_type)
		if key not in self._primes:
			self._primes[key] = [ ]
		self._primes[key].append(prime)
		return self

	def add(self, *primes):
		for prime in primes:
			self.add_prime(prime)
		return self

	def write(self, overwrite_files = False):
		for ((bitlen, primetype), primes) in self._primes.items():
			filename = self._get_filename(bitlen, primetype)
			if (len(primes) > 0) and (overwrite_files or (not os.path.exists(filename))):
				with open(filename, "w") as f:
					for prime in primes:
						print("%x" % (prime), file = f)

	def _generate_primes(self, bitlen, primetype):
		filename = self._get_filename(bitlen, primetype)
		if os.path.isfile(filename):
			offset = os.stat(filename).st_size
		else:
			offset = 0
		if bitlen <= 1024:
			count = 100
		elif bitlen <= 2048:
			count = 10
		elif bitlen <= 8192:
			count = 5
		else:
			count = 1
		_log.debug("Generating %d %d bit %s prime(s) using %s; current DB %s offset is %d", count, bitlen, primetype, self._generator, filename, offset)
		cmd = [ self._generator, "--prime-type", primetype, "--bit-length", str(bitlen), "--num-primes", str(count) ]
		SubprocessExecutor(cmd).run()

		# finally re-read database from previous offset
		self._load_primes(bitlen, primetype, offset)

	def get(self, bitlen, primetype = "2msb"):
		key = (bitlen, primetype)
		if key not in self._primes:
			try:
				self._load_primes(bitlen, primetype)
			except FileNotFoundError:
				pass
		if (key not in self._primes) or (len(self._primes[key]) == 0):
			# Prime DB is exhausted.
			if self._generator is not None:
				# Generate new primes on-the-fly and try again
				self._generate_primes(bitlen, primetype)
				return self.get(bitlen = bitlen, primetype = primetype)
			else:
				raise Exception("Primes of type %s with bitlength %d exhausted in database. Generate these primes and save them in a file called \"%s\". Execute: primegen/primegen -b %d -p %s" % (primetype, bitlen, self._get_filename(bitlen, primetype), bitlen, primetype))
		return self._primes[key].pop()
