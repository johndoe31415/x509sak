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
from x509sak.BaseAction import BaseAction
from x509sak.PrimeDB import PrimeDB
from x509sak.NumberTheory import NumberTheory
from x509sak.PublicKey import PublicKey
from x509sak.AlgorithmDB import Cryptosystems
from x509sak.DSAParameters import DSAParameters

class ActionGenerateBrokenDSA(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		if (not self._args.force) and os.path.exists(self._args.outfile):
			raise UnfulfilledPrerequisitesException("File/directory %s already exists. Remove it first or use --force." % (self._args.outfile))

		self._prime_db = PrimeDB(self._args.prime_db, generator_program = self._args.generator)
		q = self._prime_db.get(args.N_bits)
		if self._args.verbose >= 1:
			print("Chosen q = 0x%x" % (q))

		bit_diff = args.L_bits - q.bit_length()
		while True:
			r = NumberTheory.randint_bits(bit_diff, two_msb_set = True)
			p = (r * q) + 1
			if NumberTheory.is_probable_prime(p):
				break
		if self._args.verbose >= 1:
			print("Chosen p = 0x%x" % (p))

		assert(q.bit_length() == args.N_bits)
		assert(p.bit_length() == args.L_bits)
		assert((p - 1) % q == 0)

		# Non-verifiable method of generating g, see A.2.1 of FIPS 186-4, pg. 41
		e = (p - 1) // q
		while True:
			h = random.randint(2, p - 2)
			g = pow(h, e, p)
			if g == 1:
				continue
			break

		if self._args.verbose >= 1:
			print("Chosen g = 0x%x" % (g))

		dsa_parameters = DSAParameters.create(p = p, q = q, g = g)
		dsa_parameters.write_pemfile(self._args.outfile)
