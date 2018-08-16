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
from x509sak.RSAPrivateKey import RSAPrivateKey
from x509sak.NumberTheory import NumberTheory
from x509sak.Exceptions import UnfulfilledPrerequisitesException

class ActionGenerateBrokenRSA(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		if (not self._args.force) and os.path.exists(self._args.outfile):
			raise UnfulfilledPrerequisitesException("File/directory %s already exists. Remove it first or use --force." % (self._args.outfile))

		p_bitlen = self._args.bitlen // 2
		q_bitlen = self._args.bitlen - p_bitlen
		if (self._args.close_q) and (p_bitlen != q_bitlen):
			raise UnfulfilledPrerequisitesException("Generating a close-q keypair with a %d modulus does't work, because p would have to be %d bit and q %d bit. Choose an even modulus bitlength." % (self._args.bitlen, p_bitlen, q_bitlen))

		if self._args.q_stepping < 1:
			raise InvalidInputException("q-stepping value must be greater or equal to 1, was %d." % (self._args.q_stepping))

		prime_db = PrimeDB(self._args.prime_db)
		p = prime_db[p_bitlen]
		if not self._args.close_q:
			q = prime_db[q_bitlen]
		else:
			q = p
			while True:
				q += 2 * random.randint(1, self._args.q_stepping)
				if NumberTheory.is_probable_prime(q):
					break
			if self._args.verbose >= 1:
				diff = q - p
				print("q - p = %d (%d bit)" % (diff, diff.bit_length()))

		# Always make p the smaller factor
		if p > q:
			(p, q) = (q, p)
		n = p * q
		e = self._args.public_exponent
		if e == -1:
			e = random.randint(2, n - 1)
		rsa_keypair = RSAPrivateKey.create(p = p, q = q, e = e, swap_e_d = self._args.switch_e_d, valid_only = not self._args.accept_unusable_key)
		rsa_keypair.write_pemfile(self._args.outfile)

		if self._args.verbose >= 1:
			print("Generated %d bit RSA key:" % (rsa_keypair.n.bit_length()))
			print("p = 0x%x" % (rsa_keypair.p))
			print("q = 0x%x" % (rsa_keypair.q))
			print("n = 0x%x" % (rsa_keypair.n))
			print("d = 0x%x" % (rsa_keypair.d))
			print("e = 0x%x" % (rsa_keypair.e))
