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
from x509sak.BaseAction import BaseAction
from x509sak.PrimeDB import PrimeDB
from x509sak.RSAPrivateKey import RSAPrivateKey

class ActionGenerateBrokenRSA(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		prime_db = PrimeDB(self._args.prime_db)
		(p, q) = (prime_db[self._args.bitlen], prime_db[self._args.bitlen])
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
