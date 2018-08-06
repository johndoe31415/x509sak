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

import unittest
from x509sak.SecurityEstimator import RSASecurityEstimator

class RSASecurityEstimatorTests(unittest.TestCase):
	def test_rsa_modulus_bitlength(self):
		# NIST SP800-57 Part 1 revision 4 (January 2016)
		expected_rsa_security = {
			1024:	80,
			2048:	112,
			3072:	128,
			7680:	192,
			15360:	256,
		}
		for (modulus_bitlength, expected_security) in expected_rsa_security.items():
			n = 2 ** modulus_bitlength
			analysis = RSASecurityEstimator().analyze_n(n)
			deviation = analysis["bits"] - expected_security
			self.assertLessEqual(abs(deviation), 8)
