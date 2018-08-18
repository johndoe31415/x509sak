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

import tempfile
from x509sak.tests import BaseTest
from x509sak.WorkDir import WorkDir
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.Exceptions import CmdExecutionFailedException
from x509sak.RSAPrivateKey import RSAPrivateKey

class CmdLineTestsGenBrokenRSA(BaseTest):
	@staticmethod
	def _setup_prime_db(prime_cnt = 2):
		assert(prime_cnt in [ 1, 2 ])
		with open("primes_2msb_128.txt", "w") as f:
			print("d7627ea571293d6bd1dc8d4664bc6ab1", file = f)
			if prime_cnt >= 2:
				print("ee56535d1f91101227f00411ad847dc5", file = f)

	def test_create_rsa_key_no_overwrite(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			with open("broken_rsa.key", "wb") as f:
				pass
			with self.assertRaises(CmdExecutionFailedException):
				SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa" ], on_failure = "exception-nopause")

	def test_create_rsa_key(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			self._setup_prime_db()
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd7627ea571293d6bd1dc8d4664bc6ab1)
			self.assertEqual(key.q, 0xee56535d1f91101227f00411ad847dc5)
			self.assertEqual(key.e, 0x10001)
			self.assertEqual(key.d, 0xac3352a186e958edf0986c5c1a5e52765bd227f393811531b006e533d66b3201)
			key.check_integrity()

	def test_carmichael_totient(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			self._setup_prime_db()
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "--carmichael-totient" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd7627ea571293d6bd1dc8d4664bc6ab1)
			self.assertEqual(key.q, 0xee56535d1f91101227f00411ad847dc5)
			self.assertEqual(key.e, 0x10001)
			self.assertEqual(key.d, 0x15ceac67cc861d2286ca1af592252ee97b8f5504bb2bcae5407b6a300817faf1)
			key.check_integrity()

	def test_create_close_q_rsa_key(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			self._setup_prime_db(1)
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "--close-q" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd7627ea571293d6bd1dc8d4664bc6ab1)
			self.assertEqual(key.q, key.p + 94)
			key.check_integrity()

	def test_create_inv_e_d_rsa_key(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			self._setup_prime_db()
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "--switch-e-d", "-e", "0x101" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd7627ea571293d6bd1dc8d4664bc6ab1)
			self.assertEqual(key.q, 0xee56535d1f91101227f00411ad847dc5)
			self.assertEqual(key.d, 0x101)
			key.check_integrity()

	def test_invalid_close_q(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			self.assertIn(b"even modulus bitlength", SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "129", "--close-q" ], success_retcodes = [ 1 ]))

	def test_invalid_stepping(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			self.assertIn(b"greater or equal", SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "128", "--q-stepping", "0" ], success_retcodes = [ 1 ]))

	def test_automatic_e(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			self._setup_prime_db()
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "-e", "-1" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd7627ea571293d6bd1dc8d4664bc6ab1)
			self.assertEqual(key.q, 0xee56535d1f91101227f00411ad847dc5)
			self.assertNotEqual(key.e, 0x10001)
			key.check_integrity()

	def test_verbosity(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			self._setup_prime_db(1)
			output = SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "-v", "--close-q" ])
			self.assertIn(b"p = 0xd7627ea571293d6bd1dc8d4664bc6ab1", output)

	def test_retry_q(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			self._setup_prime_db(1)
			output = SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "-v", "--close-q", "--public-exponent", "3", "-vv" ])
			self.assertIn(b"retrying", output)

	def test_retry_e(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			self._setup_prime_db(1)
			# Roughly with p = 0.75 there needs to be at least a retry. The
			# probability that it fails 10 times in a row without there being a
			# bug therefore is roughly one in a million.
			for i in range(10):
				output = SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "-f", "-v", "--close-q", "--public-exponent", "3", "-e", "-1", "-vv" ])
				if b"retrying" in output:
					break
			else:
				self.fail("In 10 tries, never was a retry with a different e value chosen. Highly improbable.")
