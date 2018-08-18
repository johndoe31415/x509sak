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
from x509sak.PrimeDB import PrimeDB
from x509sak.NumberTheory import NumberTheory

class CmdLineTestsGenBrokenRSA(BaseTest):
	def test_create_rsa_key_no_overwrite(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			with open("broken_rsa.key", "wb"):
				pass
			with self.assertRaises(CmdExecutionFailedException):
				SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa" ], on_failure = "exception-nopause")

	def test_create_rsa_key(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			PrimeDB().add(0xd06bda6bd4031ec96cb8023fd89fc9bb, 0xd578117dc5a445697a7c6e04e09c801f).write()
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd06bda6bd4031ec96cb8023fd89fc9bb)
			self.assertEqual(key.q, 0xd578117dc5a445697a7c6e04e09c801f)
			self.assertEqual(key.e, 0x10001)
			self.assertEqual(key.d, 0x5a360028c4c14b78b770d19ce099e80b0a9b25ab6ae35098ce9e7cc27d08ca19)
			key.check_integrity()

	def test_carmichael_totient(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			PrimeDB().add(0xd06bda6bd4031ec96cb8023fd89fc9bb, 0xd578117dc5a445697a7c6e04e09c801f).write()
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "--carmichael-totient" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd06bda6bd4031ec96cb8023fd89fc9bb)
			self.assertEqual(key.q, 0xd578117dc5a445697a7c6e04e09c801f)
			self.assertEqual(key.e, 0x10001)
			self.assertEqual(key.d, 0x3504164f03e88396ab0cbc8200b8d91a19a60e66e09d11d9e69f27802917833)
			key.check_integrity()

	def test_create_close_q_rsa_key(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			PrimeDB().add(0xd7627ea571293d6bd1dc8d4664bc6ab1).write()
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "--close-q" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd7627ea571293d6bd1dc8d4664bc6ab1)
			self.assertEqual(key.q, key.p + 94)
			key.check_integrity()

	def test_create_inv_e_d_rsa_key(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			PrimeDB().add(0xd06bda6bd4031ec96cb8023fd89fc9bb, 0xd578117dc5a445697a7c6e04e09c801f).write()
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "--switch-e-d", "-e", "0x101" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd06bda6bd4031ec96cb8023fd89fc9bb)
			self.assertEqual(key.q, 0xd578117dc5a445697a7c6e04e09c801f)
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
			PrimeDB().add(0xd06bda6bd4031ec96cb8023fd89fc9bb, 0xd578117dc5a445697a7c6e04e09c801f).write()
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "-e", "-1" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd06bda6bd4031ec96cb8023fd89fc9bb)
			self.assertEqual(key.q, 0xd578117dc5a445697a7c6e04e09c801f)
			self.assertNotEqual(key.e, 0x10001)
			key.check_integrity()

	def test_verbosity(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			PrimeDB().add(0xd7627ea571293d6bd1dc8d4664bc6ab1).write()
			output = SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "-v", "--close-q" ])
			self.assertIn(b"p = 0xd7627ea571293d6bd1dc8d4664bc6ab1", output)

	def test_retry_q(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			PrimeDB().add(0xd7627ea571293d6bd1dc8d4664bc6ab1).write()
			output = SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "-v", "--close-q", "--public-exponent", "3", "-vv" ])
			self.assertIn(b"retrying", output)

	def test_retry_e(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			PrimeDB().add(0xd7627ea571293d6bd1dc8d4664bc6ab1).write()
			# Roughly with p = 0.75 there needs to be at least a retry. The
			# probability that it fails 10 times in a row without there being a
			# bug therefore is roughly one in a million.
			for i in range(10):
				output = SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "-f", "-v", "--close-q", "--public-exponent", "3", "-e", "-1", "-vv" ])
				if b"retrying" in output:
					break
			else:
				self.fail("In 10 tries, never was a retry with a different e value chosen. Highly improbable.")

	def test_gcd_n_phi_n(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			PrimeDB().add(0x1fd22b50d1e28365855635, 0x3af25062dcf148b85084f5).write()
			output = SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "257", "--gcd-n-phi-n", "-v" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 257)
			self.assertEqual(key.p, 0x1fd22b50d1e28365855635)
			self.assertEqual(key.q, 0xea778f672d05715314fd556a2667dca7743e33da973)
			self.assertEqual((key.q - 1) % (2 * key.p), 0)
			self.assertNotEqual(NumberTheory.gcd(key.n, key.phi_n), 1)
			self.assertEqual(key.e, 0x10001)
			self.assertIn(b"gcd(n, phi(n)) = p", output)
			key.check_integrity()

	def test_incompatible_opts(self):
		with tempfile.NamedTemporaryFile(prefix = "config_", suffix = ".cnf") as f:
			output = SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--close-q", "--gcd-n-phi-n", "--outfile", f.name ], success_retcodes = [ 1 ])
			self.assertIn(b"not allowed", output)

	def test_gcd_n_phi_n_try_again_q(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			PrimeDB().add(0x3f25fbdd02563798a3ee15, 0x3c1e53497fe2626fa6d389, 0x3bf7ae07a1892c3881ee69).write()
			output = SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "259", "--gcd-n-phi-n", "-vv" ], success_retcodes = [ 1 ])
			self.assertIn(b"exhausted", output)
