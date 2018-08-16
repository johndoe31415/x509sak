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
	def test_create_rsa_key_no_overwrite(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			with open("broken_rsa.key", "wb") as f:
				pass
			with self.assertRaises(CmdExecutionFailedException):
				SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa" ])

	def test_create_rsa_key(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			with open("primes_128.txt", "w") as f:
				print("d7627ea571293d6bd1dc8d4664bc6ab1", file = f)
				print("ee56535d1f91101227f00411ad847dc5", file = f)
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd7627ea571293d6bd1dc8d4664bc6ab1)
			self.assertEqual(key.q, 0xee56535d1f91101227f00411ad847dc5)
			self.assertEqual(key.e, 0x10001)
			key.check_integrity()

	def test_create_close_q_rsa_key(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			with open("primes_128.txt", "w") as f:
				print("d7627ea571293d6bd1dc8d4664bc6ab1", file = f)
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "--close-q" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd7627ea571293d6bd1dc8d4664bc6ab1)
			self.assertEqual(key.q, key.p + 94)
			key.check_integrity()

	def test_create_inv_e_d_rsa_key(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			with open("primes_128.txt", "w") as f:
				print("d7627ea571293d6bd1dc8d4664bc6ab1", file = f)
				print("ee56535d1f91101227f00411ad847dc5", file = f)
			SubprocessExecutor.run(self._x509sak + [ "genbrokenrsa", "--bitlen", "256", "--switch-e-d", "-e", "0x101" ])
			key = RSAPrivateKey.read_pemfile("broken_rsa.key")[0]
			self.assertEqual(key.n.bit_length(), 256)
			self.assertEqual(key.p, 0xd7627ea571293d6bd1dc8d4664bc6ab1)
			self.assertEqual(key.q, 0xee56535d1f91101227f00411ad847dc5)
			self.assertEqual(key.d, 0x101)
			key.check_integrity()
