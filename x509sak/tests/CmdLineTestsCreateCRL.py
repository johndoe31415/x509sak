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
import datetime
from x509sak.tests import BaseTest
from x509sak.WorkDir import WorkDir
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.CertificateRevocationList import CertificateRevocationList

class CmdLineTestsCreateCRL(BaseTest):
	def test_create_crl(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor(self._x509sak + [ "createca", "root_ca" ]).run()
			SubprocessExecutor(self._x509sak + [ "createcrl", "root_ca", "output.crl" ]).run()
			crl = SubprocessExecutor([ "openssl", "crl", "-in", "output.crl", "-text", "-noout" ]).run().stdout
			self.assertIn(b"No Revoked Certificates.", crl)

			der_crl = SubprocessExecutor([ "openssl", "crl", "-in", "output.crl", "-outform", "der" ]).run().stdout
			crl = CertificateRevocationList(der_crl)
			self.assertEqual(crl.crt_count, 0)

	def test_revoke_crt_crl(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor(self._x509sak + [ "createca", "root_ca" ]).run()
			SubprocessExecutor(self._x509sak + [ "createcrt", "-c", "root_ca", "client.key", "client.crt" ]).run()

			SubprocessExecutor(self._x509sak + [ "revokecrt", "root_ca", "client.crt" ]).run()
			SubprocessExecutor(self._x509sak + [ "createcrl", "root_ca", "output.crl" ]).run()
			crl = SubprocessExecutor([ "openssl", "crl", "-in", "output.crl", "-text", "-noout" ]).run().stdout
			self.assertIn(b"Revoked Certificates:", crl)

			der_crl = SubprocessExecutor([ "openssl", "crl", "-in", "output.crl", "-outform", "der" ]).run().stdout
			crl = CertificateRevocationList(der_crl)
			self.assertEqual(crl.crt_count, 1)

	def test_crl_hash(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor(self._x509sak + [ "createca", "root_ca" ]).run()
			SubprocessExecutor(self._x509sak + [ "createcrl", "root_ca", "--hashfnc", "sha256", "output.crl" ]).run()
			crl = SubprocessExecutor([ "openssl", "crl", "-in", "output.crl", "-text", "-noout" ]).run().stdout
			self.assertIn(b"ecdsa-with-SHA256", crl)

			SubprocessExecutor(self._x509sak + [ "createcrl", "root_ca", "--hashfnc", "sha384", "output.crl" ]).run()
			crl = SubprocessExecutor([ "openssl", "crl", "-in", "output.crl", "-text", "-noout" ]).run().stdout
			self.assertIn(b"ecdsa-with-SHA384", crl)

	def test_crl_validity(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor(self._x509sak + [ "createca", "root_ca" ]).run()

			for days in [ 1, 30 ]:
				SubprocessExecutor(self._x509sak + [ "createcrl", "root_ca", "-d", str(days), "output.crl" ]).run()
				now = datetime.datetime.utcnow()
				der_crl = SubprocessExecutor([ "openssl", "crl", "-in", "output.crl", "-outform", "der" ]).run().stdout
				crl = CertificateRevocationList(der_crl)

				self.assertAlmostEqual((crl.this_update - now).total_seconds(), 0, delta = 60)
				self.assertAlmostEqual((crl.next_update - now).total_seconds(), 86400 * days, delta = 60)
