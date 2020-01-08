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
from x509sak.X509Certificate import X509Certificate
from x509sak.OID import OIDDB

class CmdLineTestsForgeCert(BaseTest):
	def _assertCrtsSimilar(self, original, forgery):
		self.assertEqual(original.subject, forgery.subject)
		self.assertEqual(original.issuer, forgery.issuer)
		self.assertEqual(original.valid_not_before, forgery.valid_not_before)
		self.assertEqual(original.valid_not_after, forgery.valid_not_after)
		self.assertEqual(original.signature_alg_oid, forgery.signature_alg_oid)
		self.assertEqual(original.pubkey.keyspec, forgery.pubkey.keyspec)
		self.assertNotEqual(original.pubkey, forgery.pubkey)

	def test_forge_root(self):
		root_crt = self._load_crt("ok/johannes-bauer-root")
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			root_crt.write_pemfile("root.crt")
			self._run_x509sak([ "forgecert", "root.crt" ])

			forged_root_crt = X509Certificate.read_pemfile("forged_00.crt")[0]
			self._assertCrtsSimilar(root_crt, forged_root_crt)
			orig_ski = root_crt.extensions.get_first(OIDDB.X509Extensions.inverse("SubjectKeyIdentifier"))
			forged_ski = forged_root_crt.extensions.get_first(OIDDB.X509Extensions.inverse("SubjectKeyIdentifier"))
			self.assertEqual(orig_ski, forged_ski)

	def test_forge_root_new_ski(self):
		root_crt = self._load_crt("ok/johannes-bauer-root")
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			root_crt.write_pemfile("root.crt")
			self._run_x509sak([ "forgecert", "--recalculate-keyids", "root.crt" ])

			forged_root_crt = X509Certificate.read_pemfile("forged_00.crt")[0]
			self._assertCrtsSimilar(root_crt, forged_root_crt)
			orig_ski = root_crt.extensions.get_first(OIDDB.X509Extensions.inverse("SubjectKeyIdentifier"))
			forged_ski = forged_root_crt.extensions.get_first(OIDDB.X509Extensions.inverse("SubjectKeyIdentifier"))
			self.assertNotEqual(orig_ski, forged_ski)

	def test_forge_chain(self):
		root_crt = self._load_crt("ok/johannes-bauer-root")
		intermediate_crt = self._load_crt("ok/johannes-bauer-intermediate")
		server_crt = self._load_crt("ok/johannes-bauer.com")
		orig_crts = [ root_crt, intermediate_crt, server_crt ]

		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			with open("chain.crt", "w") as f:
				for orig_crt in orig_crts:
					print(orig_crt.to_pem_data(), file = f)
			self._run_x509sak([ "forgecert", "chain.crt" ])

			for (num, orig_crt) in enumerate(orig_crts):
				forged_crt = X509Certificate.read_pemfile("forged_%02d.crt" % (num))[0]
				self._assertCrtsSimilar(orig_crt, forged_crt)
