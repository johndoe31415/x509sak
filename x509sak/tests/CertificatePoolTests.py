#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2021 Johannes Bauer
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

from x509sak import CertificatePool
from x509sak.tests import BaseTest

class CertificatePoolTests(BaseTest):
	def test_empty_pool(self):
		pool = CertificatePool()
		server_cert = self._load_crt("ok/johannes-bauer.com")
		intermediate_cert = self._load_crt("ok/johannes-bauer-intermediate")
		root_cert = self._load_crt("ok/johannes-bauer-root")

		chain = pool.find_chain(server_cert)
		self.assertEqual(chain.root, None)
		self.assertEqual(chain.chain, tuple())
		self.assertEqual(chain.leaf, server_cert)
		self.assertEqual(chain.full_chain, (server_cert, ))

		chain = pool.find_chain(intermediate_cert)
		self.assertEqual(chain.root, None)
		self.assertEqual(chain.chain, tuple())
		self.assertEqual(chain.leaf, intermediate_cert)
		self.assertEqual(chain.full_chain, (intermediate_cert, ))

		chain = pool.find_chain(root_cert)
		self.assertEqual(chain.root, root_cert)
		self.assertEqual(chain.chain, tuple())
		self.assertEqual(chain.leaf, root_cert)
		self.assertEqual(chain.full_chain, (root_cert, ))

	def test_fullchain(self):
		pool = CertificatePool()
		server_cert = self._load_crt("ok/johannes-bauer.com")
		intermediate_cert = self._load_crt("ok/johannes-bauer-intermediate")
		root_cert = self._load_crt("ok/johannes-bauer-root")
		pool.add_certificate(server_cert)
		pool.add_certificate(intermediate_cert)
		pool.add_certificate(root_cert)

		self.assertEqual(list(pool.find_issuers(server_cert))[0], intermediate_cert)
		self.assertEqual(list(pool.find_issuers(intermediate_cert))[0], root_cert)
		self.assertEqual(list(pool.find_issuers(root_cert))[0], root_cert)

		chain = pool.find_chain(server_cert)
		self.assertEqual(chain.root, root_cert)
		self.assertEqual(chain.chain, (intermediate_cert, ))
		self.assertEqual(chain.leaf, server_cert)
		self.assertEqual(chain.full_chain, (server_cert, intermediate_cert, root_cert))

	def test_partial_chain(self):
		pool = CertificatePool()
		server_cert = self._load_crt("ok/johannes-bauer.com")
		intermediate_cert = self._load_crt("ok/johannes-bauer-intermediate")
		pool.add_certificate(server_cert)
		pool.add_certificate(intermediate_cert)

		chain = pool.find_chain(server_cert)
		self.assertEqual(chain.root, None)
		self.assertEqual(chain.chain, (intermediate_cert, ))
		self.assertEqual(chain.leaf, server_cert)
		self.assertEqual(chain.full_chain, (server_cert, intermediate_cert))
