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

import sys
from x509sak import CertificatePool, X509Certificate
from x509sak.BaseAction import BaseAction

class ActionBuildChain(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)
		self._pool = CertificatePool()
		self._load_truststore()
		if self._args.inform == "pem":
			certs = X509Certificate.read_pemfile(self._args.crtfile)
			if not self._args.dont_trust_crtfile:
				self._pool.add_certificates(certs)
			cert = certs[0]
		elif self._args.inform == "der":
			cert = X509Certificate.read_derfile(self._args.crtfile)
		else:
			raise Exception(NotImplemented)
		chain = self._pool.find_chain(cert)
		if (chain.root is None) and (not self._args.allow_partial_chain):
			print("Could not build full chain for certificate %s and partial chain matches are disallowed." % (self._args.crtfile), file = sys.stderr)
			sys.exit(1)

		if self._args.outform == "rootonly":
			if chain.root is None:
				print("Root certificate output requested, but none found.", file = sys.stderr)
				sys.exit(1)
			certs = [ chain.root ]
		elif self._args.outform == "intermediates":
			certs = list(chain.chain)
		elif self._args.outform in [ "fullchain", "multifile" ]:
			certs = list(chain.full_chain)
		elif self._args.outform == "all-except-root":
			certs = list(chain.full_chain)
			if chain.root is not None:
				certs = certs[:-1]
		else:
			raise Exception(NotImplemented)

		if not self._args.order_leaf_to_root:
			certs = certs[::-1]

		for (cid, cert) in enumerate(certs):
			self._log.debug("Cert %d: %s", cid, cert)

		if self._args.outform == "multifile":
			for (cid, cert) in enumerate(certs):
				filename = self._args.outfile % (cid)
				with open(filename, "w") as f:
					print(cert.to_pem_data(), file = f)
		else:
			if self._args.outfile is not None:
				with open(self._args.outfile, "w") as f:
					self._print_certs(f, certs)
			else:
				self._print_certs(sys.stdout, certs)

	@staticmethod
	def _print_certs(f, certs):
		for cert in certs:
			print(cert.to_pem_data(), file = f)

	def _load_truststore(self):
		self._pool.load_sources(self._args.ca_source)
		self._log.debug("Loaded a total of %d unique certificates in trust store.", self._pool.certificate_count)
