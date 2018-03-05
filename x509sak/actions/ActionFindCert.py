#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2017-2017 Johannes Bauer
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
from x509sak.BaseAction import BaseAction

class ActionFindCert(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)
		self._pool = CertificatePool()
		self._pool.load_sources(self._args.crtsource)
		self._log.debug("Loaded a total of %d unique certificates in trust store.", self._pool.certificate_count)

		for cert in sorted(self._pool):
			if self._cert_matches(cert):
				cert.dump_pem()

	def _cert_matches(self, cert):
		if self._args.hashval is not None:
			if not cert.hashval.hex().startswith(self._args.hashval):
				return False
		return True
