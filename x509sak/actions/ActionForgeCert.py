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

import os
import tempfile
import subprocess
import shutil
from x509sak.BaseAction import BaseAction
from x509sak.OpenSSLTools import OpenSSLTools
from x509sak import X509Certificate

class ActionForgeCert(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		certs = X509Certificate.read_pemfile(self._args.crt_filename)
		self._log.debug("Read %d certificates to forge.", len(certs))
		for cert in certs:
			self._forge_cert(cert)

	def _forge_cert(self, cert):
		print(cert)
		print(cert.signed_payload)
		print(cert.signer_cryptosystem)
