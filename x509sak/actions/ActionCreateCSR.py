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
from x509sak.OpenSSLTools import OpenSSLTools
from x509sak.CAManager import CAManager
from x509sak.BaseAction import BaseAction

class ActionCreateCSR(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		if os.path.exists(self._args.out_filename) and (not self._args.force):
			raise Exception("File/directory %s already exists. Remove it first or use --force." % (self._args.out_filename))
		if os.path.exists(self._args.key_filename) and (self._args.keytype is not None) and (not self._args.force):
			raise Exception("File/directory %s already exists. Remove it first or use --force." % (self._args.key_filename))

		if self._args.keytype is not None:
			OpenSSLTools.create_private_key(self._args.key_filename, self._args.keytype)

		options = { option.key: option.value for option in self._args.extension }
		if self._args.create_crt is None:
			# Create CSR
			OpenSSLTools.create_csr(self._args.key_filename, self._args.out_filename, self._args.subject_dn, options = options, subject_alternative_dns_names = self._args.san_dns, subject_alternative_ip_addresses = self._args.san_ip)
		else:
			# Create certificate
			with tempfile.NamedTemporaryFile(prefix = "csr_", suffix = ".pem") as csr:
				OpenSSLTools.create_csr(self._args.key_filename, csr.name, subject_dn = "/CN=Discard")
				ca = CAManager(self._args.create_crt)
				ca.sign_csr(csr.name, self._args.out_filename, subject_dn = self._args.subject_dn, options = options, validity_days = self._args.validity_days, extension_template = self._args.template, subject_alternative_dns_names = self._args.san_dns, subject_alternative_ip_addresses = self._args.san_ip, signing_hash = self._args.hashfnc)
