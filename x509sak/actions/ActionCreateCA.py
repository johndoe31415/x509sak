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
import shutil
from x509sak import CAManager
from x509sak.BaseAction import BaseAction
from x509sak.PrivateKeyStorage import PrivateKeyStorage, PrivateKeyStorageForm
from x509sak.KeySpecification import KeySpecification
from x509sak.CmdLineArgs import KeySpecArgument
from x509sak.OpenSSLTools import OpenSSLTools

class ActionCreateCA(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)
		if self._args.force:
			try:
				os.unlink(self._args.capath)
			except (IsADirectoryError, FileNotFoundError):
				pass
			try:
				shutil.rmtree(self._args.capath)
			except FileNotFoundError:
				pass

		if os.path.exists(self._args.capath):
			raise Exception("File/directory %s already exists. Remove it first or use --force." % (self._args.capath))

		try:
			os.makedirs(self._args.capath)
		except FileExistsError:
			pass
		os.chmod(self._args.capath, 0o700)


		camgr = CAManager(self._args.capath)

		if (self._args.gen_keyspec is not None) or ((self._args.gen_keyspec is None) and (self._args.hardware_key is None)):
			# We need to generate a key.
			if self._args.gen_keyspec is not None:
				keyspec = self._args.gen_keyspec
			else:
				# Cannot default to this in argparse because it's part of a
				# mutually exclusive group with hardware_key
				keyspec = KeySpecification.from_keyspec_argument(KeySpecArgument("ecc:secp384r1"))
			private_key_storage = PrivateKeyStorage(PrivateKeyStorageForm.PEM_FILE, filename = "CA.key", search_path = camgr.capath)
			OpenSSLTools.create_private_key(private_key_storage, keyspec = keyspec)
		else:
			# The key is stored in hardware.
			private_key_storage = PrivateKeyStorage(PrivateKeyStorageForm.HARDWARE_TOKEN, pkcs11uri = self._args.hardware_key, so_search_path = self._args.pkcs11_so_search, module_so = self._args.pkcs11_module)

		camgr.create_ca_structure(private_key_storage = private_key_storage)
		if self._args.parent_ca is None:
			# Self-signed root CA
			camgr.create_selfsigned_ca_cert(subject_dn = self._args.subject_dn, validity_days = self._args.validity_days, signing_hash = self._args.hashfnc, serial = self._args.serial)

			# Create certificate chain file that only consists of our
			# self-signed certificate
			shutil.copy(self._args.capath + "/CA.crt", self._args.capath + "/chain.crt")
		else:
			# Intermediate CA
			if self._args.serial is not None:
				raise Exception("Can only specify certificate serial number when creating self-signed root CA certificate.")
			with tempfile.NamedTemporaryFile("w", prefix = "ca_", suffix = ".csr") as csr:
				camgr.create_ca_csr(csr_filename = csr.name, subject_dn = self._args.subject_dn)
				parent_ca = CAManager(self._args.parent_ca)
				parent_ca.sign_csr(csr.name, camgr.root_crt_filename, subject_dn = self._args.subject_dn, validity_days = self._args.validity_days, extension_template = "ca", signing_hash = self._args.hashfnc)

			# Create a certificate chain by appending the parent chain to our certificate
			if os.path.isfile(self._args.parent_ca + "/chain.crt"):
				with open(self._args.parent_ca + "/chain.crt") as parent_chainfile:
					parent_chain = parent_chainfile.read()
				with open(self._args.capath + "/CA.crt") as new_certificate_file:
					new_certificate = new_certificate_file.read()
				with open(self._args.capath + "/chain.crt", "w") as intermediate_chainfile:
					intermediate_chainfile.write(parent_chain)
					intermediate_chainfile.write(new_certificate)
