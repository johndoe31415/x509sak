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
import json
from x509sak.OpenSSLTools import OpenSSLTools
from x509sak.PrivateKeyStorage import PrivateKeyStorage, PrivateKeyStorageForm

class CAManager(object):
	_EXTENSION_TEMPLATES = {
		"rootca": {
			"basicConstraints":			"critical,CA:TRUE",
			"subjectKeyIdentifier":		"hash",
			"keyUsage":					"critical,digitalSignature,keyCertSign,cRLSign",
		},
		"ca": {
			"basicConstraints":			"critical,CA:TRUE",
			"subjectKeyIdentifier":		"hash",
			"authorityKeyIdentifier":	"keyid",
			"keyUsage":					"critical,digitalSignature,keyCertSign,cRLSign",
		},
		"tls-client": {
			"nsCertType":				"client",
			"basicConstraints":			"critical,CA:FALSE",
			"subjectKeyIdentifier":		"hash",
			"authorityKeyIdentifier":	"keyid",
			"keyUsage":					"critical,digitalSignature,keyAgreement,keyEncipherment",
			"extendedKeyUsage":			"clientAuth",
		},
		"tls-server": {
			"nsCertType":				"server",
			"basicConstraints":			"critical,CA:FALSE",
			"subjectKeyIdentifier":		"hash",
			"authorityKeyIdentifier":	"keyid",
			"keyUsage":					"critical,digitalSignature,keyAgreement,keyEncipherment",
			"extendedKeyUsage":			"serverAuth",
		},
	}

	def __init__(self, capath):
		self._capath = os.path.realpath(capath)
		if not self._capath.endswith("/"):
			self._capath += "/"

		if not os.path.isfile(self.metadata_filename):
			# Create if does not exist for legacy CAs.
			self._private_key_storage = PrivateKeyStorage(PrivateKeyStorageForm.PEM_FILE, filename = "CA.key", search_path = self._capath)
			self._save_metadata()
		else:
			# Load from metadata
			self._load_metadata()
		if self._private_key_storage.is_file_based:
			self._private_key_storage.update("search_path", self._capath)

	@property
	def capath(self):
		return self._capath

	def _load_metadata(self):
		with open(self.metadata_filename) as f:
			metadata = json.load(f)
		self._private_key_storage = PrivateKeyStorage.from_dict(metadata["private_key_storage"])

	def _save_metadata(self):
		metadata = {
			"version":				1,
			"private_key_storage":	self._private_key_storage.to_dict(),
		}
		with open(self.metadata_filename, "w") as f:
			json.dump(metadata, f, sort_keys = True, indent = 4)
			f.write("\n")

	def _file(self, filename):
		return self._capath + filename

	@property
	def metadata_filename(self):
		return self._file("metadata.json")

	@property
	def private_key_storage(self):
		return self._private_key_storage

	@property
	def root_crt_filename(self):
		return self._file("CA.crt")

	@property
	def serial_filename(self):
		return self._file("serial")

	@property
	def crlnumber_filename(self):
		return self._file("crlnumber")

	@property
	def crl_filename(self):
		return self._file("CA.crl")

	@property
	def index_filename(self):
		return self._file("index.txt")

	@property
	def index_attr_filename(self):
		return self._file("index.txt.attr")

	@property
	def newcerts_dirname(self):
		return self._file("certs")

	def __create_ca_key(self, keyspec):
		OpenSSLTools.create_private_key(self._file(self.private_key_storage.filename), keyspec)

	def create_selfsigned_ca_cert(self, subject_dn, validity_days, signing_hash, serial):
		OpenSSLTools.create_selfsigned_certificate(self.private_key_storage, self.root_crt_filename, subject_dn, validity_days, signing_hash = signing_hash, serial = serial, custom_x509_extensions = self._EXTENSION_TEMPLATES["rootca"])

	def create_ca_csr(self, csr_filename, subject_dn):
		OpenSSLTools.create_csr(self.private_key_storage, csr_filename, subject_dn)

	def sign_csr(self, csr_filename, crt_filename, subject_dn, validity_days, extension_template = None, custom_x509_extensions = None, subject_alternative_dns_names = None, subject_alternative_ip_addresses = None, signing_hash = None):
		extensions = { }
		if extension_template is not None:
			extensions.update(self._EXTENSION_TEMPLATES[extension_template])
		if custom_x509_extensions is not None:
			extensions.update(custom_x509_extensions)
		OpenSSLTools.ca_sign_csr(self, csr_filename, crt_filename, subject_dn, validity_days, custom_x509_extensions = extensions, subject_alternative_dns_names = subject_alternative_dns_names, subject_alternative_ip_addresses = subject_alternative_ip_addresses, signing_hash = signing_hash)

	def revoke_crt(self, *args, **kwargs):
		OpenSSLTools.ca_revoke_crt(self, *args, **kwargs)

	def create_crl(self, *args, **kwargs):
		OpenSSLTools.ca_create_crl(self, *args, **kwargs)

	def __create_management_files(self, unique_subject = True):
		with open(self.index_filename, "w") as f:
			pass
		with open(self.index_attr_filename, "w") as f:
			print("unique_subject = %s" % ("yes" if unique_subject else "no"), file = f)
		with open(self.serial_filename, "w") as f:
			print("01", file = f)
		with open(self.crlnumber_filename, "w") as f:
			print("01", file = f)
		os.mkdir(self.newcerts_dirname)

	def create_ca_structure(self, private_key_storage, unique_subject = True):
		self._private_key_storage = private_key_storage
		self._save_metadata()
		self.__create_management_files(unique_subject = unique_subject)
