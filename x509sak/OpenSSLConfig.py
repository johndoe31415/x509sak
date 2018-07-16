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

from x509sak.PrivateKeyStorage import PrivateKeyStorageForm
from x509sak.Tools import PathTools

class OpenSSLConfig(object):
	def __init__(self):
		self._engine_dynamic_path = None
		self._engine_module_path = None
		self._custom_x509_extensions = { }
		self._subject_alternative_dns_names = [ ]
		self._subject_alternative_ip_addresses = [ ]

	@property
	def extension_count(self):
		return len(self._custom_x509_extensions) + len(self._subject_alternative_dns_names) + len(self._subject_alternative_ip_addresses)

	def dump(self):
		print("OpenSSL config:")
		print("    Engine dynamic path : %s" % (self._engine_dynamic_path))
		print("    Engine MODULE path  : %s" % (self._engine_module_path))
		print("    X.509 extensions    : %s" % (str(self._custom_x509_extensions)))
		print("    Subj alternative DNS: %s" % (str(self._subject_alternative_dns_names)))
		print("    Subj alternative IP : %s" % (str(self._subject_alternative_ip_addresses)))

	@property
	def use_engine(self):
		return self._engine_dynamic_path is not None

	def set_private_key_storage(self, private_key_storage):
		if private_key_storage.storage_form == PrivateKeyStorageForm.HARDWARE_TOKEN:
			self._engine_dynamic_path = PathTools.find(private_key_storage.so_search_path, private_key_storage.dynamic_so)
			self._engine_module_path = PathTools.find(private_key_storage.so_search_path, private_key_storage.module_so)

	def set_custom_x509_extensions(self, custom_x509_extensions):
		if custom_x509_extensions is None:
			custom_x509_extensions = { }
		self._custom_x509_extensions = custom_x509_extensions

	def set_subject_alternative_dns_names(self, subject_alternative_dns_names):
		if subject_alternative_dns_names is None:
			subject_alternative_dns_names = [ ]
		self._subject_alternative_dns_names = subject_alternative_dns_names

	def set_subject_alternative_ip_addresses(self, subject_alternative_ip_addresses):
		if subject_alternative_ip_addresses is None:
			subject_alternative_ip_addresses = [ ]
		self._subject_alternative_ip_addresses = subject_alternative_ip_addresses


	def __write_config(self, f):
		print("openssl_conf = openssl_conf", file = f)
		print(file = f)
		print("[openssl_conf]", file = f)
		if self.use_engine:
			print("engines = engines_config", file = f)
		print(file = f)
		print("[engines_config]", file = f)
		print("pkcs11 = engine_pkcs11_parameters", file = f)
		print(file = f)
		print("[engine_pkcs11_parameters]", file = f)
		print("engine_id = pkcs11", file = f)
		print("dynamic_path = %s" % (self._engine_dynamic_path), file = f)
		print("MODULE_PATH = %s" % (self._engine_module_path), file = f)
		print("init = 0", file = f)
		print(file = f)
		print("[ca]", file = f)
		print("default_ca = CA_default", file = f)
		print(file = f)
		print("[CA_default]", file = f)
		print("database = index.txt", file = f)
		print("new_certs_dir = certs", file = f)
		print("certificate = CA.crt", file = f)
		print("private_key = CA.key", file = f)
		print("serial = serial", file = f)
		print("crlnumber = crlnumber", file = f)
		print("crl = CA.crl", file = f)
		print("default_md = sha256", file = f)
		print("default_days = 365", file = f)
		print("default_crl_days = 30", file = f)
		print("policy = policy_onlyCN", file = f)
		if self.extension_count > 0:
			print("x509_extensions = extensions", file = f)
		print(file = f)
		print("[policy_onlyCN]", file = f)
		print("commonName = supplied", file = f)
		print(file = f)
		print("[req]", file = f)
		print("distinguished_name = default", file = f)
		if self.extension_count > 0:
			print("x509_extensions = extensions", file = f)
			print("req_extensions = extensions", file = f)
		print(file = f)
		print("[extensions]", file = f)
		for (key, value) in sorted(self._custom_x509_extensions.items()):
			print("%s = %s" % (key, value), file = f)

		alt_names = [ ]
		alt_names += [ "DNS:%s" % (value) for value in self._subject_alternative_dns_names ]
		alt_names += [ "IP:%s" % (value) for value in self._subject_alternative_ip_addresses ]
		if len(alt_names) > 0:
			print("subjectAltName = %s" % (", ".join(alt_names)), file = f)

	def write_to(self, filename):
		with open(filename, "w") as f:
			self.__write_config(f)
