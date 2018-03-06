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
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.OpenSSLTools import OpenSSLTools
from x509sak.OpenSSLConfig import OpenSSLConfig
from x509sak.WorkDir import WorkDir

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

	def _file(self, filename):
		return self._capath + filename

	@property
	def private_key_filename(self):
		return self._file("CA.key")

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

	@property
	def config_filename(self):
		return self._file("ca.cnf")

	def __create_ca_key(self, keyspec):
		OpenSSLTools.create_private_key(self.private_key_filename, keyspec)

	def create_selfsigned_ca_cert(self, subject_dn, validity_days, signing_hash, serial):
		OpenSSLTools.create_selfsigned_certificate(self.private_key_filename, self.root_crt_filename, subject_dn, validity_days, signing_hash = signing_hash, serial = serial, options = self._EXTENSION_TEMPLATES["rootca"])

	def create_ca_csr(self, csr_filename, subject_dn):
		OpenSSLTools.create_csr(self.private_key_filename, csr_filename, subject_dn)

	def __create_index_files(self):
		with open(self.index_filename, "w") as f:
			pass
		with open(self.index_attr_filename, "w") as f:
			pass
		with open(self.serial_filename, "w") as f:
			print("01", file = f)
		with open(self.crlnumber_filename, "w") as f:
			print("01", file = f)
		os.mkdir(self.newcerts_dirname)

	def __create_config(self, signing_hash):
		ca_name = "CA_default"

		cfg = OpenSSLConfig()
		cfg.new_section("ca")
		cfg.add("default_ca", ca_name)

		cfg.new_section(ca_name)
		cfg.add("database", "index.txt")
		cfg.add("new_certs_dir", "certs")
		cfg.add("certificate", "CA.crt")
		cfg.add("private_key", "CA.key")
		cfg.add("serial", "serial")
		cfg.add("crlnumber", "crlnumber")
		cfg.add("crl", "CA.crl")
		cfg.add("default_md", signing_hash)
		cfg.add("default_days", "365")
		cfg.add("default_crl_days", "30")
		cfg.add("policy", "policy_onlyCN")

		cfg.new_section("policy_onlyCN")
		cfg.add("commonName", "supplied")

		with open(self.config_filename, "w") as f:
			cfg.write_file(f)

	def create_ca_structure(self, keytype, signing_hash):
		self.__create_ca_key(keytype)
		self.__create_index_files()
		self.__create_config(signing_hash)

	def sign_csr(self, csr_filename, crt_filename, subject_dn = None, validity_days = None, extension_template = None, options = None, subject_alternative_dns_names = None, subject_alternative_ip_addresses = None, signing_hash = None):
		csr_absfilename = os.path.realpath(csr_filename)
		crt_absfilename = os.path.realpath(crt_filename)
		with WorkDir(self._capath), tempfile.NamedTemporaryFile("w", prefix = "ext_", suffix = ".cnf") as extfile:
			cmd = [ "openssl", "ca", "-config", self.config_filename, "-in", csr_absfilename, "-batch", "-notext", "-out", crt_absfilename ]
			if subject_dn is not None:
				cmd += [ "-subj", subject_dn ]
			if validity_days is not None:
				cmd += [ "-days", str(validity_days) ]
			if signing_hash is not None:
				cmd += [ "-md", signing_hash ]
			effective_options = { }
			if extension_template is not None:
				effective_options.update(self._EXTENSION_TEMPLATES[extension_template])
			if options is not None:
				effective_options.update(options)
			extension_count = OpenSSLTools.write_extension_file(extfile, options = effective_options, subject_alternative_dns_names = subject_alternative_dns_names, subject_alternative_ip_addresses = subject_alternative_ip_addresses)
			if extension_count > 0:
				cmd += [ "-extfile", extfile.name ]
			SubprocessExecutor.run(cmd)

	def revoke_crt(self, crt_filename):
		crt_absfilename = os.path.realpath(crt_filename)
		with WorkDir(self._capath), tempfile.NamedTemporaryFile("w", prefix = "ext_", suffix = ".cnf") as extfile:
			cmd = [ "openssl", "ca", "-config", self.config_filename, "-revoke", crt_absfilename ]
			SubprocessExecutor.run(cmd)
