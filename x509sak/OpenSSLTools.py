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
from x509sak.KeySpecification import Cryptosystem
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.Exceptions import InvalidInputException, LazyDeveloperException
from x509sak.PrivateKeyStorage import PrivateKeyStorageForm
from x509sak.WorkDir import WorkDir
from x509sak.OpenSSLConfig import OpenSSLConfig

class OpenSSLTools(object):
	@classmethod
	def __create_pem_private_key(cls, private_key_filename, keyspec):
		if keyspec.cryptosystem == Cryptosystem.RSA:
			cmd = [ "openssl", "genrsa", "-out", private_key_filename, str(keyspec["bitlen"]) ]
		elif keyspec.cryptosystem == Cryptosystem.ECC:
			cmd = [ "openssl", "ecparam", "-genkey", "-out", private_key_filename, "-name", keyspec["curve"] ]
		else:
			raise LazyDeveloperException(NotImplemented, keyspec.cryptosystem)
		SubprocessExecutor.run(cmd)

	@classmethod
	def create_private_key(cls, private_key_storage, keyspec):
		with tempfile.NamedTemporaryFile(prefix = "privkey_", suffix = ".pem") as pem_file:
			cls.__create_pem_private_key(pem_file.name, keyspec)

			# Then convert to the desired result format in a second step
			cmd = [ "openssl" ]
			if keyspec.cryptosystem == Cryptosystem.RSA:
				cmd += [ "rsa" ]
			elif keyspec.cryptosystem == Cryptosystem.ECC:
				cmd += [ "ec" ]
			else:
				raise LazyDeveloperException(NotImplemented, keyspec.cryptosystem)
			if private_key_storage.storage_form == PrivateKeyStorageForm.PEM_FILE:
				cmd += [ "-outform", "pem" ]
			elif private_key_storage.storage_form == PrivateKeyStorageForm.DER_FILE:
				cmd += [ "-outform", "der" ]
			else:
				raise LazyDeveloperException(NotImplemented, private_key_storage.storage_form)
			cmd += [ "-in", pem_file.name, "-out", private_key_storage.full_filename ]
			SubprocessExecutor.run(cmd)

	@classmethod
	def _privkey_option(cls, private_key_storage, key_option = "key"):
		if private_key_storage.storage_form == PrivateKeyStorageForm.PEM_FILE:
			cmd = [ "-%s" % (key_option), private_key_storage.full_filename ]
		elif private_key_storage.storage_form == PrivateKeyStorageForm.DER_FILE:
			cmd = [ "-%s" % (key_option), private_key_storage.full_filename, "-keyform", "der" ]
		elif private_key_storage.storage_form == PrivateKeyStorageForm.HARDWARE_TOKEN:
			cmd = [ "-%s" % (key_option), "0:%d" % (private_key_storage.key_id), "-keyform", "engine", "-engine", "pkcs11" ]
		else:
			raise LazyDeveloperException(NotImplemented, private_key_storage.storage_form)
		return cmd

	@classmethod
	def __get_config(cls, private_key_storage, custom_x509_extensions = None, subject_alternative_dns_names = None, subject_alternative_ip_addresses = None):
		openssl_config = OpenSSLConfig()
		openssl_config.set_private_key_storage(private_key_storage)
		openssl_config.set_custom_x509_extensions(custom_x509_extensions)
		openssl_config.set_subject_alternative_dns_names(subject_alternative_dns_names)
		openssl_config.set_subject_alternative_ip_addresses(subject_alternative_ip_addresses)
		return openssl_config

	@classmethod
	def __create_csr_or_selfsigned_certificate(cls, private_key_storage, output_filename, subject_dn, validity_days, custom_x509_extensions = None, subject_alternative_dns_names = None, subject_alternative_ip_addresses = None, signing_hash = None, serial = None):
		openssl_config = cls.__get_config(private_key_storage = private_key_storage, custom_x509_extensions = custom_x509_extensions, subject_alternative_dns_names = subject_alternative_dns_names, subject_alternative_ip_addresses = subject_alternative_ip_addresses)
		with tempfile.NamedTemporaryFile("w", prefix = "config_", suffix = ".cnf") as config_file:
			openssl_config.write_to(config_file.name)
			cmd = [ "openssl", "req", "-new" ]
			if validity_days is not None:
				cmd += [ "-x509", "-days", str(validity_days) ]
			if signing_hash is not None:
				cmd += [ "-%s" % (signing_hash) ]
			if serial is not None:
				cmd += [ "-set_serial", "%d" % (serial) ]
			cmd += cls._privkey_option(private_key_storage)
			cmd += [  "-subj", subject_dn, "-out", output_filename ]
			SubprocessExecutor.run(cmd, env = { "OPENSSL_CONF": config_file.name })

	@classmethod
	def create_selfsigned_certificate(cls, private_key_storage, certificate_filename, subject_dn, validity_days, custom_x509_extensions = None, subject_alternative_dns_names = None, subject_alternative_ip_addresses = None, signing_hash = None, serial = None):
		return cls.__create_csr_or_selfsigned_certificate(
				private_key_storage = private_key_storage,
				output_filename = certificate_filename,
				subject_dn = subject_dn,
				validity_days = validity_days,
				custom_x509_extensions = custom_x509_extensions,
				subject_alternative_dns_names = subject_alternative_dns_names,
				subject_alternative_ip_addresses = subject_alternative_ip_addresses,
				signing_hash = signing_hash,
				serial = serial,
		)

	@classmethod
	def create_csr(cls, private_key_storage, csr_filename, subject_dn, custom_x509_extensions = None, subject_alternative_dns_names = None, subject_alternative_ip_addresses = None):
		return cls.__create_csr_or_selfsigned_certificate(
				private_key_storage = private_key_storage,
				output_filename = csr_filename,
				subject_dn = subject_dn,
				validity_days = None,
				custom_x509_extensions = custom_x509_extensions,
				subject_alternative_dns_names = subject_alternative_dns_names,
				subject_alternative_ip_addresses = subject_alternative_ip_addresses,
		)

	@classmethod
	def ca_sign_csr(cls, ca_manager, csr_filename, crt_filename, subject_dn, validity_days, custom_x509_extensions = None, subject_alternative_dns_names = None, subject_alternative_ip_addresses = None, signing_hash = None):
		csr_absfilename = os.path.realpath(csr_filename)
		crt_absfilename = os.path.realpath(crt_filename)
		openssl_config = cls.__get_config(private_key_storage = ca_manager.private_key_storage, custom_x509_extensions = custom_x509_extensions, subject_alternative_dns_names = subject_alternative_dns_names, subject_alternative_ip_addresses = subject_alternative_ip_addresses)
		with WorkDir(ca_manager.capath), tempfile.NamedTemporaryFile("w", prefix = "config_", suffix = ".cnf") as config_file:
			openssl_config.write_to(config_file.name)
			cmd = [ "openssl", "ca", "-in", csr_absfilename, "-batch", "-notext", "-out", crt_absfilename ]
			cmd += cls._privkey_option(ca_manager.private_key_storage, key_option = "keyfile")
			if subject_dn is not None:
				cmd += [ "-subj", subject_dn ]
			if validity_days is not None:
				cmd += [ "-days", str(validity_days) ]
			if signing_hash is not None:
				cmd += [ "-md", signing_hash ]
			SubprocessExecutor.run(cmd, env = { "OPENSSL_CONF": config_file.name })

	@classmethod
	def ca_revoke_crt(cls, ca_manager, crt_filename):
		crt_absfilename = os.path.realpath(crt_filename)
		openssl_config = cls.__get_config(private_key_storage = ca_manager.private_key_storage)
		with WorkDir(ca_manager.capath), tempfile.NamedTemporaryFile("w", prefix = "config_", suffix = ".cnf") as config_file:
			openssl_config.write_to(config_file.name)
			cmd = [ "openssl", "ca", "-revoke", crt_absfilename ]
			SubprocessExecutor.run(cmd, env = { "OPENSSL_CONF": config_file.name })

	@classmethod
	def sign_data(cls, signing_algorithm, private_key_filename, payload):
		cmd = [ "openssl", "dgst", "-sign", private_key_filename, "-%s" % (signing_algorithm.hashfunction) ]
		(_, signature) = SubprocessExecutor.run(cmd, stdin = payload, discard_stderr = True, return_stdout = True)
		return signature

	@classmethod
	def private_to_public(cls, private_key_filename, public_key_filename):
		success = SubprocessExecutor.run([ "openssl", "rsa", "-in", private_key_filename, "-pubout", "-out", public_key_filename ], on_failure = "pass")
		if not success:
			success = SubprocessExecutor.run([ "openssl", "ec", "-in", private_key_filename, "-pubout", "-out", public_key_filename ], on_failure = "pass")
		if not success:
			raise InvalidInputException("File %s contained neither RSA nor ECC private key." % (private_key_filename))
