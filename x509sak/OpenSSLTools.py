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

import os
import re
import tempfile
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.Exceptions import InvalidInputException, LazyDeveloperException
from x509sak.PrivateKeyStorage import PrivateKeyStorageForm
from x509sak.WorkDir import WorkDir
from x509sak.OpenSSLConfig import OpenSSLConfig
from x509sak.TempUMask import TempUMask
from x509sak.AlgorithmDB import Cryptosystems

class OpenSSLTools():
	_EXECUTABLE = "openssl"
	_CACHED_VERSION = None
	_VERSION_RE = re.compile(r"^OpenSSL (?P<major>\d+)\.(?P<minor>\d+)\.(?P<fix>\d+)(?P<patch>[a-z])?")
	_CERT_VERIFY_REGEX = re.compile(r"error (?P<error_code>\d+) at (?P<depth>\d+) depth lookup:(?P<reason>.*)")

	@classmethod
	def openssl_version(cls):
		if cls._CACHED_VERSION is None:
			result = SubprocessExecutor([ cls._EXECUTABLE, "version" ]).run()
			match = cls._VERSION_RE.match(result.stdout_text)
			if match:
				match = match.groupdict()
				cls._CACHED_VERSION = (int(match["major"]), int(match["minor"]), int(match["fix"]), match["patch"])
		return cls._CACHED_VERSION

	@classmethod
	def __create_pem_private_key(cls, private_key_filename, keyspec):
		if keyspec.cryptosystem == Cryptosystems.RSA:
			cmd = [ cls._EXECUTABLE, "genrsa", "-out", private_key_filename, str(keyspec["bitlen"]) ]
		elif keyspec.cryptosystem == Cryptosystems.ECC_ECDSA:
			cmd = [ cls._EXECUTABLE, "ecparam", "-genkey", "-out", private_key_filename, "-name", keyspec["curvename"] ]
		elif keyspec.cryptosystem == Cryptosystems.ECC_EdDSA:
			cmd = [ cls._EXECUTABLE, "genpkey", "-out", private_key_filename, "-algorithm", keyspec["curvename"] ]
		else:
			raise LazyDeveloperException(NotImplemented, keyspec.cryptosystem)
		SubprocessExecutor(cmd).run()

	@classmethod
	def create_private_key(cls, private_key_storage, keyspec):
		with tempfile.NamedTemporaryFile(prefix = "privkey_", suffix = ".pem") as pem_file:
			cls.__create_pem_private_key(pem_file.name, keyspec)

			# Then convert to the desired result format in a second step
			cmd = [ cls._EXECUTABLE ]
			if keyspec.cryptosystem == Cryptosystems.RSA:
				cmd += [ "rsa" ]
			elif keyspec.cryptosystem == Cryptosystems.ECC_ECDSA:
				cmd += [ "ec" ]
			elif keyspec.cryptosystem in [ Cryptosystems.ECC_EdDSA, Cryptosystems.ECC_ECDH ]:
				cmd += [ "pkey" ]
			else:
				raise LazyDeveloperException(NotImplemented, keyspec.cryptosystem)
			if private_key_storage.storage_form == PrivateKeyStorageForm.PEM_FILE:
				cmd += [ "-outform", "pem" ]
			elif private_key_storage.storage_form == PrivateKeyStorageForm.DER_FILE:
				cmd += [ "-outform", "der" ]
			else:
				raise LazyDeveloperException(NotImplemented, private_key_storage.storage_form)
			cmd += [ "-in", pem_file.name, "-out", private_key_storage.full_filename ]
			SubprocessExecutor(cmd).run()

	@classmethod
	def _privkey_option(cls, private_key_storage, key_option = "key"):
		if private_key_storage.storage_form == PrivateKeyStorageForm.PEM_FILE:
			cmd = [ "-%s" % (key_option), private_key_storage.full_filename ]
		elif private_key_storage.storage_form == PrivateKeyStorageForm.DER_FILE:
			cmd = [ "-%s" % (key_option), private_key_storage.full_filename, "-keyform", "der" ]
		elif private_key_storage.storage_form == PrivateKeyStorageForm.HARDWARE_TOKEN:
			cmd = [ "-%s" % (key_option), private_key_storage.pkcs11uri, "-keyform", "engine", "-engine", "pkcs11" ]
			#cmd = [ "-%s" % (key_option), "0:%d" % (private_key_storage.key_id), "-keyform", "engine", "-engine", "pkcs11" ]
		else:
			raise LazyDeveloperException(NotImplemented, private_key_storage.storage_form)
		return cmd

	@classmethod
	def __get_config(cls, private_key_storage, x509_extensions = None, subject_alternative_dns_names = None, subject_alternative_ip_addresses = None):
		openssl_config = OpenSSLConfig()
		openssl_config.set_private_key_storage(private_key_storage)
		openssl_config.set_x509_extensions(x509_extensions)
		openssl_config.set_subject_alternative_dns_names(subject_alternative_dns_names)
		openssl_config.set_subject_alternative_ip_addresses(subject_alternative_ip_addresses)
		return openssl_config

	@classmethod
	def __create_csr_or_selfsigned_certificate(cls, private_key_storage, output_filename, subject_dn, validity_days, x509_extensions = None, subject_alternative_dns_names = None, subject_alternative_ip_addresses = None, signing_hash = None, serial = None):
		openssl_config = cls.__get_config(private_key_storage = private_key_storage, x509_extensions = x509_extensions, subject_alternative_dns_names = subject_alternative_dns_names, subject_alternative_ip_addresses = subject_alternative_ip_addresses)
		with tempfile.NamedTemporaryFile("w", prefix = "config_", suffix = ".cnf") as config_file:
			openssl_config.write_to(config_file.name)
			cmd = [ cls._EXECUTABLE, "req", "-utf8", "-new" ]
			if validity_days is not None:
				cmd += [ "-x509", "-days", str(validity_days) ]
			if signing_hash is not None:
				cmd += [ "-%s" % (signing_hash) ]
			if serial is not None:
				cmd += [ "-set_serial", "%d" % (serial) ]
			cmd += cls._privkey_option(private_key_storage)
			cmd += [  "-subj", subject_dn, "-out", output_filename ]
			SubprocessExecutor(cmd, env = { "OPENSSL_CONF": config_file.name }).run()

	@classmethod
	def create_selfsigned_certificate(cls, private_key_storage, certificate_filename, subject_dn, validity_days, x509_extensions = None, subject_alternative_dns_names = None, subject_alternative_ip_addresses = None, signing_hash = None, serial = None):
		return cls.__create_csr_or_selfsigned_certificate(
				private_key_storage = private_key_storage,
				output_filename = certificate_filename,
				subject_dn = subject_dn,
				validity_days = validity_days,
				x509_extensions = x509_extensions,
				subject_alternative_dns_names = subject_alternative_dns_names,
				subject_alternative_ip_addresses = subject_alternative_ip_addresses,
				signing_hash = signing_hash,
				serial = serial,
		)

	@classmethod
	def create_csr(cls, private_key_storage, csr_filename, subject_dn, x509_extensions = None, subject_alternative_dns_names = None, subject_alternative_ip_addresses = None, signing_hash = None):
		return cls.__create_csr_or_selfsigned_certificate(
				private_key_storage = private_key_storage,
				output_filename = csr_filename,
				subject_dn = subject_dn,
				validity_days = None,
				x509_extensions = x509_extensions,
				subject_alternative_dns_names = subject_alternative_dns_names,
				subject_alternative_ip_addresses = subject_alternative_ip_addresses,
				signing_hash = signing_hash,
		)

	@classmethod
	def ca_sign_csr(cls, ca_manager, csr_filename, crt_filename, subject_dn, validity_days, x509_extensions = None, subject_alternative_dns_names = None, subject_alternative_ip_addresses = None, signing_hash = None):
		csr_absfilename = os.path.realpath(csr_filename)
		crt_absfilename = os.path.realpath(crt_filename)
		openssl_config = cls.__get_config(private_key_storage = ca_manager.private_key_storage, x509_extensions = x509_extensions, subject_alternative_dns_names = subject_alternative_dns_names, subject_alternative_ip_addresses = subject_alternative_ip_addresses)
		with WorkDir(ca_manager.capath), tempfile.NamedTemporaryFile("w", prefix = "config_", suffix = ".cnf") as config_file:
			openssl_config.write_to(config_file.name)
			cmd = [ cls._EXECUTABLE, "ca", "-utf8", "-in", csr_absfilename, "-batch", "-notext", "-out", crt_absfilename ]
			cmd += cls._privkey_option(ca_manager.private_key_storage, key_option = "keyfile")
			if subject_dn is not None:
				cmd += [ "-subj", subject_dn ]
			if validity_days is not None:
				cmd += [ "-days", str(validity_days) ]
			if signing_hash is not None:
				cmd += [ "-md", signing_hash ]
			SubprocessExecutor(cmd, env = { "OPENSSL_CONF": config_file.name }).run()

	@classmethod
	def ca_revoke_crt(cls, ca_manager, crt_filename):
		crt_absfilename = os.path.realpath(crt_filename)
		openssl_config = cls.__get_config(private_key_storage = ca_manager.private_key_storage)
		with WorkDir(ca_manager.capath), tempfile.NamedTemporaryFile("w", prefix = "config_", suffix = ".cnf") as config_file:
			openssl_config.write_to(config_file.name)
			cmd = [ cls._EXECUTABLE, "ca", "-revoke", crt_absfilename ]
			cmd += cls._privkey_option(ca_manager.private_key_storage, key_option = "keyfile")
			SubprocessExecutor(cmd, env = { "OPENSSL_CONF": config_file.name }).run()

	@classmethod
	def ca_create_crl(cls, ca_manager, crl_filename, signing_hash = None, validity_days = None):
		crl_absfilename = os.path.realpath(crl_filename)
		openssl_config = cls.__get_config(private_key_storage = ca_manager.private_key_storage)
		with WorkDir(ca_manager.capath), tempfile.NamedTemporaryFile("w", prefix = "config_", suffix = ".cnf") as config_file:
			openssl_config.write_to(config_file.name)
			cmd = [ cls._EXECUTABLE, "ca", "-gencrl", "-out", crl_absfilename ]
			if validity_days is not None:
				cmd += [ "-crldays", str(validity_days) ]
			if signing_hash is not None:
				cmd += [ "-md", signing_hash ]
			SubprocessExecutor(cmd, env = { "OPENSSL_CONF": config_file.name }).run()

	@classmethod
	def sign_data(cls, signing_algorithm, private_key_filename, payload):
		cmd = [ cls._EXECUTABLE, "dgst", "-sign", private_key_filename, "-%s" % (signing_algorithm.value.hash_fnc.value.name) ]
		signature = SubprocessExecutor(cmd, stdin = payload).run().stdout
		return signature

	@classmethod
	def private_to_public(cls, private_key_filename, public_key_filename):
		success = SubprocessExecutor([ cls._EXECUTABLE, "rsa", "-in", private_key_filename, "-pubout", "-out", public_key_filename ], on_failure = "pass").run().successful
		if not success:
			success = SubprocessExecutor([ cls._EXECUTABLE, "ec", "-in", private_key_filename, "-pubout", "-out", public_key_filename ], on_failure = "pass").run().successful
		if not success:
			raise InvalidInputException("File %s contained neither RSA nor ECC private key." % (private_key_filename))

	@classmethod
	def create_pkcs12(cls, certificates, private_key_storage = None, modern_crypto = True, passphrase = None):
		with TempUMask(), tempfile.NamedTemporaryFile("w", prefix = "pkcs_pass_", suffix = ".txt") as pass_file:
			if passphrase is not None:
				print(passphrase, file = pass_file)
			else:
				print(file = pass_file)
			pass_file.flush()

			cmd = [ cls._EXECUTABLE, "pkcs12", "-export" ]
			if private_key_storage is None:
				cmd += [ "-nokeys" ]
			else:
				assert(private_key_storage.is_file_based)
				if private_key_storage.storage_form == PrivateKeyStorageForm.PEM_FILE:
					cmd += [ "-inkey", private_key_storage.filename ]
				else:
					raise LazyDeveloperException(NotImplemented, private_key_storage.storage_form)
			cmd += [ "-passout", "file:%s" % (pass_file.name) ]
			if modern_crypto:
				cmd += [ "-macalg", "sha384", "-maciter", "-keypbe", "aes-128-cbc" ]
			pem_certificates = "\n".join(certificate.to_pem_data() for certificate in certificates)
			output = SubprocessExecutor(cmd, stdin = pem_certificates.encode("ascii")).run().stdout
			return output

	@classmethod
	def get_tls_server_cert_pem(cls, hostname, port = 443):
		result = SubprocessExecutor([ cls._EXECUTABLE, "s_client", "-connect", "%s:%d" % (hostname, port), "-servername", hostname ]).run()
		return result.stdout.decode()

	@classmethod
	def validate_signature(cls, issuer_certificate, subject_certificate, verbose_failure = False):
		with tempfile.NamedTemporaryFile(prefix = "subject_", suffix = ".crt") as subject, tempfile.NamedTemporaryFile(prefix = "issuer_", suffix = ".crt") as issuer, tempfile.TemporaryDirectory(prefix = "empty") as emptydir:
			subject_certificate.write_pemfile(subject.name)
			issuer_certificate.write_pemfile(issuer.name)

			cmd = [ "openssl", "verify", "-CApath", emptydir ]
			if cls.openssl_version() >= (1, 1, 0, ""):
				cmd += [ "-no_check_time" ]
			cmd += [ "-check_ss_sig", "-CAfile", issuer.name, subject.name ]
			result = SubprocessExecutor(cmd, on_failure = "pass").run()
			if result.successful:
				return True
			else:
				# Maybe the certificate signature was okay, but the complete
				# chain couldn't be established. This would still count as a
				# successful verification, however.
				match = cls._CERT_VERIFY_REGEX.search(result.stdouterr_text)
				if match:
					match = match.groupdict()
					(error_code, depth) = (int(match["error_code"]), int(match["depth"]))
					chain_valid = (error_code == 2) and (depth == 1)
					if (not chain_valid) and verbose_failure:
						print("Certificate verification error, error_code %d, depth = %d. %s not signed by %s." % (error_code, depth, subject_certificate, issuer_certificate))
						result.dump()
					return chain_valid
				else:
					# If in doubt, reject.
					if verbose_failure:
						print("Certificate verification error. %s not signed by %s." % (subject_certificate, issuer_certificate))
						result.dump()
					return False
