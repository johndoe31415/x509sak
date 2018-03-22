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
from x509sak.Tools import ASN1Tools
from x509sak.PublicKey import PublicKey

class ActionForgeCert(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		certs = X509Certificate.read_pemfile(self._args.crt_filename)
		if not certs[0].is_selfsigned():
			raise InvalidInputException("First certificate in chain (%s) is not self-signed." % (certs[0]))
		for (cert_id, (issuer, subject)) in enumerate(zip(certs, certs[1:]), 1):
			if not subject.signed_by(issuer):
				raise InvalidInputException("Certificate %d in file (%s) is not issuer for certificate %d (%s)." % (cert_id, issuer, cert_id + 1, subject))

		self._log.debug("Chain of %d certificates to forge.", len(certs))
		self._forge_cert(0, certs[0], 0, certs[0])
		for (cert_subject_id, (issuer, subject)) in enumerate(zip(certs, certs[1:]), 1):
			self._forge_cert(cert_subject_id - 1, issuer, cert_subject_id, subject)

	def _forge_cert(self, cert_issuer_id, issuer, cert_subject_id, subject):
		self._log.debug("Forging chain element %d -> %d: %s -> %s", cert_issuer_id, cert_subject_id, issuer, subject)
		issuer_key_filename = self._args.key_template % (cert_issuer_id)
		key_filename = self._args.key_template % (cert_subject_id)
		crt_filename = self._args.cert_template % (cert_subject_id)

		sig_alg = subject.signature_algorithm
		if (not os.path.isfile(key_filename)) or self._args.force:
			OpenSSLTools.create_private_key(key_filename, sig_alg.cryptosystem)

		with tempfile.NamedTemporaryFile(prefix = "pubkey_", suffix = ".pem") as pubkey_file:
			OpenSSLTools.private_to_public(key_filename, pubkey_file.name)
			pubkey = PublicKey.read_pemfile(pubkey_file.name)[0]

		# Replace public key first
		forged_cert_asn1 = subject.asn1_clone
		forged_cert_asn1["tbsCertificate"]["subjectPublicKeyInfo"] = pubkey.asn1
		forged_cert = X509Certificate.from_asn1(forged_cert_asn1)

		# Then sign the modified certifiate
		signature = OpenSSLTools.sign_data(sig_alg, issuer_key_filename, forged_cert.signed_payload)

		# Finally, place the signature into the certificate
		forged_cert_asn1["signatureValue"] = ASN1Tools.bytes2bitstring(signature)
		forged_cert = X509Certificate.from_asn1(forged_cert_asn1)
		forged_cert.write_pemfile(crt_filename)
