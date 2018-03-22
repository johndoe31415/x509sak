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
import unittest
import pkgutil
import datetime
from x509sak import X509Certificate

class X509CertificateTests(unittest.TestCase):
	@staticmethod
	def _load_crt(crtname):
		x509_text = pkgutil.get_data("x509sak.tests.data", crtname).decode("ascii")
		cert = X509Certificate.from_pem_data(x509_text)[0]
		return cert

	def test_pem_load(self):
		x509_text = pkgutil.get_data("x509sak.tests.data", "johannes-bauer.com.crt").decode("ascii")
		cert = X509Certificate.from_pem_data(x509_text)
		self.assertEqual(len(cert), 1)
		cert = cert[0]
		self.assertEqual(cert.to_pem_data() + "\n", x509_text)

	def test_crt_equality(self):
		cert1 = self._load_crt("johannes-bauer.com.crt")
		cert2 = self._load_crt("johannes-bauer.com.crt")
		self.assertEqual(cert1, cert2)

	def test_distinguished_names(self):
		cert = self._load_crt("johannes-bauer-intermediate.crt")
		self.assertEqual(cert.issuer.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")
		self.assertEqual(cert.subject.rfc2253_str, "CN=Let's Encrypt Authority X3,C=US,O=Let's Encrypt")

		cert = self._load_crt("johannes-bauer-root.crt")
		self.assertEqual(cert.subject, cert.issuer)
		self.assertFalse(cert.subject != cert.issuer)

	def test_load_system_certs(self):
		dirname = "/etc/ssl/certs/"
		for filename in os.listdir(dirname):
			if filename.endswith(".pem"):
				fullfilename = dirname + filename
				cert = X509Certificate.read_pemfile(fullfilename)[0]
				temp = cert.issuer.rfc2253_str + cert.subject.rfc2253_str

	def test_crt_dates(self):
		cert = self._load_crt("johannes-bauer-intermediate.crt")
		self.assertEqual(cert.valid_not_before, datetime.datetime(2016, 3, 17, 16, 40, 46))
		self.assertEqual(cert.valid_not_after, datetime.datetime(2021, 3, 17, 16, 40, 46))
