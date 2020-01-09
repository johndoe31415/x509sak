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
import json
from x509sak.tests import BaseTest
from x509sak.WorkDir import WorkDir
from x509sak.PRNG import HashedPRNG
from x509sak.X509Certificate import X509Certificate
from x509sak.PublicKey import PublicKey

class CmdLineTestsScrape(BaseTest):
	@staticmethod
	def _prepare_file(fp, data):
		fp.truncate(0)
		fp.seek(0)
		prng = HashedPRNG(seed = b"woohoo")
		for element in data:
			if isinstance(element, int):
				fp.write(prng.get(element))
			else:
				fp.write(element)
		fp.flush()

	def test_scrape_dir_exists(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			HashedPRNG(seed = b"foobar").write_file("out.bin", 3000)
			os.mkdir("scrape")
			with open("scrape/foo", "wb"):
				pass
			self._run_x509sak([ "scrape", "out.bin" ], success_return_codes = [ 1 ])
			self.assertTrue(os.path.isfile("scrape/foo"))
			self._run_x509sak([ "scrape", "--force", "out.bin" ])
			self.assertTrue(os.path.isfile("scrape/foo"))

	def test_scrape_random(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			HashedPRNG(seed = b"foobar").write_file("out.bin", 3 * 1024 * 1024)
			self._run_x509sak([ "scrape", "out.bin" ])
			found = os.listdir("scrape/")
			self.assertEqual(len(found), 0)

	def test_scrape_der_crt(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			crt = self._load_crt("ok/johannes-bauer.com")
			for prefix_len in [ 0, 100, 1000, 1024 * 1024 - 100, 1024 * 1024, 1024 * 1024 + 100 ]:
				HashedPRNG(seed = b"foobar").write_bracketed("out.bin", prefix_len, crt.der_data, 1000)
				self._run_x509sak([ "scrape", "out.bin" ])
				found = os.listdir("scrape/")
				self.assertEqual(len(found), 1)
				scraped_crt = X509Certificate.read_pemfile("scrape/scrape_%07x_crt.pem" % (prefix_len))[0]
				self.assertEqual(crt, scraped_crt)
				shutil.rmtree("scrape")

	def test_scrape_pem_crt(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			crt = self._load_crt("ok/johannes-bauer.com")
			for prefix_len in [ 0, 100, 1000 ]:
				self._prepare_file(f, [ prefix_len, crt.to_pem_data().encode("ascii"), 1000 ])
				self._run_x509sak([ "scrape", "--no-der", f.name ])
				found = os.listdir("scrape/")
				self.assertEqual(len(found), 1)
				scraped_crt = X509Certificate.read_pemfile("scrape/scrape_%07x_crt.pem" % (prefix_len))[0]
				self.assertEqual(crt, scraped_crt)
				shutil.rmtree("scrape")

	def test_scrape_der_crt_twice(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			crt = self._load_crt("ok/johannes-bauer.com")
			self._prepare_file(f, [ 1000, crt.der_data, 100, crt.der_data, 500 ])
			self._run_x509sak([ "scrape", "--no-pem", f.name ])

			found = os.listdir("scrape/")
			self.assertEqual(len(found), 1)
			scraped_crt = X509Certificate.read_pemfile("scrape/scrape_%07x_crt.pem" % (1000))[0]
			self.assertEqual(crt, scraped_crt)

			self._run_x509sak([ "scrape", "--force", "--allow-non-unique-blobs", f.name ])
			found = os.listdir("scrape/")
			self.assertEqual(len(found), 2)
			scraped_crt = X509Certificate.read_pemfile("scrape/scrape_%07x_crt.pem" % (1000))[0]
			self.assertEqual(crt, scraped_crt)
			scraped_crt = X509Certificate.read_pemfile("scrape/scrape_%07x_crt.pem" % (1100 + len(crt.der_data)))[0]
			self.assertEqual(crt, scraped_crt)

	def test_scrape_json(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			crt = self._load_crt("ok/johannes-bauer.com")
			self._prepare_file(f, [ 1000, crt.der_data, 100, crt.der_data, 500 ])
			self._run_x509sak([ "scrape", "--write-json", "out.json", f.name ])
			with open("out.json") as f:
				data = json.load(f)
			self.assertEqual(len(data["findings"]), 4)

	def test_extract_nested(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			crt = self._load_crt("ok/johannes-bauer.com")
			self._prepare_file(f, [ 100, crt.der_data, 100 ])
			self._run_x509sak([ "scrape", "--extract-nested", f.name ])
			found = os.listdir("scrape/")
			self.assertEqual(len(found), 2)
			scraped_crt = X509Certificate.read_pemfile("scrape/scrape_%07x_crt.pem" % (100))[0]
			scraped_pubkey = PublicKey.read_pemfile("scrape/scrape_%07x_pubkey.pem" % (287))[0]
			self.assertEqual(scraped_crt.pubkey, scraped_pubkey)

	def test_extract_broken_pem1(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			self._prepare_file(f, [ 100, b"-----BEGIN XYZ", 100 ])
			self._run_x509sak([ "scrape", "--extract-nested", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 0)

	def test_extract_broken_pem2(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			crt = self._load_crt("ok/johannes-bauer.com")
			self._prepare_file(f, [ 100, crt.to_pem_data().encode("ascii")[:-10], 100 ])
			self._run_x509sak([ "scrape", "--extract-nested", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 0)

	def test_extract_broken_pem3(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			self._prepare_file(f, [ 100, b"-----BEGIN CERTIFICATE----- -----END CERTIFICATE-----", 100 ])
			self._run_x509sak([ "scrape", "--extract-nested", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 0)

	def test_scrape_original_der(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			crt = self._load_crt("ok/johannes-bauer.com")
			self._prepare_file(f, [ 100, crt.der_data, 100 ])
			self._run_x509sak([ "scrape", "--keep-original-der", f.name ])
			scraped_crt = X509Certificate.read_derfile("scrape/scrape_%07x_crt.der" % (100))
			self.assertEqual(len(os.listdir("scrape/")), 1)
			self.assertEqual(crt, scraped_crt)

	def test_failed_rsa_privkey(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			crt = self._load_crt("ok/johannes-bauer.com")
			self._prepare_file(f, [ 100, crt.der_data, 100 ])
			self._run_x509sak([ "scrape", "--keep-original-der", f.name ])
			scraped_crt = X509Certificate.read_derfile("scrape/scrape_%07x_crt.der" % (100))
			self.assertEqual(len(os.listdir("scrape/")), 1)
			self.assertEqual(crt, scraped_crt)

	def test_failed_rsa_plausibility(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			privkey = self._load_privkey("broken/rsa_p_q_neq_n")
			self._prepare_file(f, [ 100, privkey.der_data, 100 ])
			self._run_x509sak([ "scrape", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 0)
			shutil.rmtree("scrape")
			self._run_x509sak([ "scrape", "--disable-der-sanity-checks", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 1)

	def test_failed_ec_plausibility(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			self._prepare_file(f, [ 100, bytes.fromhex("300b0201010406666f6f626172"), 100 ])
			self._run_x509sak([ "scrape", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 0)
			shutil.rmtree("scrape")
			self._run_x509sak([ "scrape", "--disable-der-sanity-checks", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 1)

	def test_failed_dsa_plausibility(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			self._prepare_file(f, [ 100, bytes.fromhex("300b0203112233020400aabbcc"), 100 ])
			self._run_x509sak([ "scrape", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 0)
			shutil.rmtree("scrape")
			self._run_x509sak([ "scrape", "--disable-der-sanity-checks", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 1)

	def test_included_types(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			crt = self._load_crt("ok/johannes-bauer.com")
			self._prepare_file(f, [ 100, crt.der_data, 100 ])
			self._run_x509sak([ "scrape", "--include-dertype", "crt", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 1)
			shutil.rmtree("scrape")

			self._run_x509sak([ "scrape", "--include-dertype", "crt", "--exclude-dertype", "crt", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 0)
			shutil.rmtree("scrape")

			self._run_x509sak([ "scrape", "--include-dertype", "pubkey", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 1)
			shutil.rmtree("scrape")

			self._run_x509sak([ "scrape", "--include-dertype", "ec_key", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 0)
			shutil.rmtree("scrape")

	def test_32k_cert(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), tempfile.NamedTemporaryFile(prefix = "scrapeme_", suffix = ".bin") as f:
			crt_der = self._load_data("certs/broken/length_32k.der.gz")
			self.assertEqual(len(crt_der), 32 * 1024)
			self._prepare_file(f, [ 100, crt_der, 100 ])
			self._run_x509sak([ "scrape", f.name ])
			self.assertEqual(len(os.listdir("scrape/")), 1)
