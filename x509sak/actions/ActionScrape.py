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
import re
import base64
from x509sak.BaseAction import BaseAction
from x509sak.ScrapeEngine import ScrapeEngine
from x509sak.Tools import PEMDataTools
import pyasn1.codec.der.decoder
from pyasn1_modules import rfc2459, rfc2437

class ActionScrape(BaseAction):
	_PEM_BEGIN = re.compile("^-----BEGIN (?P<marker>[ A-Za-z0-9]+)-----")
	_MARKERS = {
		"CERTIFICATE":			"crt",
		"OPENSSH PRIVATE KEY":	"openssh_key",
		"DSA PRIVATE KEY":		"dsa_key",
		"RSA PRIVATE KEY":		"rsa_key",
		"EC PRIVATE KEY":		"ec_key",
		"PUBLIC KEY":			"pubkey",
	}
	_DER_CLASSES = [
		(rfc2459.Certificate(),				"crt"),
		(rfc2459.SubjectPublicKeyInfo(),	"pubkey"),
		(rfc2437.RSAPrivateKey(),			"rsa_key"),
	]

	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		if os.path.exists(self._args.outdir) and (not self._args.force):
			raise Exception("Directory %s already exists. Remove it first or use --force." % (self._args.outdir))
		try:
			os.makedirs(self._args.outdir)
		except FileExistsError:
			pass

		engine = ScrapeEngine(self._args.filename)
		engine.search(self._find_pem, b"-----BEGIN CERTIFICATE-----", min_length = 53, max_length = 4096)
		engine.search(self._find_pem, b"-----BEGIN OPENSSH PRIVATE KEY-----", min_length = 70, max_length = 4096)
		engine.search(self._find_pem, b"-----BEGIN DSA PRIVATE KEY-----", min_length = 62, max_length = 4096)
		engine.search(self._find_pem, b"-----BEGIN RSA PRIVATE KEY-----", min_length = 62, max_length = 4096)
		engine.search(self._find_pem, b"-----BEGIN EC PRIVATE KEY-----", min_length = 60, max_length = 4096)
		engine.search(self._find_pem, b"-----BEGIN PUBLIC KEY-----", min_length = 52, max_length = 4096)
		engine.search(self._find_der, bytes.fromhex("30 81"), min_length = 3, max_length = 32 * 1024)
		engine.search(self._find_der, bytes.fromhex("30 82"), min_length = 4, max_length = 32 * 1024)
		engine.commence()

	def _found(self, offset, datatype, extension, data):
		filename_args = {
			"type":		datatype,
			"offset":	offset,
			"ext":		extension,
		}
		filename = self._args.outdir + "/" + (self._args.outmask % filename_args)
		with open(filename, "wb") as f:
			f.write(data)

	def _find_pem(self, offset, data):
		textdata = data.decode("ascii", errors = "ignore")
		result = self._PEM_BEGIN.match(textdata)
		if result is None:
			return
		result = result.groupdict()
		marker = result["marker"]
		full_re = re.compile("-----BEGIN %s-----(?P<pem_data>.*?)-----END %s-----" % (marker, marker), flags = re.DOTALL | re.MULTILINE)
		result = full_re.match(textdata)
		if result is None:
			return
		result = result.groupdict()
		pem_data = result["pem_data"]
		pem_data = pem_data.replace("\r", "")
		pem_data = pem_data.replace("\n", "")
		pem_data = pem_data.replace("\t", "")
		pem_data = pem_data.replace(" ", "")
		pem_data = base64.b64decode(pem_data)
		output_data = (PEMDataTools.data2pem(pem_data, marker) + "\n").encode()
		datatype = self._MARKERS.get(marker, "unknown")
		self._found(offset = offset, datatype = datatype, extension = "pem", data = output_data)

	def _find_der(self, offset, data):
		if data[1] == 0x81:
			length = 3 + data[2]
		elif data[1] == 0x82:
			length = 4 + (data[2] << 8) | data[3]
		else:
			raise LazyDeveloperException(NotImplemented, data[1])
		if len(data) < length:
			return
		derdata = data[ : length]

		for (decoding_class, datatype) in self._DER_CLASSES:
			try:
				(asn1, tail) = pyasn1.codec.der.decoder.decode(derdata, model = decoding_class)
				self._found(offset = offset, datatype = datatype, extension = "der", data = derdata)
			except pyasn1.error.PyAsn1Error as e:
				pass
