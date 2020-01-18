#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2020 Johannes Bauer
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

import readline
import code
import os
import atexit
import hashlib
import subprocess
import pyasn1.codec.der.decoder
import pyasn1.codec.der.encoder
import x509sak
from x509sak import X509Certificate
from x509sak.BaseAction import BaseAction
from x509sak.Tools import PaddingTools, ASN1Tools
from x509sak.HexDump import HexDump

class DebugConsole(code.InteractiveConsole):
	def __init__(self, local_vars = None, histfile = os.path.expanduser(".dbgconsole_history")):
		code.InteractiveConsole.__init__(self, locals = local_vars)
		self.init_history(histfile)

	def init_history(self, histfile):
		readline.parse_and_bind("tab: complete")
		if hasattr(readline, "read_history_file"):
			try:
				readline.read_history_file(histfile)
			except IOError:
				pass
			atexit.register(self.save_history, histfile)

	def save_history(self, histfile):
		readline.write_history_file(histfile)

class ActionDebug(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)
		crts = self._read_certificates(self._args.crtfile)

		self._hd = HexDump()
		local_vars = {
			"x509sak":	x509sak,
			"derdec":	lambda data: pyasn1.codec.der.decoder.decode(data)[0],
			"derenc":	pyasn1.codec.der.encoder.encode,
			"crts":		crts,
			"c":		crts[0] if (len(crts) > 0) else None,
			"a":		crts[0].asn1 if (len(crts) > 0) else None,
			"unpkcs1":	PaddingTools.unpad_pkcs1,
			"decrsa":	self._decrypt_selfsigned_rsa_signature,
			"md5":		lambda payload: hashlib.md5(payload).digest(),
			"sha1":		lambda payload: hashlib.sha1(payload).digest(),
			"sha256":	lambda payload: hashlib.sha256(payload).digest(),
			"sha384":	lambda payload: hashlib.sha384(payload).digest(),
			"sha512":	lambda payload: hashlib.sha512(payload).digest(),
			"hd":		self._hd.dump,
			"ap":		self._asn1parse,
			"write_py":	self._write_py,
			"safedec":	ASN1Tools.safe_decode,
		}

		console = DebugConsole(local_vars = local_vars)
		for command in self._args.execute:
			print(">>> %s" % (command))
			console.runcode(command)
		if len(self._args.execute) > 0:
			print()
		if not self._args.no_interact:
			console.interact()

	def _read_certificate(self, filename):
		if not self._args.der:
			return X509Certificate.read_pemfile(filename)
		else:
			return [ X509Certificate.read_derfile(filename) ]

	def _read_certificates(self, filenames):
		certificates = [ ]
		for filename in filenames:
			certificates += self._read_certificate(filename)
		return certificates

	def _write_py(self, data, outfile):
		with open(outfile, "w") as f:
			for (name, value) in sorted(data.items()):
				if isinstance(value, int):
					if value < 100000:
						print("%s = %d" % (name, value), file = f)
					else:
						print("%s = %#x" % (name, value), file = f)
				else:
					print("# %s omitted (type %s)" % (name, value.__type__.__name__), file = f)

	def _decrypt_selfsigned_rsa_signature(self, certificate):
		plain = pow(int.from_bytes(certificate.signature, byteorder = "big"), certificate.pubkey.e, certificate.pubkey.n)
		length = (plain.bit_length() + 7) // 8
		return int.to_bytes(plain, length = length, byteorder = "big")

	def _asn1parse(self, data):
		proc = subprocess.Popen([ "openssl", "asn1parse", "-inform", "der", "-i" ], stdin = subprocess.PIPE)
		proc.communicate(data)
