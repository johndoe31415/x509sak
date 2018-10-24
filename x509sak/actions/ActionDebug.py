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

import readline
import code
import os
import atexit
import pyasn1.codec.der.decoder
import pyasn1.codec.der.encoder
import x509sak
import hashlib
from x509sak import CertificatePool, X509Certificate
from x509sak.BaseAction import BaseAction
from x509sak.Tools import PaddingTools

class DebugConsole(code.InteractiveConsole):
	def __init__(self, locals = None, histfile = os.path.expanduser(".dbgconsole_history")):
		code.InteractiveConsole.__init__(self, locals = locals)
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
		crts = X509Certificate.read_pemfile(self._args.crtfile)

		variables = {
			"x509sak":	x509sak,
			"derdec":	lambda data: pyasn1.codec.der.decoder.decode(data)[0],
			"derenc":	pyasn1.codec.der.encoder.encode,
			"crts":		crts,
			"c":		crts[0],
			"a":		crts[0].asn1,
			"unpkcs1":	PaddingTools.unpad_pkcs1,
			"decrsa":	self._decrypt_selfsigned_rsa_signature,
			"md5":		lambda payload: hashlib.md5(payload).digest(),
			"sha1":		lambda payload: hashlib.sha1(payload).digest(),
			"sha256":	lambda payload: hashlib.sha256(payload).digest(),
			"sha384":	lambda payload: hashlib.sha384(payload).digest(),
			"sha512":	lambda payload: hashlib.sha512(payload).digest(),
		}

		console = DebugConsole(locals = variables)
		console.interact()

	def _decrypt_selfsigned_rsa_signature(self, certificate):
		plain = pow(int.from_bytes(certificate.signature, byteorder = "big"), certificate.pubkey.e, certificate.pubkey.n)
		length = (plain.bit_length() + 7) // 8
		return int.to_bytes(plain, length = length, byteorder = "big")
