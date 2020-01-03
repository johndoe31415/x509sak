#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2020-2020 Johannes Bauer
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

import pprint
from x509sak.BaseAction import BaseAction
from x509sak.tls.TLSStructs import CertificatePkt
from x509sak.tls.TLSMessageDecoder import TLSMessageDecoder
from x509sak.X509Certificate import X509Certificate
from x509sak.HexDump import HexDump

class ActionTLSParse(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		if args.encoding == "hex":
			with open(args.filename) as f:
				data = bytes.fromhex(f.read().replace("\n", ""))
		elif args.encoding == "bin":
			with open(args.filename, "rb") as f:
				data = f.read()
		else:
			raise NotImplementedError(args.encoding)

		if self._args.verbose >= 1:
			hd = HexDump()
			hd.dump(data)

		self._pp = pprint.PrettyPrinter(width = 180)
		decoder = TLSMessageDecoder(side = args.side)
		decoder.add_hook("alert", self._msg_alert)
		decoder.add_hook("handshake", self._msg_handshake)
		decoder.put(data)

	def _msg_alert(self, hooktype, msg):
		print("Alert:", msg)

	def _msg_handshake(self, hooktype, msg_id, msg_type, data):
		print("%s:" % (msg_type.name))
		self._pp.pprint(data)
		if msg_type == CertificatePkt:
			print("%d certificates received:" % (len(data["payload"]["certificates"])))
			for der_data in data["payload"]["certificates"]:
				cert = X509Certificate(bytes(der_data))
				print(cert)
		print()
