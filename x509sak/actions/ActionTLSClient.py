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

from x509sak.BaseAction import BaseAction
from x509sak.tls.Enums import TLSVersion
from x509sak.tls.MessageHelper import ClientHelloHelper
from x509sak.tls.TLSStructs import ClientHelloPkt, CertificatePkt
from x509sak.tls.TLSConnection import TLSClientConnection
from x509sak.X509Certificate import X509Certificate

class ActionTLSClient(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		tls_version = TLSVersion.ProtocolTLSv1_2
		self._conn = TLSClientConnection.tcp_connect(tls_version = tls_version, servername = args.servername, port = args.port)
		self._conn.decoder.add_hook("handshake", self._recv_handshake)
		self._conn.decoder.add_hook("record_layer", self._recv_record_layer)

		chh = ClientHelloHelper()
		client_hello = chh.create(server_name = args.servername)
		frame = ClientHelloPkt.pack(client_hello)
		self._conn.send_handshake(frame)

		self._conn.receive()

	def _recv_record_layer(self, hooktype, msg_id, data):
		print("<- %3d %s %s (%d bytes)" % (msg_id, data["content_type"].name, data["record_layer_version"], len(data["payload"])))

	def _recv_handshake(self, hooktype, msg_id, msg_type, data):
		print("<= %3d %s" % (msg_id, msg_type.name))
		if msg_type == CertificatePkt:
			print("    %d certificates received:" % (len(data["payload"]["certificates"])))
			for der_data in data["payload"]["certificates"]:
				cert = X509Certificate(bytes(der_data))
				print("        %s" % (cert))
