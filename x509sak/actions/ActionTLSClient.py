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
from x509sak.tls.TLSStructs import ClientHelloPkt
from x509sak.tls.TLSConnection import TLSConnection

class ActionTLSClient(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		tls_version = TLSVersion.ProtocolTLSv1_2
		connection = TLSConnection.tcp_connect(tls_version = tls_version, servername = args.servername, port = args.port)

		chh = ClientHelloHelper()
		print(chh.cipher_suite_directory.dump())
		client_hello = chh.create(server_name = args.servername)
		frame = ClientHelloPkt.pack(client_hello)
		connection.send_handshake(frame)

		print(connection.wait())
