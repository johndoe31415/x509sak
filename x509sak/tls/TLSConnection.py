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

import socket
import time
from x509sak.tls.Enums import TLSVersion, ContentType
from x509sak.tls.TLSStructs import RecordLayerPkt
from x509sak.tls.TLSMessageDecoder import TLSMessageDecoder

class TLSConnectionInterruptedException(Exception): pass

class TLSConnectionTransport():
	def __init__(self, sock):
		self._sock = sock

	def send(self, data):
		return self._sock.send(data)

	def recv(self, data):
		return self._sock.recv(data)

	def close(self):
		self._sock.shutdown(socket.SHUT_RDWR)
		self._sock.close()

class TLSClientConnection():
	def __init__(self, transport, tls_version):
		assert(isinstance(tls_version, TLSVersion))
		self._transport = transport
		self._tls_version = tls_version
		self._decoder = TLSMessageDecoder(side = "server")
		self._decoder.add_hook("alert", self._msg_alert)
		self._running = True

	@property
	def decoder(self):
		return self._decoder

	def send(self, content_type, message):
		assert(isinstance(content_type, ContentType))
		assert(isinstance(message, (bytes, bytearray)))
		record_layer_pkt = {
			"content_type":				content_type,
			"record_layer_version":		self._tls_version.value[0],
			"payload":					message,
		}
		frame = RecordLayerPkt.pack(record_layer_pkt)
		return self._transport.send(frame)

	def send_handshake(self, message):
		return self.send(ContentType.Handshake, message)

	def _msg_alert(self, alert):
		print("Alert: %s" % (alert))
		self._cancel()

	def _cancel(self):
		self._running = False

	def receive(self):
		self._running = True
		while self._running:
			data = self._transport.recv(1024)
			if len(data) != 0:
				self._decoder.put(data)
			else:
				time.sleep(0.1)
		self._transport.close()

	@classmethod
	def tcp_connect(cls, tls_version, servername, port = 443, timeout = 10.0):
		sock = socket.create_connection((servername, port), timeout = timeout)
		transport = TLSConnectionTransport(sock)
		return cls(tls_version = tls_version, transport = transport)
