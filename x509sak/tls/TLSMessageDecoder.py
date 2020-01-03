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

import collections
from x509sak.tls.Enums import ContentType
from x509sak.tls.TLSStructs import RecordLayerPkt, AlertPkt, ServerHandshakeMessage, ClientHandshakeMessage
from x509sak.tls.Structure import DeserializationException
from x509sak.tls.DataBuffer import DataBuffer, DataBufferException

class TLSMessageDecoder():
	_TLSAlertMessage = collections.namedtuple("TLSAlertMessage", [ "encrypted", "data" ])

	def __init__(self, side):
		assert(side in [ "client", "server" ])
		self._side = side
		self._buffer = DataBuffer()
		self._msgid = 0
		self._installed_hooks = {
			"record_layer":		[ ],
			"alert":			[ ],
			"handshake":		[ ],
			"unimplemented":	[ ],
		}

	def put(self, data):
		self._buffer += data
		self._trigger_decode()

	def add_hook(self, hooktype, callback):
		self._installed_hooks[hooktype].append(callback)
		return self

	def add_hooks(self, hooktypes, callback):
		for hooktype in hooktypes:
			self.add_hook(hooktype, callback)

	def _execute_hook(self, hooktype, *data):
		for hook in self._installed_hooks[hooktype]:
			hook(hooktype, self._msgid, *data)

	def _handle_record_layer_pkt(self, record_layer_packet):
		self._execute_hook("record_layer", record_layer_packet)
		if record_layer_packet["content_type"] == ContentType.Alert:
			if len(record_layer_packet["payload"]) == 2:
				alert_packet = AlertPkt.unpack(DataBuffer(record_layer_packet["payload"]))
				self._execute_hook("alert", self._TLSAlertMessage(encrypted = False, data = alert_packet))
			else:
				# Encrypted alert
				self._execute_hook("alert", self._TLSAlertMessage(encrypted = True, data = record_layer_packet["payload"]))

		elif record_layer_packet["content_type"] == ContentType.Handshake:
			if self._side == "server":
				msg = ServerHandshakeMessage.unpack(DataBuffer(record_layer_packet["payload"]))
				self._execute_hook("handshake", msg[0], msg[1])
			else:
				msg = ClientHandshakeMessage.unpack(DataBuffer(record_layer_packet["payload"]))
				self._execute_hook("handshake", msg[0], msg[1])

		else:
			self._execute_hook("unimplemented", record_layer_packet["content_type"])

	def _trigger_decode(self):
		try:
			while True:
				record_layer_pkt = RecordLayerPkt.unpack(self._buffer)
				self._handle_record_layer_pkt(record_layer_pkt)
				self._msgid += 1
		except (DataBufferException, DeserializationException):
			# No more packets
			pass
