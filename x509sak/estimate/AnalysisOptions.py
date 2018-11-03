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

import enum
import datetime

class AnalysisOptions(object):
	class RSATesting(enum.IntEnum):
		Full = 0
		Some = 1
		Fast = 2

	class CertificatePurpose(enum.Enum):
		CACertificate = "ca"
		TLSServerCertificate = "tls-server"
		TLSClientCertificate = "tls-client"

		def to_dict(self):
			return self.name

	def __init__(self, rsa_testing = RSATesting.Full, include_raw_data = False, purposes = None, fqdn = None, utcnow = None):
		assert(isinstance(rsa_testing, self.RSATesting))
		self._rsa_testing = rsa_testing
		self._include_raw_data = include_raw_data
		self._purposes = purposes
		self._fqdn = fqdn
		self._utcnow = utcnow or datetime.datetime.utcnow()
		if self._purposes is None:
			self._purposes = [ ]

	@property
	def rsa_testing(self):
		return self._rsa_testing

	@property
	def include_raw_data(self):
		return self._include_raw_data

	@property
	def purposes(self):
		return self._purposes

	@property
	def fqdn(self):
		return self._fqdn

	@property
	def utcnow(self):
		return self._utcnow
