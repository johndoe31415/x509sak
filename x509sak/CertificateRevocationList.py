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

from pyasn1_modules import rfc2459
from x509sak.PEMDERObject import PEMDERObject
from x509sak.Tools import ASN1Tools

class CertificateRevocationList(PEMDERObject):
	_PEM_MARKER = "CRL"
	_ASN1_MODEL = rfc2459.CertificateList

	@property
	def this_update(self):
		return ASN1Tools.parse_datetime(str(self._asn1["tbsCertList"]["thisUpdate"].getComponent()))

	@property
	def next_update(self):
		return ASN1Tools.parse_datetime(str(self._asn1["tbsCertList"]["nextUpdate"].getComponent()))

	@property
	def crt_count(self):
		return len(self._asn1["tbsCertList"]["revokedCertificates"])

	def __str__(self):
		return "CRL<%d entries, nextUpdate = %s UTC>" % (self.crt_count, self.next_update.strftime("%Y-%m-%d %H:%M:%S"))
