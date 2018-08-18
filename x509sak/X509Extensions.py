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

import pyasn1.codec.der.decoder
import pyasn1.error
import pyasn1.type.univ
from pyasn1.type import tag
from pyasn1_modules import rfc2459
from x509sak.OID import OID, OIDDB
from x509sak.SecurityEstimator import SecurityEstimator

class X509Extensions(object):
	def __init__(self, extensions):
		self._exts = extensions

	def get_all(self, oid):
		assert(isinstance(oid, OID))
		return [ extension for extension in self._exts if extension.oid == oid ]

	def get_first(self, oid):
		assert(isinstance(oid, OID))
		exts = self.get_all(oid)
		if len(exts) == 0:
			return None
		else:
			return exts[0]

	def remove_all(self, oid):
		assert(isinstance(oid, OID))
		self._exts = [ extension for extension in self._exts if extension.oid != oid ]
		return self

	def filter(self, oid, replacement_extension):
		assert(isinstance(oid, OID))
		self._exts = [ extension if (extension.oid != oid) else replacement_extension for extension in self._exts ]
		return self

	def has(self, oid):
		assert(isinstance(oid, OID))
		return any(extension.oid == oid for extension in self._exts)

	def dump(self):
		print("%d X.509 extensions:" % (len(self)))
		for ext in self:
			print("    - %s" % (ext))

	def to_asn1(self):
		extension_list = [ extension.to_asn1() for extension in self ]
		# TODO: OMG this is fugly. We cannot use Extensions(), because it's
		# tag-incompatible with the instance used inside TBSCertificate. So, I
		# guess we're doing this? No way, Jose.
		extensions_asn1 = rfc2459.Extensions().subtype(explicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
		extensions_asn1.setComponents(*extension_list)
		return extensions_asn1

	def analyze(self, analysis_options = None):
		return SecurityEstimator.algorithm("crt_exts", analysis_options = analysis_options).analyze(self)

	def __getitem__(self, index):
		return self._exts[index]

	def __iter__(self):
		return iter(self._exts)

	def __len__(self):
		return len(self._exts)

	def __str__(self):
		return "X509Extensions<%d>" % (len(self))

class X509ExtensionRegistry(object):
	_KNOWN_EXTENSIONS = { }
	_DEFAULT_CLASS = None

	@classmethod
	def set_default_class(cls, handler):
		cls._DEFAULT_HANDLER = handler

	@classmethod
	def set_handler_class(cls, handler):
		oid = handler.get_handler_oid()
		cls._KNOWN_EXTENSIONS[oid] = handler

	@classmethod
	def create(cls, oid, critical, data):
		if oid in cls._KNOWN_EXTENSIONS:
			return cls._KNOWN_EXTENSIONS[oid](oid, critical, data)
		else:
			return cls._DEFAULT_HANDLER(oid, critical, data)

class X509Extension(object):
	_HANDLER_OID = None
	_ASN1_MODEL = None

	def __init__(self, oid, critical, data):
		assert(isinstance(oid, OID))
		assert(isinstance(critical, bool))
		assert(isinstance(data, bytes))
		self._oid = oid
		self._critical = critical
		self._data = data
		self._asn1 = None
		if self._ASN1_MODEL is not None:
			try:
				(self._asn1, _) = pyasn1.codec.der.decoder.decode(self.data, asn1Spec = self._ASN1_MODEL())
			except pyasn1.error.PyAsn1Error as e:
#				print("Couldn't parse ASN.1 extension: %s" % (str(e)))
				pass
		self._decode_hook()

	def to_asn1(self):
		extension = rfc2459.Extension()
		extension["extnID"] = self.oid.to_asn1()
		extension["critical"] = self.critical
		extension["extnValue"] = self.data
		return extension

	@classmethod
	def construct_from_asn1(cls, asn1, critical = False):
		data = pyasn1.codec.der.encoder.encode(asn1)
		return cls(oid = cls._HANDLER_OID, data = data, critical = critical)

	@classmethod
	def get_handler_oid(cls):
		return cls._HANDLER_OID

	@property
	def oid(self):
		return self._oid

	@property
	def critical(self):
		return self._critical

	@property
	def data(self):
		return self._data

	@property
	def asn1(self):
		return self._asn1

	def _decode_hook(self):
		pass

	@property
	def format_value(self):
		return self.data.hex()

	def __repr__(self):
		if self.oid in OIDDB.X509Extensions:
			name = OIDDB.X509Extensions[self.oid]
		else:
			name = str(self.oid)
		return "%s<%s = %s>" % (self.__class__.__name__, name, self.format_value)
X509ExtensionRegistry.set_default_class(X509Extension)

class X509SubjectKeyIdentifierExtension(X509Extension):
	_HANDLER_OID = OIDDB.X509Extensions.inverse("SubjectKeyIdentifier")
	_ASN1_MODEL = rfc2459.SubjectKeyIdentifier

	@classmethod
	def construct(cls, keyid):
		assert(isinstance(keyid, bytes))
		assert(len(keyid) == 20)
		return cls.construct_from_asn1(cls._ASN1_MODEL(keyid), critical = False)

	@property
	def keyid(self):
		return self._keyid

	@property
	def format_value(self):
		return "KeyID %s" % (self.keyid.hex())

	def __eq__(self, other):
		return self.keyid == other.keyid

	def _decode_hook(self):
		self._keyid = bytes(self.asn1)
X509ExtensionRegistry.set_handler_class(X509SubjectKeyIdentifierExtension)

class X509AuthorityKeyIdentifierExtension(X509Extension):
	_HANDLER_OID = OIDDB.X509Extensions.inverse("AuthorityKeyIdentifier")
	_ASN1_MODEL = rfc2459.AuthorityKeyIdentifier

	@classmethod
	def construct(cls, keyid):
		assert(isinstance(keyid, bytes))
		assert(len(keyid) == 20)
		asn1 = cls._ASN1_MODEL()
		asn1["keyIdentifier"] = keyid
		return cls.construct_from_asn1(asn1, critical = False)

	@property
	def keyid(self):
		return self._keyid

	@property
	def format_value(self):
		return "KeyID %s" % (self.keyid.hex())

	def _decode_hook(self):
		self._keyid = bytes(self.asn1["keyIdentifier"])
X509ExtensionRegistry.set_handler_class(X509AuthorityKeyIdentifierExtension)
