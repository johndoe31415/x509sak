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
import urllib.parse
from x509sak.KwargsChecker import KwargsChecker
from x509sak.Exceptions import InvalidInputException, LazyDeveloperException
from x509sak.FriendlyArgumentParser import baseint

class PrivateKeyStorageForm(enum.IntEnum):
	PEM_FILE = 1
	DER_FILE = 2
	HARDWARE_TOKEN = 3

class PrivateKeyStorage(object):
	_PARAMETER_CONSTRAINTS = {
		PrivateKeyStorageForm.PEM_FILE:			KwargsChecker(required_arguments = set([ "filename" ]), optional_arguments = set([ "search_path" ])),
		PrivateKeyStorageForm.DER_FILE:			KwargsChecker(required_arguments = set([ "filename" ]), optional_arguments = set([ "search_path" ])),
		PrivateKeyStorageForm.HARDWARE_TOKEN:	KwargsChecker(required_arguments = set([ "pkcs11uri", "so_search_path" ]), optional_arguments = set([ "dynamic_so", "module_so" ])),
	}

	def __init__(self, storage_form, **kwargs):
		assert(isinstance(storage_form, PrivateKeyStorageForm))
		self._storage_form = storage_form
		self._PARAMETER_CONSTRAINTS[storage_form].check(kwargs, hint = "PrivateKeyStorage using %s" % (storage_form.name))
		self._parameters = kwargs
		if "search_path" not in self._parameters:
			self._parameters["search_path"] = ""
		if self._storage_form == PrivateKeyStorageForm.HARDWARE_TOKEN:
			self._verify_pkcs11_uri()

	def _verify_pkcs11_uri(self):
		uri = self._parameters["pkcs11uri"]
		if uri.startswith("pkcs11:"):
			# Literal PKCS#11 URI, leave as-is.
			pass
		elif uri.startswith("label="):
			# Replace with encoded version
			label = uri[6 : ]
			self._parameters["pkcs11uri"] = "pkcs11:object=%s;type=private" % (urllib.parse.quote(label))
		elif uri.startswith("id="):
			# Replace with encoded version
			key_id_str = uri[3 : ]
			try:
				key_id = baseint(key_id_str)
				key_bytes = key_id.to_bytes(length = 16, byteorder = "big").lstrip(bytes(1))
			except (ValueError, OverflowError) as e:
				raise InvalidInputException("Key ID '%s' is not a valid hex value or is too large: %s" % (key_id_str, e.__class__.__name__))
			key_id_quoted = "".join("%%%02x" % (c) for c in key_bytes)
			self._parameters["pkcs11uri"] = "pkcs11:id=%s;type=private" % (key_id_quoted)
		else:
			raise InvalidInputException("For hardware keys, you need to either give a RFC7512-compliant pkcs11-scheme URI (starts with 'pkcs11:'), a key label in the form 'label=foobar' or a key id in the hex form like 'id=0xabc123' or in decimal form like 'id=11256099'. The supplied value '%s' is neither." % (uri))

	def update(self, key, value):
		self._PARAMETER_CONSTRAINTS[self._storage_form].check_single(key)
		self._parameters[key] = value

	@property
	def storage_form(self):
		return self._storage_form

	@property
	def is_file_based(self):
		return self.storage_form in [ PrivateKeyStorageForm.PEM_FILE, PrivateKeyStorageForm.DER_FILE ]

	@property
	def filename(self):
		assert(self.storage_form in [ PrivateKeyStorageForm.PEM_FILE, PrivateKeyStorageForm.DER_FILE ])
		return self._parameters["filename"]

	@property
	def full_filename(self):
		assert(self.storage_form in [ PrivateKeyStorageForm.PEM_FILE, PrivateKeyStorageForm.DER_FILE ])
		return self._parameters["search_path"] + self._parameters["filename"]

	@property
	def pkcs11uri(self):
		assert(self.storage_form == PrivateKeyStorageForm.HARDWARE_TOKEN)
		return self._parameters["pkcs11uri"]

	@property
	def so_search_path(self):
		assert(self.storage_form == PrivateKeyStorageForm.HARDWARE_TOKEN)
		return self._parameters["so_search_path"]

	@property
	def dynamic_so(self):
		assert(self.storage_form == PrivateKeyStorageForm.HARDWARE_TOKEN)
		return self._parameters.get("dynamic_so", "libpkcs11.so")

	@property
	def module_so(self):
		assert(self.storage_form == PrivateKeyStorageForm.HARDWARE_TOKEN)
		return self._parameters.get("module_so", "opensc-pkcs11.so")

	def to_dict(self):
		return {
			"storage_form":		self.storage_form.name,
			"parameters":		{ key: value for (key, value) in self._parameters.items() if key not in [ "search_path" ] },
		}

	@classmethod
	def from_dict(cls, serialized_dict, **kwargs):
		storage_form = getattr(PrivateKeyStorageForm, serialized_dict["storage_form"])
		parameters = serialized_dict["parameters"]
		parameters.update(kwargs)
		return cls(storage_form = storage_form, **parameters)

	@classmethod
	def from_str(cls, key_type, key_value):
		if key_type == "pem":
			return cls(PrivateKeyStorageForm.PEM_FILE, filename = key_value)
		elif key_type == "der":
			return cls(PrivateKeyStorageForm.DER_FILE, filename = key_value)
		elif key_type == "hw":
			return cls(PrivateKeyStorageForm.HARDWARE_TOKEN, pkcs11uri = key_value)
		else:
			raise LazyDeveloperException(NotImplemented, key_type)

	def __str__(self):
		if self.storage_form in [ PrivateKeyStorageForm.PEM_FILE, PrivateKeyStorageForm.DER_FILE ]:
			return "PrivateKeyStorage<%s: %s>" % (self.storage_form.name, self.filename)
		elif self.storage_form == PrivateKeyStorageForm.HARDWARE_TOKEN:
			return "PrivateKeyStorage<%s %s>" % (self.storage_form.name, self.pkcs11uri)
		else:
			return "PrivateKeyStorage<%s: %s>" % (self.storage_form.name, str(self._parameters))
