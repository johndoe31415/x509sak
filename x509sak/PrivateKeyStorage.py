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
from x509sak.KwargsChecker import KwargsChecker
from x509sak.Exceptions import LazyDeveloperException

class PrivateKeyStorageForm(enum.IntEnum):
	PEM_FILE = 1
	DER_FILE = 2
	HARDWARE_TOKEN = 3

class PrivateKeyStorage(object):
	_PARAMETER_CONSTRAINTS = {
		PrivateKeyStorageForm.PEM_FILE:			KwargsChecker(required_arguments = set([ "filename" ]), optional_arguments = set([ "search_path" ])),
		PrivateKeyStorageForm.DER_FILE:			KwargsChecker(required_arguments = set([ "filename" ]), optional_arguments = set([ "search_path" ])),
		PrivateKeyStorageForm.HARDWARE_TOKEN:	KwargsChecker(required_arguments = set([ "key_id", "so_search_path" ])),
	}

	def __init__(self, storage_form, **kwargs):
		assert(isinstance(storage_form, PrivateKeyStorageForm))
		self._storage_form = storage_form
		self._PARAMETER_CONSTRAINTS[storage_form].check(kwargs, hint = "PrivateKeyStorage using %s" % (storage_form.name))
		self._parameters = kwargs
		if "search_path" not in self._parameters:
			self._parameters["search_path"] = ""

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
	def key_id(self):
		assert(self.storage_form == PrivateKeyStorageForm.HARDWARE_TOKEN)
		return self._parameters["key_id"]

	@property
	def so_search_path(self):
		assert(self.storage_form == PrivateKeyStorageForm.HARDWARE_TOKEN)
		return self._parameters["so_search_path"]

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
			return "PrivateKeyStorage<%s ID %d>" % (self.storage_form.name, self.key_id)
		else:
			return "PrivateKeyStorage<%s: %s>" % (self.storage_form.name, str(self._parameters))
