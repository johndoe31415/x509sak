#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2019-2019 Johannes Bauer
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

import re
import inspect
import collections
from x509sak.Exceptions import ProgrammerErrorException, InvalidInputException

class BaseStructureMember():
	def __init__(self, name = None):
		self._name = name

	@property
	def name(self):
		return self._name

	def pack(self, values):
		raise NotImplementedError(self.__class__.__name__)

	def unpack(self, databuffer):
		raise NotImplementedError(self.__class__.__name__)

class StructureMember(BaseStructureMember):
	_Handlers = None
	_HandlerPurpose = collections.namedtuple("Purpose", [ "function", "typename_regex", "support_extra" ])

	def __init__(self, name, typename, enum_class = None, inner = None, inner_array = None):
		BaseStructureMember.__init__(self, name = name)
		if self._Handlers is None:
			StructureMember._Handlers = self._initialize_handlers()
		self._typename = typename
		self._enum_class = enum_class
		self._extra = {
			"inner":		inner,
			"inner_array":	inner_array,
			"enum_class":	enum_class,
		}
		self.pack = self._get_handler("pack", self.typename, self._extra)
		self.unpack = self._get_handler("unpack", self.typename, self._extra)

	def _initialize_handlers(self):
		handlers = {
			"pack": [ ],
			"unpack": [ ],
		}
		self._UnpackHandlers = { }
		for (method_name, method) in inspect.getmembers(self, inspect.ismethod):
			signature = inspect.signature(method)
			anno = signature.return_annotation
			if (anno is not None) and (anno != inspect.Signature.empty):
				functions = (anno.function, ) if isinstance(anno.function, str) else anno.function
				typename_regex = anno.typename_regex
				compiled_typename_regex = re.compile(typename_regex)
				for function in functions:
					handlers[function].append((compiled_typename_regex, method, anno))
		return handlers

	@property
	def name(self):
		return self._name

	@property
	def typename(self):
		return self._typename

	@classmethod
	def _get_handler(cls, function, typename, extra = None):
		if extra is None:
			extra = { }
		extra = { key: value for (key, value) in extra.items() if (value is not None) }
		have_extra = set(extra)
		for (regex, method, purpose) in cls._Handlers[function]:
			match = regex.fullmatch(typename)
			if match:
				match = match.groupdict()
				unsupported_extra = have_extra - set(purpose.support_extra)
				if len(unsupported_extra) > 0:
					raise ProgrammerErrorException("%s does not support the given extra argument(s): %s" % (typename, ", ".join(sorted(unsupported_extra))))
				return method(typename, match, extra)
		raise ProgrammerErrorException("No %s handler for type '%s' found." % (function, typename))

	@classmethod
	def _create_unpacker_int(cls, typename, match, extra) -> _HandlerPurpose(function = "unpack", typename_regex = r"uint(?P<bit>\d+)", support_extra = [ "enum_class" ]):
		length_bits = int(match["bit"])
		assert((length_bits % 8) == 0)
		length = length_bits // 8

		def unpack(databuffer):
			data = databuffer.get(length)
			value = int.from_bytes(data, byteorder = "big")
			if extra.get("enum_class") is not None:
				value = extra["enum_class"](value)
			return value
		return unpack

	@classmethod
	def _create_packer_int(cls, typename, match, extra) -> _HandlerPurpose(function = "pack", typename_regex = r"uint(?P<bit>\d+)", support_extra = [ "enum_class" ]):
		length_bits = int(match["bit"])
		assert((length_bits % 8) == 0)
		length = length_bits // 8
		minval = 0
		maxval = (1 << (length_bits)) - 1

		def pack(value):
			if extra.get("enum_class") is not None:
				value = int(value)
			if (value < minval) or (value > maxval):
				raise InvalidInputException("%s must be between %d and %d (given value was %d)." % (typename, minval, maxval, value))
			data = int.to_bytes(value, byteorder = "big", length = length)
			return data
		return pack

	@classmethod
	def _create_unpacker_opaque(cls, typename, match, extra) -> _HandlerPurpose(function = "unpack", typename_regex = r"opaque(?P<bit>\d+)", support_extra = [ "inner", "inner_array" ]):
		length_field_unpack = cls._get_handler("unpack", "uint" + match["bit"])
		def unpack(databuffer):
			length = length_field_unpack(databuffer)
			return databuffer.get(length)
		return unpack

	@classmethod
	def _create_packer_opaque(cls, typename, match, extra) -> _HandlerPurpose(function = "pack", typename_regex = r"opaque(?P<bit>\d+)", support_extra = [ "inner", "inner_array" ]):
		length_field_pack = cls._get_handler("pack", "uint" + match["bit"])
		def pack(data):
			return length_field_pack(len(data)) + data
		return pack

	@classmethod
	def _create_unpacker_array(cls, typename, match, extra) -> _HandlerPurpose(function = "unpack", typename_regex = r"array\[(?P<length>\d+)(,\s+(?P<padbyte>[0-9a-fA-F]{2}))?\]", support_extra = [ ]):
		length = int(match["length"])

		def unpack(databuffer):
			return databuffer.get(length)
		return unpack

	@classmethod
	def _create_packer_array(cls, typename, match, extra) -> _HandlerPurpose(function = "pack", typename_regex = r"array\[(?P<length>\d+)(,\s+(?P<padbyte>[0-9a-fA-F]{2}))?\]", support_extra = [ ]):
		length = int(match["length"])
		padbyte = None if (match["padbyte"] is None) else int(match["padbyte"], 16)

		def pack(data):
			if padbyte is None:
				# Size must exactly match up
				if len(data) == length:
					return data
				else:
					raise InvalidInputException("For packing of array of length %d without padding, %d bytes must be provided. Got %d bytes." % (length, length, len(data)))
			else:
				# Can pad
				if len(data) <= length:
					pad_len = length - len(data)
					padding = bytes([ padbyte ]) * pad_len
					return data + padding
				else:
					raise InvalidInputException("For packing of array of length %d with padding, at most %d bytes must be provided. Got %d bytes." % (length, length, len(data)))
		return pack

	def __str__(self):
		return "%s: %s" % (self.name, self.typename)

class Structure(BaseStructureMember):
	def __init__(self, members, name = None):
		BaseStructureMember.__init__(self, name = name)
		self._members = members
		self._required_keys = set(member.name for member in members)
		if len(self._required_keys) != len(members):
			raise ProgrammerErrorException("Structure definition amgiguous, duplicate member names used.")

	@property
	def members(self):
		return iter(self._members)

	@property
	def typename(self):
		return "Structure"

	def pack(self, values):
		# First check if all members are present
		present_keys = set(values.keys())
		missing_keys = self._required_keys - present_keys
		if len(missing_keys) > 0:
			raise ProgrammerErrorException("Missing keys in %s: %s" % (self.__class__.__name__, ", ".join(sorted(missing_keys))))

		result_data = bytearray()
		for member in self.members:
			value = values[member.name]
			result_data += member.pack(value)
		return bytes(result_data)

	def unpack(self, databuffer):
		result = { }
		with databuffer.rewind_on_exception():
			for member in self.members:
				result[member.name] = member.unpack(databuffer)
			return result

	def __str__(self):
		return "%s<%s>" % (self.name, ", ".join(("%s %s" % (member.name, member.typename) for member in self.members)))
