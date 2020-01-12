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

import enum
import json
import string
import functools

@functools.total_ordering
class RichJudgementCode():
	def __init__(self, code, description, **kwargs):
		self._code = code
		self._description = description
		self._flags = kwargs.get("flags")

	@property
	def code(self):
		return self._code

	@property
	def topic(self):
		return "TODO TOPIC"

	@property
	def short_text(self):
		return "TODO SHORT TEXT"

	@classmethod
	def from_node(cls, node):
		return cls(code = node.long_id, description = node.attrs["desc"])

	def __eq__(self, other):
		return self.code == other.code

	def __lt__(self, other):
		return self.code < other.code

	def __repr__(self):
		return "RichJudgementCode<%s>" % (self.code)

class StructureNode():
	_LABEL_REGULAR_CHARS = set(string.ascii_lowercase + string.ascii_uppercase + string.digits)
	_LABEL_UNDERSCORE_CHARS = set("/")
	_ALLOWED_ATTRIBUTES = set([ "short_id", "long_id", "import", "export", "flags", "desc", "label" ])
	_ALLOWED_FLAGS = set([ "datapoint" ])

	def __init__(self, name, children = None, attributes = None):
		self._name = name
		self._children = children if (children is not None) else [ ]
		self._attributes = attributes if (attributes is not None) else { }
		assert(all(key in self._ALLOWED_ATTRIBUTES for key in self._attributes))
		if "flags" in self._attributes:
			self._attributes["flags"] = frozenset(self._attributes["flags"])
			assert(all(flag in self._ALLOWED_FLAGS for flag in self._attributes["flags"]))

	def clone(self, filter_predicate = None):
		if not self.satisfies(filter_predicate):
			return None
		children = [ child.clone(filter_predicate = filter_predicate) for child in self.children if child.satisfies(filter_predicate) ]
		attributes = dict(self.attrs)
		return StructureNode(name = self.name, children = children, attributes = attributes)

	@property
	def name(self):
		return self._name

	@property
	def children(self):
		return iter(self._children)

	@property
	def label_id(self):
		if self.name is None:
			# Root node has no label
			return None
		else:
			if self.attrs.get("label") is None:
				input_name = self.name
			else:
				input_name = self.attrs["label"]

			next_uppercase = True
			label = [ ]
			for char in input_name:
				if char == " ":
					next_uppercase = True
				elif char in self._LABEL_REGULAR_CHARS:
					if next_uppercase:
						char = char.upper()
						next_uppercase = False
					label.append(char)
				elif char in self._LABEL_UNDERSCORE_CHARS:
					label.append("_")
			return "".join(label)

	@property
	def long_id(self):
		return self.attrs.get("long_id")

	@property
	def attrs(self):
		return self._attributes

	def satisfies(self, filter_predicate):
		if filter_predicate is None:
			return True
		return filter_predicate(self)

	def propagate_attribute_subtree(self, key):
		return self.apply_attribute_subtree(key, self.attrs.get(key))

	def apply_attribute_subtree(self, key, value):
		current_value = self.attrs.get(key)
		if current_value is not None:
			new_value = current_value
		else:
			new_value = value
		if new_value is not None:
			self.attrs[key] = new_value
		for child in self.children:
			child.apply_attribute_subtree(key, new_value)

	def purge_attribute(self, key):
		if key in self.attrs:
			del self.attrs[key]

	def purge_attribute_recursively(self, key):
		self.purge_attribute(key)
		for child in self.children:
			child.purge_attribute_recursively(key)

	def append_child(self, node):
		assert(isinstance(node, StructureNode))
		self._children.append(node)

	def append_children_of(self, node):
		for child in node.children:
			self.append_child(child)

	@classmethod
	def parse(cls, key, values):
		children = [ cls.parse(child_key, child_values) for (child_key, child_values) in values.items() if not child_key.startswith("_") ]
		attributes = { attribute_name[1:]: attribute_value for (attribute_name, attribute_value) in values.items() if attribute_name.startswith("_") }
		return cls(name = key, children = children, attributes = attributes)

	def dump(self, indent = 0):
		indent_str = ("   " * indent)
		if len(self._attributes) == 0:
			attrstr = ""
		else:
			attrstr = " %s" % (str(self.attrs))
		print("%s%s%s" % (indent_str, self.name, attrstr))
		for child in self.children:
			child.dump(indent + 1)

	def walk(self, callback):
		callback(self)
		for child in self.children:
			child.walk(callback)

	def assign_nodes_long_ids(self, prefix = None):
		if self.label_id is not None:
			if prefix is None:
				long_id = self.label_id
			else:
				long_id = prefix + "_" + self.label_id
			self._attributes["long_id"] = long_id
		else:
			long_id = None
		for child in self._children:
			child.assign_nodes_long_ids(prefix = long_id)

	def __repr__(self):
		return "Node<%s>" % (self.name)

class JudgementStructure():
	def __init__(self, structure_data):
		self._root = StructureNode.parse(None, structure_data)
		self._root.propagate_attribute_subtree("export")
		self._nodes_by_short_id = self._find_nodes_by_short_id()
		self._process_imports()
		self._root = self._root.clone(filter_predicate = lambda node: not node.attrs.get("export"))
		self._root.assign_nodes_long_ids()

	@property
	def root(self):
		return self._root

	def _find_nodes_by_short_id(self):
		short_ids = { }
		def visit(node):
			short_id = node.attrs.get("short_id")
			if short_id is not None:
				if short_id in short_ids:
					raise Exception("Duplicate short ID: %s" % (short_id))
				short_ids[short_id] = node
		self._root.walk(visit)
		return short_ids

	def _process_imports(self):
		def do_import(target, source, import_children = False):
			filter_predicate = lambda node: node.attrs.get("export") == True
			source_clone = source.clone(filter_predicate = filter_predicate)
			if source_clone is None:
				raise Exception("Cannot import node that is not exported.")
			if not target.attrs.get("export"):
				source_clone.purge_attribute_recursively("export")
			source_clone.purge_attribute_recursively("short_id")
			target.purge_attribute("import")
			if not import_children:
				target.append_child(source_clone)
			else:
				target.append_children_of(source_clone)

		def visit(node):
			import_short_id = node.attrs.get("import")
			if import_short_id is None:
				return
			if import_short_id.endswith("/*"):
				import_children = True
				import_short_id = import_short_id[:-2]
			else:
				import_children = False
			if import_short_id not in self._nodes_by_short_id:
				raise Exception("Import of '%s' requested, but no node by that short ID found." % (import_short_id))
			import_node = self._nodes_by_short_id[import_short_id]

			# Recursively descent before importing, in case the import imports something of its own
			visit(import_node)

			# Then import
			do_import(node, import_node, import_children = import_children)

		self._root.walk(visit)

	def create_enum_class(self):
		exported_nodes = { }
		def visit(node):
			if node.attrs.get("desc") is not None:
				exported_nodes[node.long_id] = node
		self._root.walk(visit)

		exported_nodes = { name: RichJudgementCode.from_node(node) for (name, node) in exported_nodes.items() }
		enum_class = enum.Enum("ExperimentalJudgementCodes", exported_nodes)
		return enum_class

	@classmethod
	def load_from_json(cls, filename):
		with open(filename) as f:
			structure_data = json.load(f)
		return cls(structure_data)

