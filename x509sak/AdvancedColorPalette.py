#!/usr/bin/python3
#
#	AdvancedColorPalette - Color palette/mixer capable of reading JSON input data.
#	Copyright (C) 2018-2018 Johannes Bauer
#
#	This file is part of jpycommon.
#
#	jpycommon is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	jpycommon is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with jpycommon; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>
#
#	File UUID 74ab67dd-e6a6-4732-9d5d-03dc41c747c9

import json
import bisect
import collections

class AdvancedColorPalette(object):
	_ColorElement = collections.namedtuple("ColorElement", [ "pos", "name", "r", "g", "b" ])

	def __init__(self, palette_data):
		self._palette = self._parse_palette(palette_data)
		self._elements_by_name = { element.name: element for element in self._palette if element.name is not None }

		# Extracte positions for efficient bisect lookup later
		self._pos = tuple(entry.pos for entry in self._palette)

	def _parse_palette(self, palette_data):
		palette = [ ]
		for (eid, element) in enumerate(palette_data):
			if not "rgb" in element:
				raise KeyError("Palette entry must contain at least 'rgb' key.")
			rgb = element["rgb"].lstrip("#")
			if len(rgb) != 6:
				raise Exception("Cannot parse hex RGB colors '%s', expected six digit hex value." % (rgb))
			(r, g, b) = (int(rgb[0 : 2], 16) / 255, int(rgb[2 : 4], 16) / 255, int(rgb[4 : 6], 16) / 255)
			if "pos" in element:
				pos = element["pos"]
			else:
				pos = eid
			name = element.get("name")
			entry = self._ColorElement(pos = pos, name = name, r = r, g = g, b = b)
			palette.append(entry)

		# Right now palette is unnormalized position-wise and unsorted as well.
		# First determine min and max of "pos" to normalize it.
		min_pos = min(entry.pos for entry in palette)
		max_pos = max(entry.pos for entry in palette)
		pos_range = max_pos - min_pos

		# Now do a linear mapping, then sort
		palette = [ self._ColorElement(pos = (entry.pos - min_pos) / pos_range, name = entry.name, r = entry.r, g = entry.g, b = entry.b) for entry in palette ]
		palette.sort()
		return palette

	def dump(self):
		for (eid, element) in enumerate(self._palette):
			print("%2d at %5.3f: #%02x%02x%02x (%s)" % (eid, element.pos, round(255 * element.r), round(255 * element.g), round(255 * element.b), element.name or "unnamed"))
		print()

	@classmethod
	def load_from_json(cls, filename, palettename):
		with open(filename) as f:
			palettes = json.load(f)
		if palettename not in palettes:
			raise KeyError("No palette '%s' contained in JSON file %s." % (palettename, filename))
		return cls(palettes[palettename])

	@classmethod
	def get_schema_from_json(cls, filename):
		with open(filename) as f:
			palettes = json.load(f)
		return sorted(palettes.keys())

	@staticmethod
	def _clip(value):
		if value < 0:
			value = 0
		elif value > 1:
			value = 1
		return value

	@staticmethod
	def _mix_component(p, col1, col2):
		return (col1 * (1 - p)) + (col2 * p)

	def _mix(self, pos, col1, col2):
		# Determine linear mixing coefficient p (0 means all the way col1, 1
		# means all the way col2)
		p = (pos - col1.pos) / (col2.pos - col1.pos)
		return (self._mix_component(p, col1.r, col2.r), self._mix_component(p, col1.g, col2.g), self._mix_component(p, col1.b, col2.b))

	def get_float_color(self, pos):
		pos = self._clip(pos)
		index = bisect.bisect(self._pos, pos) - 1
		if index < 0:
			index = 0
		elif index > len(self._pos) - 2:
			index = len(self._pos) - 2

		# Check that we did our lookup correctly
		assert(self._pos[index] <= pos <= self._pos[index + 1])

		col_prev = self._palette[index]
		col_next = self._palette[index + 1]
		result = self._mix(pos, col_prev, col_next)
		return result

	def get_int_color(self, pos):
		(r, g, b) = self[pos]
		return (r << 16) | (g << 8) | b

	def get_hex_color(self, pos, with_hash = True):
		(r, g, b) = self[pos]
		rgb_str = "%02x%02x%02x" % (r, g, b)
		if with_hash:
			return "#" + rgb_str
		else:
			return rgb_str

	def __getitem__(self, pos):
		if isinstance(pos, str):
			element = self._elements_by_name[pos]
			(r, g, b) = (element.r, element.g, element.b)
		else:
			(r, g, b) = self.get_float_color(pos)
		return (round(r * 255), round(g * 255), round(b * 255))

if __name__ == "__main__":
	for name in [ "flatui", "traffic", "bgrmap3" ]:
		acp = AdvancedColorPalette.load_from_json("palettes.json", name)
		acp.dump()
