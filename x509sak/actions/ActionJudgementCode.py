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

from x509sak.BaseAction import BaseAction
import x509sak.estimate.JudgementStructure

class ActionJudgementCode(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		structure = x509sak.estimate.JudgementStructure.create_judgement_structure(verbose = self._args.verbose >= 1)
		extended_enum_class = structure.create_extended_enum_class()
		if self._args.action == "list":
			codes = [ enum_code.value for enum_code in extended_enum_class ]
			for jc in sorted(codes):
				print(jc.name)
		elif self._args.action == "dump":
			structure.root.dump()
		elif self._args.action == "inherit":
			for (target_attribute, inherited_codes) in sorted(extended_enum_class.inheritance.items()):
				print("%s:" % (target_attribute))
				for (base_name, codepoint) in sorted(inherited_codes.items()):
					print("    %s: %s" % (base_name, codepoint.name))
				print()
		else:
			raise NotImplementedError(self._args.action)
