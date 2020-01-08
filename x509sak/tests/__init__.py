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

import pkgutil
import importlib
from .BaseTest import BaseTest, ResourceFileLoader

def __discover_testcases():
	for (module_info_module_finder, module_info_name, module_info_ispkg) in pkgutil.iter_modules([ "x509sak/tests" ]):
		if module_info_ispkg:
			continue
		module = importlib.import_module("x509sak.tests." + module_info_name)
		test_class = getattr(module, module_info_name, None)
		if test_class is None:
			print("Warning: Module %s doesn't have a class named %s." % (module, module_info_name))
		else:
			globals()[module_info_name] = test_class
__discover_testcases()
