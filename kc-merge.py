#!/usr/bin/python3
import argparse
import collections
import os
import re
import subprocess, functools
import sys
from typing import IO, Any, Deque, Dict, Iterable, List, Literal, Optional, Set, Tuple, Union, cast

import kconfiglib

parser = argparse.ArgumentParser()
parser.add_argument(
    '-i',
    '--input-diffconfig',
    action='store',
    type=argparse.FileType('r'),
    default=sys.stdin,
    help='Where to read the diffconfig from (default stdin)'
)
parser.add_argument(
    '-c',
    '--base-config',
    action='store',
    type=str,
    default=None,
    help='A base config to enable output of Y->N markers'
)
parser.add_argument(
    '-a',
    '--apply',
    action='store_true',
    help='Apply as many provided changes as possible, and rewrite the provided '
    'base-config.  Any remaining settings will be output in the usual format.'
)
parser.add_argument(
    '-M',
    '--discard-module-downgrade',
    action='store_true',
    help='Ignore and discard any diffconfig entries that change an entry marked "Y" to "m".'
)
parser.add_argument(
    '--hide-matching',
    action='store_true',
    help='Do not output any diffconfig entries that match the existing value. '
    'They will still be considered for --apply. '
    '(WARNING: This may lose information for symbols with dynamic defaults.)'
)
parser.add_argument(
    '-w', '--column-width', action='store', type=int, default=40, help='The width of the first column in the output.'
)
parser.add_argument(
    '-S',
    '--srctree',
    action='store',
    type=str,
    default=None,
    help='The path to the kernel source tree (overrides srctree= env)'
)
parser.add_argument(
    '-A',
    '--arch',
    action='store',
    type=str,
    default=None,
    help='The kernel architecture to use (overrides ARCH= and SRCARCH= env)'
)
ARGS = parser.parse_args()
del parser

os.environ.setdefault('CC', 'gcc')
if ARGS.arch is not None:
	os.environ['ARCH'] = ARGS.arch
	os.environ['SRCARCH'] = ARGS.arch
if ARGS.srctree is not None:
	os.environ['srctree'] = ARGS.srctree
	if 'KERNELVERSION' not in os.environ:
		os.environ['KERNELVERSION'] = subprocess.check_output(['make', 'kernelversion'],
		                                                      cwd=ARGS.srctree).decode('utf8')

if ARGS.discard_module_downgrade and not ARGS.base_config:
	print('Unable to run --discard-module-downgrade without a --base-config.', file=sys.stderr)
	raise SystemExit(1)

if ARGS.apply and not ARGS.base_config:
	print('Unable to run --apply without a --base-config.', file=sys.stderr)
	raise SystemExit(1)


def wrap_str(contents: str, ends: str) -> str:
	'''
	Wrap `contents` with the characters in `ends`, which must be even-length,
	and will be divided.
	'''
	endlen = len(ends)
	if (endlen % 2) != 0:
		raise ValueError('Cannot wrap a string with more or less than two end-caps.')
	first_end = ends[:endlen // 2]
	last_end = ends[endlen // 2:]
	return first_end + contents + last_end


@functools.total_ordering
class ConfigValue(object):
	N: 'ConfigValue'
	M: 'ConfigValue'
	Y: 'ConfigValue'

	__value: str
	__type: int

	def __init__(self, value: Union[str, int], type: Optional[int] = None):
		if value is None:
			raise ValueError('NoneType is not supported.')
		if type is None:
			# This is raw from a config file.
			# Do our best to auto-detect it properly.
			if isinstance(value, int):
				raise ValueError('Integer values must specify a type.')
			if value == '':
				self.__value = 'n'
				self.__type = kconfiglib.TRISTATE
			elif value.lower() in 'nmy':
				self.__value = value.lower()
				self.__type = kconfiglib.TRISTATE
			elif re.match('^[0-9]+$', value, re.I) is not None:
				self.__value = value
				self.__type = kconfiglib.INT
			elif re.match('^0x[0-9a-f]+$', value, re.I) is not None:
				self.__value = value
				self.__type = kconfiglib.HEX
			elif len(value) >= 2 and value[0] == '"' and value[-1] == '"':
				self.__value = kconfiglib.unescape(value[1:-1])
				self.__type = kconfiglib.STRING
			else:
				raise ValueError('Unable to interpret raw value ' + repr(value))
		elif type in (kconfiglib.BOOL, kconfiglib.TRISTATE) and isinstance(value, int):
			if value not in (0, 1, 2):
				raise ValueError(f'Integer values for {kconfiglib.TYPE_TO_STR[type]} must be in [0,2].')
			self.__value = {0: 'n', 1: 'm', 2: 'y'}[value]
			self.__type = type
		else:
			self.__value = str(value)
			self.__type = type

	def __repr__(self) -> str:
		return f'ConfigValue<{kconfiglib.TYPE_TO_STR.get(self.__type,"??")}>({str(self.__value)!r})'

	def assign_to(self, sym: kconfiglib.Symbol, *, throw: bool = True) -> bool:
		assert isinstance(sym, kconfiglib.Symbol)
		if sym.type in (kconfiglib.BOOL, kconfiglib.TRISTATE):
			if throw and self.__type not in (kconfiglib.BOOL, kconfiglib.TRISTATE):
				raise ValueError(f'Cannot assign {self!r} to {sym.name} (of type {kconfiglib.TYPE_TO_STR[sym.type]}).')
			if int(self) in sym.assignable:
				return sym.set_value(self.__value)
		elif sym.type == kconfiglib.STRING:
			if throw and self.__type != kconfiglib.STRING:
				raise ValueError(f'Cannot assign {self!r} to {sym.name} (of type {kconfiglib.TYPE_TO_STR[sym.type]}).')
			if sym.visibility > 0:
				return sym.set_value(self.__value)
		elif sym.type in (kconfiglib.INT, kconfiglib.HEX):
			if throw and self.__type not in (kconfiglib.INT, kconfiglib.HEX):
				raise ValueError(f'Cannot assign {self!r} to {sym.name} (of type {kconfiglib.TYPE_TO_STR[sym.type]}).')
			if sym.visibility > 0:
				return sym.set_value(self.__value)
		elif throw:
			raise ValueError(f'Cannot assign {self!r} to {sym.name} (of type {kconfiglib.TYPE_TO_STR[sym.type]}).')
		return False

	@property
	def escaped(self) -> str:
		if self.__type == kconfiglib.STRING:
			return wrap_str(kconfiglib.escape(self.__value), '""')
		return self.__value

	def __str__(self) -> str:
		return str(self.__value)

	def __int__(self) -> int:
		if self.__type in (kconfiglib.BOOL, kconfiglib.TRISTATE):
			return {'': 0, 'n': 0, 'm': 1, 'y': 2}[self.__value.lower()]
		elif self.__type == kconfiglib.INT:
			return int(self.__value, 10)
		elif self.__type == kconfiglib.HEX:
			return int(self.__value, 16)
		raise ValueError(f'The value {self!r} is not representable as an int.')

	def __to_comparables(self, other: Union['ConfigValue', int, str]) -> Tuple[Any, Any]:
		if self.__type == kconfiglib.STRING:
			if isinstance(other, ConfigValue) and other.__type == kconfiglib.STRING:
				other = str(other)
			if not isinstance(other, str):
				raise NotImplementedError()
			return str(self), str(other)
		elif self.__type in (kconfiglib.BOOL, kconfiglib.TRISTATE):
			if isinstance(other, ConfigValue) and other.__type in (kconfiglib.BOOL, kconfiglib.TRISTATE):
				other = int(other)
			if isinstance(other, str) and other.lower() in ('', 'n', 'm', 'y'):
				other = {'': 0, 'n': 0, 'm': 1, 'y': 2}[other.lower()]
			if not isinstance(other, int):
				raise NotImplementedError()
			return int(self), int(other)
		elif self.__type in (kconfiglib.INT, kconfiglib.HEX):
			if isinstance(other, ConfigValue) and other.__type in (kconfiglib.INT, kconfiglib.HEX):
				other = int(other)
			if not isinstance(other, int):
				raise NotImplementedError()
			return int(self), int(other)
		raise NotImplementedError()

	def __le__(self, other: Union['ConfigValue', int, str]) -> bool:
		try:
			s, o = self.__to_comparables(other)
			return s <= o
		except NotImplementedError:
			return NotImplemented

	def __eq__(self, other: Union['ConfigValue', int, str]) -> bool:
		try:
			s, o = self.__to_comparables(other)
			return s == o
		except NotImplementedError:
			return NotImplemented

	def __ne__(self, other: Union['ConfigValue', int, str]) -> bool:
		try:
			s, o = self.__to_comparables(other)
			return s != o
		except NotImplementedError:
			return NotImplemented


ConfigValue.N = ConfigValue(0, kconfiglib.TRISTATE)
ConfigValue.M = ConfigValue(1, kconfiglib.TRISTATE)
ConfigValue.Y = ConfigValue(2, kconfiglib.TRISTATE)


class ConfigNode(object):
	symstr: str
	kconfig_node: Optional[kconfiglib.MenuNode]
	path: Tuple[kconfiglib.MenuNode, ...]
	sort_key: int
	desired_value: ConfigValue

	def __init__(
	    self,
	    symstr: str,
	    path: List[kconfiglib.MenuNode],
	    sort_key: int = -1,
	    desired_value: ConfigValue = ConfigValue.N
	):
		self.symstr = symstr
		self.path = tuple(path)
		self.kconfig_node = self.path[-1] if self.path else None
		self.sort_key = sort_key
		self.desired_value = desired_value

	def __repr__(self) -> str:
		path = [node.prompt[0] if node.prompt else None for node in self.path]
		return f"ConfigNode(symstr={self.symstr!r}, path={path!r}, desired_value={self.desired_value!r})"

	def is_desired_a_downgrade_to_module(self) -> bool:
		if self.kconfig_node is None:
			return False
		if isinstance(self.kconfig_node.item, int):
			return False  # Not the right type of node to evaluate.
		if self.kconfig_node.item.type not in (kconfiglib.BOOL, kconfiglib.TRISTATE):
			return False  # Not the right type of node to evaluate.
		if self.kconfig_node.item.tri_value == 2 and self.desired_value == ConfigValue.M:
			return True
		return False


def load_diffconfig(file: IO[str]) -> Dict[str, ConfigValue]:
	desired_symbols: Dict[str, ConfigValue] = {}
	for line in file:
		# r'^(?:#\s.*)?CONFIG_(?P<symbol>[^ =]+)(?:=(?P<value>.*)|(?P<unset> is not set))'
		# r'^(?:CONFIG_(?P<set_symbol>[^ =]+)=(?P<value>.*)|# CONFIG_(?P<unset_symbol>[^ =]+) is not set.*)'
		m = re.search(
		    r'^(?:(?:CONFIG_)?(?P<set_symbol>[^\s=]+)=(?P<value>(?!")\S*|"(?:[^\\"]|\\.)*")|# (?:CONFIG_)?(?P<unset_symbol>[^\s=]+) is not set)',
		    line
		)
		if m is None:
			continue
		if m.group('set_symbol'):
			desired_symbols[m.group('set_symbol')] = ConfigValue(m.group('value'))
		else:
			desired_symbols[m.group('unset_symbol')] = ConfigValue.N
	return desired_symbols


def locate_nodes(kconf: kconfiglib.Kconfig, desired_symbols: Dict[str, ConfigValue]) -> List[ConfigNode]:
	'''
	Find all nodes in the set of desired symbols by walking the menu in its natural order.
	Insert any desired symbols that were not found at the top of the list.
	'''

	symbols: List[ConfigNode] = []
	located_symbols: Set[str] = set()
	serial = 0
	stack: List[kconfiglib.MenuNode] = [kconf.top_node]
	while stack:
		serial += 1
		node = stack[-1]

		sym = node.item  # Maybe?
		if isinstance(sym, kconfiglib.Symbol):
			if sym.name in desired_symbols:
				located_symbols.add(sym.name)
				symbols.append(ConfigNode(sym.name, list(stack[1:]), serial, desired_symbols[sym.name]))

		# Onward!
		if node.list is not None:
			# Process the next child
			stack.append(node.list)
		else:
			# No next child, we're done with this node.
			while stack and stack[-1].next is None:
				# Descend as required to find something with a next sibling.
				stack.pop()
			# If there's anything left at all, follow to its next sibling
			if stack:
				stack.append(stack.pop().next)

	for sym, val in desired_symbols.items():
		if sym in located_symbols:
			continue
		symbols.append(ConfigNode(sym, [], -1, val))

	symbols.sort(key=lambda node: node.sort_key)
	return symbols


def apply_configs(kconf: kconfiglib.Kconfig, configs: List[ConfigNode]) -> None:
	# Iterate our (assumed to be in order) list of config nodes, and apply all
	# values possible.
	for node in configs:
		if node.kconfig_node is None:
			continue
		sym = node.kconfig_node.item
		assert isinstance(sym, kconfiglib.Symbol)
		try:
			node.desired_value.assign_to(sym)
		except ValueError:
			pass


def filter_applied(kconf: kconfiglib.Kconfig, configs: List[ConfigNode]) -> List[ConfigNode]:
	# Now determine which values do NOT MATCH their desired, and return only those entries.
	remaining_configs: List[ConfigNode] = []
	for node in configs:
		if node.kconfig_node is None:
			remaining_configs.append(node)
			continue
		sym = node.kconfig_node.item
		assert isinstance(sym, kconfiglib.Symbol)
		try:
			if sym.user_value is None or node.desired_value != ConfigValue(cast(Union[str, int], sym.user_value),
			                                                               sym.type):
				remaining_configs.append(node)
		except ValueError:
			remaining_configs.append(node)

	return remaining_configs


def render(fd: IO[str], confignodes: List[ConfigNode]) -> None:
	current_section: Tuple[kconfiglib.MenuNode, ...] = tuple()

	def render_path(path: Iterable[kconfiglib.MenuNode]) -> str:
		names = [node.prompt[0].strip() if node and node.prompt else '?' for node in path]
		return ' / '.join(name for name in names if name.strip())

	if ARGS.base_config:
		fmt = '{{sym:{column_width}s}} # [{{initial:s}} -> {{final:s}}]  {{label}}\n'.format(
		    column_width=ARGS.column_width
		)
	else:
		fmt = '{{sym:{column_width}s}} # {{label}}\n'.format(column_width=ARGS.column_width)
	nmy_upper = lambda x: x.upper() if x in 'nmy' else x
	nmy_lower = lambda x: x.lower() if x in 'NMY' else x

	for node in confignodes:
		if node.path[:-1] != current_section:
			# if current_section:
			# 	fd.write(f'## End Section:   {render_path(current_section)}\n')
			current_section = node.path[:-1]
			if current_section:
				fd.write('\n')
				fd.write('\n')
				fd.write(f'## Begin Section: {render_path(current_section)}\n')
				fd.write('\n')
		renderstr = ''
		if node.desired_value == ConfigValue.N:
			renderstr = f'# {node.symstr} is not set'
		else:
			renderstr = f'{node.symstr}={node.desired_value.escaped}'
		name = '(Unknown Symbol)'
		initial: str = '?'
		final: str = node.desired_value.escaped
		if node.kconfig_node:
			sym = node.kconfig_node.item
			if isinstance(sym, kconfiglib.Symbol):
				if ARGS.hide_matching:
					if sym.str_value and node.desired_value == ConfigValue(cast(Union[str, int], sym.str_value),
					                                                       sym.type):
						continue  # Don't output this.
				name = render_path([node.kconfig_node])
				initial = ConfigValue(sym.str_value, sym.type).escaped
		if len(initial) > 6:
			initial = initial[:4] + '..'
		if len(final) > 6:
			final = final[:4] + '..'
		fd.write(fmt.format(sym=renderstr, label=name, initial=nmy_lower(initial), final=nmy_upper(final)))


def main() -> None:
	kconfig = kconfiglib.Kconfig()
	if ARGS.base_config:
		kconfig.load_config(ARGS.base_config)
	diffconfig = load_diffconfig(ARGS.input_diffconfig)
	confignodes = locate_nodes(kconfig, diffconfig)
	if ARGS.discard_module_downgrade:
		len_pre = len(confignodes)
		confignodes = [node for node in confignodes if not node.is_desired_a_downgrade_to_module()]
		len_post = len(confignodes)
		print(f'Discarded {len_pre-len_post} config entries that would have downgraded a Y to an M.', file=sys.stderr)
	if ARGS.apply:
		neverfixed: Set[ConfigNode] = set(confignodes)
		pass_count: int = 0
		while True:
			pass_count += 1
			apply_configs(kconfig, confignodes)
			kconfig.write_config(ARGS.base_config)
			kconfig.load_config(ARGS.base_config)
			remaining_confignodes = filter_applied(kconfig, confignodes)
			neverfixed_before = len([n for n in neverfixed if n.sort_key > 0])
			neverfixed &= set(remaining_confignodes)
			neverfixed_after = len([n for n in neverfixed if n.sort_key > 0])
			print(
			    f'Pass {pass_count}: {len([n for n in remaining_confignodes if n.sort_key > 0])} valid nodes.  {neverfixed_before} -> {neverfixed_after} unresolvable.',
			    file=sys.stderr,
			)
			if neverfixed_before == neverfixed_after:
				# We didn't fix anything on this pass that we hadn't fixed before.
				# It seems we can't resolve the remainder.
				#
				# This is not a count of how many are left, but how many have
				# NEVER been correct, to eliminate the possibility that
				# metastability will deadlock us.
				break
		confignodes = remaining_confignodes
	render(sys.stdout, confignodes)


if __name__ == '__main__' and not sys.flags.interactive:
	main()
