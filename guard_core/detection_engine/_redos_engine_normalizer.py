# CPython 3.14 compiles a character class that holds every character, such as
# `[\s\S]`, into the any-character opcode, which a fixed repeat skips in one step; 3.10
# to 3.13 loop over it once per character, so `[\s\S]{4095}[^☃]` costs about a second
# at 32000 characters there and about a quarter of a millisecond on 3.14. A pattern
# must get one verdict on every supported Python, so the timing children compile the
# way the older engines do: this source, run first in a child, keeps the complete
# class a class. It touches nothing when the interpreter has no such shortcut.
ENGINE_NORMALIZER_SOURCE = """\
class _NeverTheCompleteCharset(list):
    __eq__ = lambda self, other: False
    __ne__ = lambda self, other: True
    __hash__ = None
_compiler = getattr(re, '_compiler', None)
if hasattr(_compiler, '_CHARSET_ALL'):
    _compiler._CHARSET_ALL = _NeverTheCompleteCharset(_compiler._CHARSET_ALL)
"""
