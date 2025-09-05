import sys
import typing

# Provides compatability for different Types of typehints

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self


_P = typing.ParamSpec("P")
_T = typing.TypeVar("_T")
