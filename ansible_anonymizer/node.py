#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
from collections.abc import Generator
from enum import Enum
from typing import Optional, Union

from .field_checks import is_password_field_name


class ParserError(Exception):
    """Unexpected behaviour."""


class NodeType(Enum):
    """The different type of Node returned by the parser."""

    # pylint: disable=invalid-name

    unknown = 0
    field = 1
    separator = 2
    quoted_string_holder = 3
    quoted_string_closing = 4
    new_line = 5
    space = 6
    securized = 7
    backslash = 8
    deleted = 9
    secret = 10


class Node:
    # pylint: disable=too-many-instance-attributes
    """A element returned by the parser."""

    def __init__(self, begin_at: int) -> None:
        self.previous: Optional["Node"] = None
        self.next: Optional["Node"] = None
        self.begin_at: int = begin_at
        self.end_at: int
        self.text: str = ""
        self.type: NodeType = NodeType.unknown
        self.holder: Optional["Node"] = None
        # Node of the field that point on this secret
        self.secret_value_of: Optional["Node"] = None

        # NOTE: Fields only used with quoted strings (called `holder`)
        self.closed_by: Optional["Node"] = None
        self.sub: list["Node"] = []
        self.is_protected: bool = False

    def attach(self, previous: "Node") -> None:
        """Attach a new Node to the previous one in the series."""
        self.previous = previous
        previous.next = self
        holder = previous
        while holder:
            if holder.type is NodeType.quoted_string_holder and not holder.closed_by:
                holder.sub.append(self)
                self.holder = holder
                break
            if not holder.previous:
                break
            holder = holder.previous

    def get_secret(self) -> Union["Node", None]:
        """Identify the secret Node associated with the current Node."""
        candidate = self.next
        has_separator = False
        while candidate:
            if candidate.type is NodeType.space:
                pass
            elif candidate.type is NodeType.quoted_string_closing:
                pass
            elif has_separator:
                if candidate.type is NodeType.securized:
                    # We should not come back on the same node
                    raise ParserError
                if candidate.type in [
                    NodeType.field,
                    NodeType.unknown,
                    NodeType.quoted_string_holder,
                ]:
                    return candidate
                return None
            elif candidate.type is NodeType.separator:
                has_separator = True
            else:
                return None
            candidate = candidate.next
        return None

    def merge_with_next(self) -> None:
        """Merge the current node with the next one."""
        self.type = NodeType.unknown
        assert self.next  # for mypy # noqa: S101
        self.text += self.next.text
        self.next.type = NodeType.deleted
        self.next.text = "KILLED"
        self.next = self.next.next
        if self.next:
            self.next.previous = self

    def is_password_field_name(self) -> bool:
        """Return True if the field name matches the DENYLIST_REGEX regex."""
        return is_password_field_name(self.text)

    def __str__(self) -> str:
        """Expose the Node as a string."""
        return f"TEXT={self.text}, BEGIN_AT={self.begin_at}, TYPE={self.type}"

    def get_previous_nodes(self, limit: int = 0) -> Generator["Node", None, None]:
        """Return the nodes preceding the current one."""
        c = self.previous
        cpt = 0
        while c:
            yield c
            cpt += 1
            if limit and cpt >= limit:
                break
            c = c.previous

    def get_next_nodes(self, limit: int = 0) -> Generator["Node", None, None]:
        """Return the nodes following the current one."""
        c = self.next
        cpt = 0
        while c:
            yield c
            cpt += 1
            if limit and cpt >= limit:
                break
            c = c.next
