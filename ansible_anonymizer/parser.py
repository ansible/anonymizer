#!/usr/bin/env python3

from collections.abc import Generator
from enum import Enum
from typing import Literal, Optional, Union

from ansible_anonymizer.field_checks import is_password_field_name, is_path
from ansible_anonymizer.jinja2 import str_jinja2_variable_name

"""Parser for YAML-like structure that tolerate error."""

quote_t = Literal['"', "'"]


class NodeType(Enum):
    """The different type of Node returned by the parser."""

    unknown = 0
    field = 1
    separator = 2
    quoted_string_holder = 3
    quoted_string_closing = 4
    new_line = 5
    space = 6
    securized = 8
    backslash = 9
    deleted = 10


class ParserError(Exception):
    """Unexpected behaviour."""


class Node:
    """A element returned by the parser."""

    def __init__(self, begin_at: int) -> None:
        self.previous: Optional["Node"] = None
        self.next: Optional["Node"] = None
        self.begin_at: int = begin_at
        self.end_at: int
        self.text: str = ""
        self.type: NodeType = NodeType.unknown
        self.holder: Optional["Node"] = None

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
        print(f"FIELD={self.text}")
        while candidate:
            print(f"CANDIDATE: {candidate.text} ({candidate.type})")
            if candidate.type is NodeType.space:
                pass
            elif candidate.type is NodeType.quoted_string_closing:
                if candidate.holder is not self.holder:
                    raise ParserError()
            elif has_separator:
                if candidate.type is NodeType.securized:
                    # We should not come back on the same node
                    raise ParserError
                if candidate.type is NodeType.field:
                    return candidate
                if candidate.type is NodeType.unknown:
                    return candidate
                if candidate.type is NodeType.quoted_string_holder:
                    return candidate
                else:
                    return None
            elif candidate.type is NodeType.separator:
                has_separator = True
                print("HAS SEP")
            else:
                return None
            candidate = candidate.next
        return None

    def is_password_field_name(self) -> bool:
        """Return True if the field name matches the DENYLIST_REGEX regex."""
        return is_password_field_name(self.text)

    def __str__(self) -> str:
        """Expose the Node as a string."""
        return f"TEXT={self.text}, BEGIN_AT={self.begin_at}, TYPE={self.type}"


def is_valid_first_character_for_a_variable(c: str) -> bool:
    """Assuming variable names cannot start with a digit."""
    return c.isascii() and (c.isalpha() or c in ["-", "_"])


def is_valid_variable_character(c: str) -> bool:
    # note: isnumeric accepts a wider range than just the 0-9
    return c.isascii() and (c.isalpha() or c.isnumeric() or c in ["-", "_"])


def is_field_value_sep(c: str) -> bool:
    return c in [":", "="]


def parser(block: str) -> Node:
    root_node = Node(0)
    root_node.type = NodeType.quoted_string_holder
    current_node = root_node
    for pos, c in enumerate(block):
        if c == "\\":
            new_node = Node(pos)
            new_node.attach(previous=current_node)
            new_node.type = NodeType.backslash
            current_node = new_node
        elif c in ["'", '"']:
            is_protected = current_node.type is NodeType.backslash

            holder = current_node.holder
            while holder:
                if (
                    holder.text == c
                    and holder.is_protected is is_protected
                    and not holder.closed_by
                ):
                    break
                holder = holder.holder

            if holder:
                new_node = Node(pos)
                new_node.attach(previous=current_node)
                new_node.type = NodeType.quoted_string_closing
                holder.closed_by = new_node
                current_node = new_node
            else:
                new_node = Node(pos)
                new_node.type = NodeType.quoted_string_holder
                new_node.is_protected = is_protected
                new_node.attach(previous=current_node)
                current_node = new_node
        elif is_valid_first_character_for_a_variable(c):
            if current_node.type is NodeType.field:
                pass
            else:
                new_node = Node(pos)
                new_node.attach(previous=current_node)
                new_node.type = NodeType.field
                current_node = new_node
        elif is_valid_variable_character(c):
            if current_node.type is NodeType.field:
                pass
            elif current_node.type is not NodeType.unknown:
                new_node = Node(pos)
                new_node.attach(previous=current_node)
                current_node = new_node
        elif is_field_value_sep(c):
            new_node = Node(pos)
            new_node.attach(previous=current_node)
            new_node.type = NodeType.separator
            current_node = new_node
        elif c == "\n":
            new_node = Node(pos)
            new_node.attach(previous=current_node)
            new_node.type = NodeType.new_line
            current_node = new_node
        elif c == " ":
            new_node = Node(pos)
            new_node.attach(previous=current_node)
            new_node.type = NodeType.space
            current_node = new_node
        else:
            if current_node.type is not NodeType.unknown:
                new_node = Node(pos)
                new_node.attach(previous=current_node)
                current_node = new_node

        current_node.text += c
    return root_node


def hide_secrets(block: str) -> str:
    root_node = parser(block)
    close_quotes(root_node)
    handle_backslashes(root_node)
    # Group substring with unknown and field types
    # combinate_fields(root_node)
    combinate_value_fields(root_node)

    hide_secret_fields(root_node)

    output = ""
    for node in flatten(root_node):
        output += node.text
    return output


def close_quotes(root_node: Node) -> None:
    """Close the quotes that are still opened."""
    current_node = root_node.next
    while current_node:
        if current_node.type is NodeType.quoted_string_holder and not current_node.closed_by:
            current_node.type = NodeType.unknown
        current_node = current_node.next


def handle_backslashes(root_node: Node) -> None:
    """
    Convert the backslashes are regular unkown leaves.

    The backslash type is only used to identify the protected quotes.
    """
    current_node = root_node.next
    while current_node:
        if current_node.type is not NodeType.backslash:
            pass
        elif (
            current_node.next
            and current_node.next.type
            in [NodeType.quoted_string_holder, NodeType.quoted_string_closing]
            and current_node.holder is current_node.next.holder
        ):
            current_node.next.text = current_node.text + current_node.next.text
            if current_node.previous:
                current_node.previous.next = current_node.next
                current_node.next.previous = current_node.previous
            current_node.text = "KILLED"
            current_node.type = NodeType.deleted
            current_node = current_node.next
        else:
            current_node.type = NodeType.unknown
        current_node = current_node.next


def combinate_value_fields(root_node: Node) -> None:
    """
    Merge the unquoted value fields.

    In YAML, a value can be an unprotected string with spaces. Internally
    the parser represent such series of spaces and fields as different
    Node objects. Since all these objects are actually one single value,
    we merge them together.
    """
    current_node = root_node
    mergable_types = [NodeType.space, NodeType.field, NodeType.unknown]
    post_sep = False
    while current_node:
        if post_sep:
            # We ignore the first space after the : sign
            if current_node.type is NodeType.space and current_node.next:
                current_node = current_node.next

            while (
                current_node.type in mergable_types
                and current_node.next
                and current_node.next.type in mergable_types
                and not current_node.next.is_password_field_name()
            ):
                current_node.type = NodeType.unknown
                current_node.text += current_node.next.text
                current_node.next = current_node.next.next
                if current_node.next:
                    current_node.next.previous = current_node

        elif current_node.type is NodeType.separator and current_node.text == ":":
            post_sep = True
        if current_node.next is None:
            break
        current_node = current_node.next


def print_node(root_node: Node) -> None:
    for node in flatten(root_node):
        print(node, end="")


def flatten(node: Node) -> Generator[Node, None, None]:
    n = node
    while n:
        yield n
        if not n.next:
            break
        n = n.next


def hide_secret_fields(root_node: Node) -> None:
    def hide_quoted_string(node: Node, secret_node: Node) -> None:
        assert secret_node.closed_by  # for mypy # noqa: S101
        secret_node.next = secret_node.closed_by.next
        secret_node.type = NodeType.securized
        secret_node.text = (
            f"{secret_node.text}{{{{ {str_jinja2_variable_name(node.text)} }}}}{secret_node.text}"
        )
        if secret_node.next:
            return hide_secret_fields(secret_node.next)

    def hide_regular_field(node: Node, secret_node: Node) -> None:
        secret_node.type = NodeType.securized
        assert secret_node.holder  # for mypy # noqa: S101
        quote = "" if secret_node.holder.text else '"'
        secret_node.text = f"{quote}{{{{ {str_jinja2_variable_name(node.text)} }}}}{quote}"
        if secret_node.next:
            return hide_secret_fields(secret_node.next)

    for node in flatten(root_node):
        if node.type is not NodeType.field:
            continue
        if not node.is_password_field_name():
            continue

        secret_node = node.get_secret()
        if not secret_node:
            continue
        if is_path(secret_node.text):
            continue

        if secret_node.type is NodeType.quoted_string_holder:
            return hide_quoted_string(node, secret_node)
        else:
            return hide_regular_field(node, secret_node)
