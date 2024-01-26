#!/usr/bin/env python3
"""Parser for YAML-like structure that is error tolerant."""
from collections.abc import Generator
from typing import Optional, Union

from .node import Node, NodeType
from .parser_multi_lines import group_multi_lines


def is_valid_first_character_for_a_variable(char: str) -> bool:
    """Assuming variable names cannot start with a digit."""
    return char.isascii() and (char.isalpha() or char in ["-", "_"])


def is_valid_variable_character(char: str) -> bool:
    """Return True if the character can be part of an Ansible variable name."""
    # note: isnumeric accepts a wider range than just the 0-9
    return char.isascii() and (char.isalpha() or char.isnumeric() or char in ["-", "_"])


def is_field_value_sep(char: str) -> bool:
    """Return True if the character is : or =."""
    return char in [":", "="]


def breakup_elements(block: str) -> Node:
    # pylint: disable=too-many-branches
    # pylint: disable=too-many-statements
    """Digest a text block an return a list of Nodes that will be simplified later."""
    root_node = Node(0)
    root_node.type = NodeType.quoted_string_holder
    current_node = root_node
    for pos, c in enumerate(block):  # pylint: disable=invalid-name
        previous_node = current_node
        current_node = Node(-1)  # -1 == undef, the variable will be reset
        if c == "\\":
            new_node = Node(pos)
            new_node.attach(previous=previous_node)
            new_node.type = NodeType.backslash
            current_node = new_node
        elif c in ["'", '"']:
            is_protected = previous_node.type is NodeType.backslash

            holder: Optional[Node] = previous_node
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
                new_node.attach(previous=previous_node)
                new_node.type = NodeType.quoted_string_closing
                holder.closed_by = new_node
                current_node = new_node
            else:
                new_node = Node(pos)
                new_node.type = NodeType.quoted_string_holder
                new_node.is_protected = is_protected
                new_node.attach(previous=previous_node)
                current_node = new_node
        elif is_valid_first_character_for_a_variable(c):
            if previous_node.type is NodeType.field:
                current_node = previous_node
            else:
                new_node = Node(pos)
                new_node.attach(previous=previous_node)
                new_node.type = NodeType.field
                current_node = new_node
        elif is_valid_variable_character(c):
            if previous_node.type is NodeType.field:
                current_node = previous_node
            else:
                new_node = Node(pos)
                new_node.attach(previous=previous_node)
                new_node.type = NodeType.field
                current_node = new_node
        elif is_field_value_sep(c):
            new_node = Node(pos)
            new_node.attach(previous=previous_node)
            new_node.type = NodeType.separator
            current_node = new_node
        elif c == "\n":
            new_node = Node(pos)
            new_node.attach(previous=previous_node)
            new_node.type = NodeType.new_line
            current_node = new_node
        elif c == " ":
            new_node = Node(pos)
            new_node.attach(previous=previous_node)
            new_node.type = NodeType.space
            current_node = new_node
        elif previous_node.type is not NodeType.unknown:
            new_node = Node(pos)
            new_node.attach(previous=previous_node)
            current_node = new_node
        else:
            # Should never happend
            new_node = Node(pos)
            new_node.attach(previous=previous_node)
            current_node = new_node

        current_node.text += c
    return root_node


def parse_raw_block(block: str) -> Node:
    """Return block without any potential secrets."""
    root_node = breakup_elements(block)
    close_quotes(root_node)
    group_multi_lines(root_node)
    handle_backslashes(root_node)
    combinate_value_fields(root_node)
    identify_secrets(root_node)
    return root_node


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
    """Combinate the unquoted value strings."""
    mergable_types = [NodeType.space, NodeType.field, NodeType.unknown, NodeType.space]

    def _is_a_new_key_value(node: Node) -> bool:
        """Check if the current node is actually the beginning of a new secret key/value."""
        if not node.next:
            return False

        current = node.next
        if current.type is not NodeType.space:
            return False

        while current.type == NodeType.space:
            if current.next is None:
                return False
            current = current.next

        # if we've got a separator after the field, we prefer to preserve
        # it. e.g: secret1: foo secret2: bar, secret1 and secret2 are two distinct seecrets.
        if current and current.type is NodeType.field and current.next and current.next.text == ":":
            return True
        return False

    def _find_separator_node(node: Node) -> Union[None, Node]:
        while node and node.next:
            if node.next.type is NodeType.space:
                node = node.next
            elif node.next and node.next.type is NodeType.separator:
                return node.next
            else:
                return None
        return None

    current_node = root_node
    while current_node and current_node.next:
        current_node = current_node.next
        if current_node.type is not NodeType.field:
            continue
        if not current_node.is_password_field_name():
            continue

        secret_content_ptr = current_node.get_secret()
        if not secret_content_ptr:
            continue
        separator = _find_separator_node(current_node)
        if not separator:
            continue
        if secret_content_ptr.type is NodeType.quoted_string_holder:
            current_node = secret_content_ptr.closed_by
            continue
        while (
            secret_content_ptr.next
            and (
                (secret_content_ptr.next.type in mergable_types)
                or (
                    secret_content_ptr.next.type is NodeType.separator
                    and secret_content_ptr.next.text != separator.text
                )
            )
            and not _is_a_new_key_value(secret_content_ptr)
        ):
            secret_content_ptr.merge_with_next()


def flatten(node: Node) -> Generator[Node, None, None]:
    """Iterator that go through each nodes and follow the original text order."""
    current = node
    while current:
        yield current
        if not current.next:
            break
        current = current.next


def identify_secrets(root_node: Node) -> None:
    """Remove the secret fields from a series of nodes."""

    def identify_quoted_string(node: Node, secret_node: Node) -> None:
        assert secret_node.closed_by  # for mypy # noqa: S101
        cursor = secret_node.next
        while cursor and cursor != secret_node.closed_by and cursor.next != secret_node.closed_by:
            cursor.merge_with_next()
        if secret_node.next and secret_node.next != secret_node.closed_by:
            secret_node.next.secret_value_of = node
            secret_node.next.type = NodeType.secret
        if secret_node.next:
            identify_secrets(secret_node.next)

    def identify_regular_field(node: Node, secret_node: Node) -> None:
        assert secret_node.holder  # for mypy # noqa: S101
        secret_node.secret_value_of = node
        secret_node.type = NodeType.secret
        if secret_node.next:
            identify_secrets(secret_node.next)

    for node in flatten(root_node):
        if node.type is not NodeType.field:
            continue
        if not node.is_password_field_name():
            continue

        secret_node = node.get_secret()
        if not secret_node:
            continue

        if secret_node.type is NodeType.quoted_string_holder:
            return identify_quoted_string(node, secret_node)
        return identify_regular_field(node, secret_node)
