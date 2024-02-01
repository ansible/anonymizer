#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
"""Identify and merge the multilines nodes."""
from .node import Node, NodeType


class Line:
    """A wrapper class for a list of nodes that compose a line."""

    def __init__(self, space_indent_length: int, nodes: list[Node]) -> None:
        self.space_indent_length = space_indent_length
        self.content = ""
        for i in nodes:
            self.content += i.text
        self.nodes: list[Node] = nodes

    def get_last_node(self) -> Node:
        """Return the last node of the line."""
        return self.nodes[-1]


def is_beginning_of_multiline_block(node: Node) -> bool:
    if node.text not in ["|", ">"]:
        return False
    previous_nodes = list(reversed(list(node.get_previous_nodes(limit=3))))
    next_nodes = list(node.get_next_nodes(limit=2))
    if [n.type for n in previous_nodes] != [NodeType.field, NodeType.separator, NodeType.space]:
        return False
    if previous_nodes[1].text != ":":
        return False
    if [n.type for n in next_nodes] != [NodeType.new_line, NodeType.space]:
        return False
    return True


def read_one_line(node: Node) -> Line:
    space_indent_length: int = 0
    nodes: list[Node] = []

    c = node

    while c and c.next and c.type == NodeType.space:
        space_indent_length += len(c.text)
        nodes.append(c)
        c = c.next
    while c:
        nodes.append(c)
        if c.type == NodeType.new_line:
            break
        c = c.next
    return Line(space_indent_length, nodes)


def get_lines(node: Node) -> list[Line]:
    c = node.next  # Slip the first \n
    while c and c.next and c.type is NodeType.space:
        c = c.next
    if not (c and c.next):
        return []
    c = c.next
    first_line: Line = read_one_line(c)
    lines: list[Line] = [first_line]
    c = first_line.get_last_node()
    while c and c.next:
        new_line = read_one_line(c.next)
        if new_line.space_indent_length < first_line.space_indent_length:
            break
        lines.append(new_line)
        c = new_line.get_last_node()
    return lines


def group_multi_lines(node: Node) -> None:
    """Iterator that go through each nodes and follow the original text order."""
    current = node
    while current:
        if is_beginning_of_multiline_block(current):
            lines = get_lines(current)
            if not lines:
                current = current.next
                continue
            length = sum(len(i.nodes) for i in lines)
            for idx in range(length):
                if length == idx + 1 and current.next and current.next.type is NodeType.new_line:
                    break
                current.merge_with_next()
            current.type = NodeType.field
            # The if statement that should always be True because
            # is_beginning_of_multiline_block() was used first,
            # This is used for mypy/pyright to avoid the following error:
            # "previous" is not a known member of "None"
            if current.previous and current.previous.previous:
                current.secret_value_of = current.previous.previous.previous
        current = current.next
