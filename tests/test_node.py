#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring

from ansible_anonymizer.node import NodeType
from ansible_anonymizer.parser import parse_raw_block


def test_get_previous():
    sample = """
    "aaa
       \\"passwd: bob\\""
    """
    root_node = parse_raw_block(sample)
    assert [n.type for n in root_node.get_previous_nodes()] == []
    assert [n.type for n in root_node.next.next.next.get_previous_nodes(limit=1)] == [
        NodeType.space
    ]
    assert [n.type for n in root_node.next.next.next.get_previous_nodes()] == [
        NodeType.space,
        NodeType.new_line,
        NodeType.quoted_string_holder,
    ]


def test_get_next():
    sample = """
    "aaa
       \\"passwd: bob\\""
    """
    root_node = parse_raw_block(sample)
    assert [n.type for n in root_node.get_next_nodes()][:3] == [
        NodeType.new_line,
        NodeType.space,
        NodeType.space,
    ]
    assert [n.type for n in root_node.get_next_nodes(limit=1)] == [NodeType.new_line]
