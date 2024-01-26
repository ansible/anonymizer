#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring

from ansible_anonymizer.node import NodeType
from ansible_anonymizer.parser import (
    breakup_elements,
    flatten,
)
from ansible_anonymizer.parser_multi_lines import (
    group_multi_lines,
)


def test_parser_multilines():
    sample = "a: |\n  my\n  multi\n  line\n"
    root_node = breakup_elements(sample)
    nodes_found_before = list(flatten(root_node))
    assert [n.type for n in nodes_found_before] == [
        NodeType.quoted_string_holder,
        NodeType.field,
        NodeType.separator,
        NodeType.space,
        NodeType.unknown,
        NodeType.new_line,
        NodeType.space,
        NodeType.space,
        NodeType.field,
        NodeType.new_line,
        NodeType.space,
        NodeType.space,
        NodeType.field,
        NodeType.new_line,
        NodeType.space,
        NodeType.space,
        NodeType.field,
        NodeType.new_line,
    ]
    group_multi_lines(root_node)
    nodes_found_after = list(flatten(root_node))

    assert [
        NodeType.quoted_string_holder,
        NodeType.field,
        NodeType.separator,
        NodeType.space,
        NodeType.field,
        NodeType.new_line,
    ] == [n.type for n in nodes_found_after]
    assert nodes_found_after[-2].text == "|\n  my\n  multi\n  line"
    assert nodes_found_after[-1].text == "\n"


def test_parser_empty_multilines():
    sample = "a: |\nb: zz"
    root_node = breakup_elements(sample)
    nodes_found_before = list(flatten(root_node))
    group_multi_lines(root_node)
    nodes_found_after = list(flatten(root_node))
    assert [n.type for n in nodes_found_before] == [n.type for n in nodes_found_after]
