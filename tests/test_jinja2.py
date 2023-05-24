#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring

from ansible_anonymizer.jinja2 import str_jinja2_variable_name


def test_str_jinja2_variable_name_leading_underscore():
    assert str_jinja2_variable_name("-foo-BAR") == "foo_bar"
