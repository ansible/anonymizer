#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring

from textwrap import dedent

from ansible_anonymizer.parser import (
    NodeType,
    breakup_elements,
    combinate_value_fields,
    flatten,
    parse_raw_block,
)


def test_hide_secrets_trailing_secret():
    sample = "password1: foobar\npassword: barfoo"
    root_node = parse_raw_block(sample)
    passwords = {
        t.secret_value_of.text: t.text for t in flatten(root_node) if t.type is NodeType.secret
    }
    assert passwords == {"password1": "foobar", "password": "barfoo"}


def test_hide_secrets_quoted_field():
    sample = """
    "password9": "my_password10: maxplus"
    """
    root_node = parse_raw_block(sample)
    passwords = {
        t.secret_value_of.text: t.text for t in flatten(root_node) if t.type is NodeType.secret
    }
    assert passwords == {"password9": "my_password10: maxplus"}


def test_parse_secrets_unquoted_field():
    sample = """
    password9: "my_password10: maxplus"
    """
    root_node = parse_raw_block(sample)
    passwords = {
        t.secret_value_of.text: t.text for t in flatten(root_node) if t.type is NodeType.secret
    }
    assert passwords == {"password9": "my_password10: maxplus"}


def test_parse_secrets_pattern_within_quoted_string():
    sample = """
    'password9: "my_password10: maxplus"'
    """
    root_node = parse_raw_block(sample)
    passwords = {
        t.secret_value_of.text: t.text for t in flatten(root_node) if t.type is NodeType.secret
    }
    assert passwords == {"password9": "my_password10: maxplus"}


def test_parse_secrets_long_string():
    sample = """
    passwd: $6$j212wezy$7H/1LT4f9/N3wpgNunhsIqtMj62OKiS3nyNwuizouQc3u7MbYCarYeAHWYPYb2FT.lbioDm2RrkJPb9BZMN1O/
    """  # noqa: E501
    root_node = parse_raw_block(sample)
    passwords = {
        t.secret_value_of.text: t.text for t in flatten(root_node) if t.type is NodeType.secret
    }
    assert passwords == {
        "passwd": (
            "$6$j212wezy$7H/1LT4f9/N3wpgNunhsIqtMj62OKiS3nyNwuizo"
            "uQc3u7MbYCarYeAHWYPYb2FT.lbioDm2RrkJPb9BZMN1O/"
        )
    }


def test_parse_secrets_2_level_of_quotes():
    sample = """
    "aaa'
       passwd: bob'"
    """
    root_node = parse_raw_block(sample)
    passwords = {
        t.secret_value_of.text: t.text for t in flatten(root_node) if t.type is NodeType.secret
    }
    assert passwords == {"passwd": "bob"}


def test_parse_secrets_protected_double_quotes():
    sample = """
    "aaa
       \\"passwd: bob\\""
    """
    root_node = parse_raw_block(sample)
    passwords = {
        t.secret_value_of.text: t.text for t in flatten(root_node) if t.type is NodeType.secret
    }
    assert passwords == {"passwd": "bob"}


def test_parse_secrets_empty():
    sample = ""
    root_node = parse_raw_block(sample)
    nodes = list(flatten(root_node))
    assert len(nodes) == 1


def test_parse_secrets_field_only():
    sample = "passwd"
    root_node = parse_raw_block(sample)
    nodes = list(flatten(root_node))
    assert len(nodes) == 2
    assert nodes[-1].text == sample


def test_parse_secrets_vars_file():
    sample = """
    ansible_user: root
    ansible_host: esxi1-gw.ws.testing.ansible.com
    ansible_password: '!234AaAa56'
    """
    root_node = parse_raw_block(sample)
    passwords = {
        t.secret_value_of.text: t.text for t in flatten(root_node) if t.type is NodeType.secret
    }
    assert passwords == {"ansible_password": "!234AaAa56"}


def test_parse_secrets_unquoted_string():
    sample = """
    ansible_password: an unquoted string
    """
    root_node = parse_raw_block(dedent(sample))
    nodes = list(flatten(root_node))
    assert nodes[-2].text == "an unquoted string"
    assert nodes[-2].secret_value_of.text == "ansible_password"


def test_parse_secrets_multi_secrets():
    sample = """
    '(?i)password1:': "{{ _iosxr_password }}"
    "this is somethingpass: password2: else my_password3: 'password4: _Agaim': barfoo"
    password5: maxplus
    password6: "maxplus"
    password7: "my_password8: maxplus"
    "password9": "my_password10: maxplus"
    password11: "my_password12:
              maxplus"

    passwd: $6$j212wezy$7H/1LT4f9/N3wpgNunhsIqtMj62OKiS3nyNwuizouQc3u7MbYCarYeAHWYPYb2FT.lbioDm2RrkJPb9BZMN1O/
    """  # noqa: E501
    root_node = parse_raw_block(sample)
    passwords = {
        t.secret_value_of.text: t.text for t in flatten(root_node) if t.type is NodeType.secret
    }
    assert passwords == {
        "somethingpass": "password2",
        "my_password3": "password4: _Agaim",
        "password5": "maxplus",
        "password6": "maxplus",
        "password7": "my_password8: maxplus",
        "password9": "my_password10: maxplus",
        "password11": "my_password12:\n              maxplus",
        "passwd": (
            "$6$j212wezy$7H/1LT4f9/N3wpgNunhsIqtMj62OKiS3n"
            "yNwuizouQc3u7MbYCarYeAHWYPYb2FT.lbioDm2RrkJPb9"
            "BZMN1O/"
        ),
    }


def test_parser_simple_key_value_string():
    sample = 'config_reverseproxy_oauth_password: "passw0rd"'
    expectation = [
        ("", NodeType.quoted_string_holder),
        ("config_reverseproxy_oauth_password", NodeType.field),
        (":", NodeType.separator),
        (" ", NodeType.space),
        ('"', NodeType.quoted_string_holder),
        ("passw0rd", NodeType.field),
        ('"', NodeType.quoted_string_closing),
    ]
    root_node = breakup_elements(sample)
    expanded = [(c.text, c.type) for c in flatten(root_node)]
    assert expanded == expectation


def test_parser_multi_spaces_before_simple_key_value_string():
    sample = 'config_reverseproxy_oauth_password:      "passw0rd"'
    expectation = [
        ("", NodeType.quoted_string_holder),
        ("config_reverseproxy_oauth_password", NodeType.field),
        (":", NodeType.separator),
        (" ", NodeType.space),
        (" ", NodeType.space),
        (" ", NodeType.space),
        (" ", NodeType.space),
        (" ", NodeType.space),
        (" ", NodeType.space),
        ('"', NodeType.quoted_string_holder),
        ("passw0rd", NodeType.field),
        ('"', NodeType.quoted_string_closing),
    ]
    root_node = breakup_elements(sample)
    expanded = [(c.text, c.type) for c in flatten(root_node)]
    assert expanded == expectation


def test_parser_get_secret():
    sample = "config_reverseproxy_oauth_password: my_secret"
    root_node = breakup_elements(sample)
    list_of_nodes = list(flatten(root_node))
    field_name_node = list_of_nodes[1]
    assert field_name_node.text == "config_reverseproxy_oauth_password"
    assert field_name_node.get_secret().text == "my_secret"


def test_parser_get_secret_with_unquoted_special_chars():
    sample = "config_reverseproxy_oauth_password: %$#my_secret&"
    root_node = breakup_elements(sample)
    field_name_node = root_node.next
    assert field_name_node.text == "config_reverseproxy_oauth_password"
    # Without combinate_value_fields we only get the first node of the secret
    assert field_name_node.get_secret().text == "%"
    combinate_value_fields(root_node)
    assert field_name_node.get_secret().text == "%$#my_secret&"


def test_parser_get_secret_with_ini_file():
    sample = """
    [default]
    foo = bar
    key=value
    turbo_secret=@#%$%^&^^ 645

    [section.bar]
    George = # a comment
    """
    root_node = breakup_elements(dedent(sample))
    secret_node = [n for n in flatten(root_node) if n.text == "turbo_secret"][0]
    # Without combinate_value_fields we only get the first node of the secret
    combinate_value_fields(root_node)
    assert secret_node.get_secret().text == "@#%$%^&^^ 645"


def test_combinate_value_fields():
    sample = "config_reverseproxy_oauth_password: my!secret%$!"
    root_node = breakup_elements(sample)
    assert len(list(flatten(root_node))) == 10
    combinate_value_fields(root_node)
    assert len(list(flatten(root_node))) == 5


def test_hide_secrets_multi_spaces_before_simple_key_value_string():
    sample = 'config_reverseproxy_oauth_password:      "passw0rd"'
    root_node = parse_raw_block(sample)
    nodes = list(flatten(root_node))
    assert nodes[-2].text == "passw0rd"
    assert nodes[-2].type is NodeType.secret


def test_parser_unquoted_password_with_special_chars():
    sample = 'my_password=      !pass w0rd"'
    root_node = parse_raw_block(sample)
    nodes = list(flatten(root_node))
    assert [t.type for t in nodes] == [
        NodeType.quoted_string_holder,
        NodeType.field,
        NodeType.separator,
        NodeType.space,
        NodeType.space,
        NodeType.space,
        NodeType.space,
        NodeType.space,
        NodeType.space,
        NodeType.secret,
    ]
    assert nodes[-1].type is NodeType.secret
    assert nodes[-1].text == '!pass w0rd"'


def test_parser_two_passwords_on_same_line():
    sample = 'my_password:      !pass w0rd  another_password: hide_thís "'
    root_node = parse_raw_block(sample)
    nodes = list(flatten(root_node))
    assert [t.type for t in nodes] == [
        NodeType.quoted_string_holder,
        NodeType.field,
        NodeType.separator,
        NodeType.space,
        NodeType.space,
        NodeType.space,
        NodeType.space,
        NodeType.space,
        NodeType.space,
        NodeType.secret,
        NodeType.space,
        NodeType.space,
        NodeType.field,
        NodeType.separator,
        NodeType.space,
        NodeType.secret,
    ]
    assert nodes[9].type is NodeType.secret
    assert nodes[9].text == "!pass w0rd"

    assert nodes[-1].type is NodeType.secret
    assert nodes[-1].text == 'hide_thís "'


def test_parser_one_password_and_one_regular_kv_on_same_line():
    sample = "my_password:      !pass w0rd  some-key: show-this"
    root_node = parse_raw_block(sample)
    nodes = list(flatten(root_node))
    assert [t.type for t in nodes] == [
        NodeType.quoted_string_holder,
        NodeType.field,
        NodeType.separator,
        NodeType.space,
        NodeType.space,
        NodeType.space,
        NodeType.space,
        NodeType.space,
        NodeType.space,
        NodeType.secret,
        NodeType.space,
        NodeType.space,
        NodeType.field,
        NodeType.separator,
        NodeType.space,
        NodeType.field,
    ]
    assert nodes[9].type is NodeType.secret
    assert nodes[9].text == "!pass w0rd"


def test_parser_yaml_unquoted_password_with_a_equal_sign():
    sample = 'my_password:     !pass=w0rd"'
    root_node = parse_raw_block(sample)
    nodes = list(flatten(root_node))
    assert nodes[-1].secret_value_of is nodes[1]
    assert nodes[-1].type is NodeType.secret
    assert nodes[-1].text == '!pass=w0rd"'


def test_parser_ini_unquoted_password_with_a_colon_sign():
    sample = 'my_password = !pass:w0rd"'
    root_node = parse_raw_block(sample)
    nodes = list(flatten(root_node))
    assert nodes[-1].secret_value_of is nodes[1]
    assert nodes[-1].type is NodeType.secret
    assert nodes[-1].text == '!pass:w0rd"'


def test_parser_empty_quoted_secret():
    sample = 'password=""'
    root_node = breakup_elements(sample)
    node_types_found = [n.type for n in flatten(root_node)]
    assert node_types_found == [
        NodeType.quoted_string_holder,
        NodeType.field,
        NodeType.separator,
        NodeType.quoted_string_holder,
        NodeType.quoted_string_closing,
    ]
    nodes_found = list(flatten(root_node))
    assert nodes_found[-2].closed_by == nodes_found[-1]


def test_parser_one_character_quoted_secret():
    sample = 'password="a"'
    root_node = breakup_elements(sample)
    node_types_found = [n.type for n in flatten(root_node)]
    assert node_types_found == [
        NodeType.quoted_string_holder,
        NodeType.field,
        NodeType.separator,
        NodeType.quoted_string_holder,
        NodeType.field,
        NodeType.quoted_string_closing,
    ]
    nodes_found = list(flatten(root_node))
    assert nodes_found[-3].closed_by == nodes_found[-1]
