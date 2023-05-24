#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring

from textwrap import dedent

from ansible_anonymizer.parser import (
    NodeType,
    combinate_value_fields,
    flatten,
    hide_secrets,
    parser,
)


def test_hide_secret_sudo_line():
    source = 'line="%wheel\tALL=(ALL)\tNOPASSWD: ALL"'
    assert hide_secrets(source) == source


def test_hide_secrets_quoted():
    assert (
        hide_secrets("ansible: 'ALL=(ALL) PASSWD: \\\"{{NOPASSWD'")
        == "ansible: 'ALL=(ALL) PASSWD: {{ passwd }}'"
    )
    assert (
        hide_secrets("ansible: 'ALL=(ALL) PASSWD: \\\"{{NOPASSWD'")
        == "ansible: 'ALL=(ALL) PASSWD: {{ passwd }}'"
    )
    assert (
        hide_secrets("password1: 'foobar'\npassword: 'barfoo'")
        == "password1: '{{ password1 }}'\npassword: '{{ password }}'"
    )
    assert (
        hide_secrets('%wheel	ALL=(ALL)	PASSWD: "ALL"') == '%wheel	ALL=(ALL)	PASSWD: "{{ passwd }}"'
    )


def test_hide_secrets_preserve_protected_quotes():
    assert (
        hide_secrets('line: "%ansible password=\'foobar\'"')
        == 'line: "%ansible password=\'{{ password }}\'"'
    )


def test_hide_secrets_trailing_secret():
    origin = "password1: foobar\npassword: barfoo"
    expectation = 'password1: "{{ password1 }}"\npassword: "{{ password }}"'
    assert hide_secrets(origin) == expectation


def test_hide_secrets_quoted_field():
    origin = """
    "password9": "my_password10: maxplus"
    """
    expectation = """
    "password9": "{{ password9 }}"
    """
    assert hide_secrets(origin) == expectation


def test_hide_secrets_unquoted_field():
    origin = """
    password9: "my_password10: maxplus"
    """
    expectation = """
    password9: "{{ password9 }}"
    """
    assert hide_secrets(origin) == expectation


def test_hide_secrets_pattern_within_quoted_string():
    origin = """
    'password9: "my_password10: maxplus"'
    """
    expectation = """
    'password9: "{{ password9 }}"'
    """
    assert hide_secrets(origin) == expectation


def test_hide_secrets_long_string():
    origin = """
    passwd: $6$j212wezy$7H/1LT4f9/N3wpgNunhsIqtMj62OKiS3nyNwuizouQc3u7MbYCarYeAHWYPYb2FT.lbioDm2RrkJPb9BZMN1O/
    """  # noqa: E501
    expectation = """
    passwd: "{{ passwd }}"
    """
    assert hide_secrets(origin) == expectation


def test_hide_secrets_2_level_of_quotes():
    origin = """
    "aaa'
       passwd: bob'"
    """
    expectation = """
    "aaa'
       passwd: {{ passwd }}'"
    """
    assert hide_secrets(origin) == expectation


def test_hide_secrets_protected_double_quotes():
    origin = """
    "aaa
       \\"passwd: bob\\""
    """
    expectation = """
    "aaa
       \\"passwd: {{ passwd }}\\""
    """
    assert hide_secrets(origin) == expectation


def test_hide_secrets_empty():
    origin = ""
    expectation = ""
    assert hide_secrets(origin) == expectation


def test_hide_secrets_field_only():
    origin = "passwd"
    expectation = "passwd"
    assert hide_secrets(origin) == expectation


def test_hide_secrets_vars_file():
    origin = """
    ansible_user: root
    ansible_host: esxi1-gw.ws.testing.ansible.com
    ansible_password: '!234AaAa56'
    """
    expectation = """
    ansible_user: root
    ansible_host: esxi1-gw.ws.testing.ansible.com
    ansible_password: '{{ ansible_password }}'
    """
    assert hide_secrets(dedent(origin)) == dedent(expectation)


def test_hide_secrets_unquoted_string():
    origin = """
    ansible_password: an unquoted string
    """
    expectation = """
    ansible_password: "{{ ansible_password }}"
    """
    assert hide_secrets(dedent(origin)) == dedent(expectation)


def test_hide_secrets_multi_secrets():
    origin = """
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
    expectation = """
    '(?i)password1:': "{{ _iosxr_password }}"
    "this is somethingpass: {{ somethingpass }}: else my_password3: '{{ my_password3 }}': barfoo"
    password5: "{{ password5 }}"
    password6: "{{ password6 }}"
    password7: "{{ password7 }}"
    "password9": "{{ password9 }}"
    password11: "{{ password11 }}"

    passwd: "{{ passwd }}"
    """
    assert hide_secrets(origin) == expectation


def test_hide_secrets_aws_profile():
    origin = """
    [my-secret-account]
    aws_access_key_id = BJIA5UUFYYOOKZQODC3F
    aws_secret_access_key = NeTL/2vPPnlnb/8RBtsw3EwnNjflDbgZiDmRskhb
    """

    expectation = """
    [my-secret-account]
    aws_access_key_id = "{{ aws_access_key_id }}"
    aws_secret_access_key = "{{ aws_secret_access_key }}"
    """
    assert hide_secrets(dedent(origin)) == dedent(expectation)


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
    root_node = parser(sample)
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
    root_node = parser(sample)
    expanded = [(c.text, c.type) for c in flatten(root_node)]
    assert expanded == expectation


def test_parser_get_secret():
    sample = "config_reverseproxy_oauth_password: my_secret"
    root_node = parser(sample)
    list_of_nodes = list(flatten(root_node))
    field_name_node = list_of_nodes[1]
    assert field_name_node.text == "config_reverseproxy_oauth_password"
    assert field_name_node.get_secret().text == "my_secret"


def test_parser_get_secret_with_unquoted_special_chars():
    sample = "config_reverseproxy_oauth_password: %$#my_secret&"
    root_node = parser(sample)
    field_name_node = root_node.next
    assert field_name_node.text == "config_reverseproxy_oauth_password"
    # Without combinate_value_fields we only get the first node of the secret
    assert field_name_node.get_secret().text == "%$#"
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
    root_node = parser(dedent(sample))
    secret_node = [n for n in flatten(root_node) if n.text == "turbo_secret"][0]
    # Without combinate_value_fields we only get the first node of the secret
    combinate_value_fields(root_node)
    assert secret_node.get_secret().text == "@#%$%^&^^ 645"


def test_combinate_value_fields():
    sample = "config_reverseproxy_oauth_password: my!secret%$!"
    root_node = parser(sample)
    assert len(list(flatten(root_node))) == 8
    combinate_value_fields(root_node)
    assert len(list(flatten(root_node))) == 5


def test_hide_secrets_multi_spaces_before_simple_key_value_string():
    sample = 'config_reverseproxy_oauth_password:      "passw0rd"'
    assert (
        hide_secrets(sample)
        == 'config_reverseproxy_oauth_password:      "{{ config_reverseproxy_oauth_password }}"'
    )


def test_parser_unquoted_password_with_special_chars():
    sample = 'my_password=      !pass w0rd"'
    assert hide_secrets(sample) == 'my_password=      "{{ my_password }}"'


def test_parser_two_passwords_on_same_line():
    sample = 'my_password:      !pass w0rd  another_password: hide_thís "'
    assert (
        hide_secrets(sample)
        == 'my_password:      "{{ my_password }}"  another_password: "{{ another_password }}"'
    )


def test_parser_one_password_and_one_regular_kv_on_same_line():
    sample = "my_password:      !pass w0rd  some-key: show-this"
    assert hide_secrets(sample) == 'my_password:      "{{ my_password }}"  some-key: show-this'


def test_parser_yaml_unquoted_password_with_a_equal_sign():
    sample = 'my_password:     !pass=w0rd"'
    assert hide_secrets(sample) == 'my_password:     "{{ my_password }}"'


def test_parser_ini_unquoted_password_with_a_colon_sign():
    sample = 'my_password = !pass:w0rd"'
    assert hide_secrets(sample) == 'my_password = "{{ my_password }}"'
