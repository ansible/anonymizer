#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=R0801
from ipaddress import IPv4Address, IPv4Network, IPv6Address
from string import Template
from textwrap import dedent

from ansible_anonymizer.anonymizer import (
    anonymize,
    anonymize_field,
    anonymize_struct,
    anonymize_text_block,
    hide_comments,
    hide_credit_cards,
    hide_emails,
    hide_ip_addresses,
    hide_mac_addresses,
    hide_us_phone_numbers,
    hide_us_ssn,
    hide_user_name,
    redact_ip_address,
    redact_ipv4_address,
    redact_ipv6_address,
    unquote,
)


def test_redact_ipv4_address():
    assert redact_ipv4_address(IPv4Address("192.168.3.5")) in IPv4Network("192.168.3.0/24")
    assert redact_ipv4_address(IPv4Address("8.8.8.8")) == IPv4Address("8.8.8.8")
    assert redact_ipv4_address(IPv4Address("8.8.8.9")) in IPv4Network("8.8.8.0/24")


def test_redact_ipv6_address():
    assert redact_ipv6_address(IPv6Address("2001:4860:4860::8888")) == IPv6Address(
        "2001:4860:4860::8888"
    )
    assert IPv6Address(redact_ipv6_address(IPv6Address("2001:db8:3333:4444:5555:6666:7777:8888")))


def test_redact_ip_address():
    assert redact_ip_address("2001:4860:4860::8888") == "2001:4860:4860::8888"
    assert IPv4Address(redact_ip_address("8.8.8.9"))


def test_anonymize_struct_nested_struct():
    in_ = {
        "name": "Install nginx and nodejs 12",
        "apt": {"name": ["nginx", "nodejs"], "state": "latest"},
        "a_set": {1, 2, 3},
        "dict_wit_with_int_as_index": {1: "1", 2: "2", 3: "3"},
    }
    assert anonymize_struct(in_) == in_


def test_anonymize_struct_ip_addresses():
    in_ = {
        "name": "foo@montreal.ca",
        "a_module": {
            "ip": ["2001:460:48::888", "192.168.1.1"],
            "password": "@This-should-disapear!",
        },
    }
    changed = anonymize_struct(in_)
    assert "foo@montreal.ca" not in changed["name"]
    assert "2001:460:48::888" not in changed["a_module"]["ip"]
    assert changed["a_module"]["password"] == "{{ password }}"


def test_anonymize_multiple_passwords():
    in_ = {"password": ["first_password", "second_password"]}
    assert anonymize_struct(in_) == {"password": ["{{ password }}", "{{ password }}"]}


def test_anonymize_email():
    # Str
    in_ = "my-email-address@somewhe.re"
    changed = anonymize_struct(in_)
    assert in_ not in changed
    assert isinstance(changed, str)
    assert "@" in changed

    # List
    in_ = ["my-email-address@somewhe.re"]
    changed = anonymize_struct(in_)
    assert in_ != changed
    assert isinstance(changed[0], str)
    assert "@" in changed[0]


def test_anonymize_with_special_template():
    original = {"password": ["first_password", "second_password"], "block": 'password1: "bar"'}
    expected = {"password": ["ö", "ö"], "block": 'password1: "ö"'}
    value_template = Template("ö")
    value_template = Template("ö")
    assert anonymize_struct(original, value_template=value_template) == expected


def test_anonymize_deprecated_function():
    in_ = ["my-email-address@somewhe.re"]
    changed = anonymize(in_)
    assert in_ != changed


def test_anonymize_text_block_no_change():
    source = """
    ---
    - name: AWS Cloud Operations
      hosts: localhost
      tasks:
        - name: Create a virtual network named myvpc
          amazon.aws.ec2_vpc_net:
            aws_access_key: "{{ aws_access_key }}"
            aws_secret_key: "{{ aws_secret_key }}"

    ---
    - name: AWS Cloud Operations
      hosts: localhost
      vars:
        myvpc_region: "us-east1"
        myvpc_name: "myvpc"

      tasks:
        - name: Create a virtual network
          amazon.aws.ec2_vpc_net:
            name: "{{ myvpc_name }}"
            cidr_block: "{{ myvpc_cidr_block }}"

    ---
    - name: Add mysshkey to Linux servers
      ansible.posix.authorized_key:
        user: "{{ user }}"
        state: present
        key: "{{ lookup('file', '/mysshkey') }}"

    """
    assert anonymize_text_block(dedent(source)) == dedent(source)


def test_anonymize_text_block_secret_fields():
    source = """

        - name: some example
            a-broken-key:
                my-secret: a-secret
                @^my-secret: weird-artifact
                %@iÜ-secret: "again"
                quoted-secret: ' With {{ some_variable }} again    '
                private_key: ~/.ssh/id_rsa

    """
    expectation = """

        - name: some example
            a-broken-key:
                my-secret: "{{ my_secret }}"
                @^my-secret: "{{ my_secret }}"
                %@iÜ-secret: "{{ secret }}"
                quoted-secret: '{{ quoted_secret }}'
                private_key: "{{ private_key }}"

    """
    assert anonymize_text_block(source) == expectation


def test_anonymize_text_block_email_addresses():
    source = """

        - name: some example
            a-broken-key:
                emails: - fooo@bar.ca
                - pierre-loup@some.company
                - christina@world.corp
                - "christina@world.corp"
                - 'christina@world.corp'

    """
    expectation = """

        - name: some example
            a-broken-key:
                emails: - lucas14@example.com
                - elijah6@example.com
                - evelyn17@example.com
                - "evelyn17@example.com"
                - 'evelyn17@example.com'

    """
    assert anonymize_text_block(source) == expectation
    assert hide_emails(source) == expectation


def test_anonymize_text_block_ip_addresses():
    source = """

        - name: some example
            this-should-remain: 8.8.8.8
            a-broken-key:
                some-random-ips: - fda4:597b:21fc:d31f::
                - 23.233.103.236
                - 192.168.10.34
                - 192.168.10.34/32
                - fda4:597b:21fc:d31f::/128
    """
    expectation = """

        - name: some example
            this-should-remain: 8.8.8.8
            a-broken-key:
                some-random-ips: - fda4:17b:1fc:31f::
                - 23.233.104.40
                - 192.168.10.48
                - 192.168.10.48/32
                - fda4:17b:1fc:31f::/128
    """
    assert anonymize_text_block(source) == expectation
    assert hide_ip_addresses(source) == expectation


def test_anonymize_text_block_us_ssn():
    source = """

    - copy:
        content: |
          here some content with a ssn "078-05-1120"
          and this is pi: 3.1415926535897936

    """

    expectation = """

    - copy:
        content: |
          here some content with a ssn "{{ ssn }}"
          and this is pi: 3.1415926535897936

    """
    assert anonymize_text_block(source) == expectation
    assert hide_us_ssn(source) == expectation


def test_anonymize_text_block_macaddress():
    source = """

    - copy:
        content: |
          some mac addresses "a0:36:9f:0e:9d:78"
          or A0-36-9F-0E-9D-78
          or A036.9F0E.9D78
          and this is pi: 3.1415926535897936

    """

    expectation = """

    - copy:
        content: |
          some mac addresses "5b:e1:4a:b9:48:23"
          or f5-8b-e4-53-e2-cd
          or 39cf.2897.2601
          and this is pi: 3.1415926535897936

    """
    assert anonymize_text_block(source) == expectation
    assert hide_mac_addresses(source) == expectation


def test_anonymize_text_block_us_phone_numbers():
    source = """

    - copy:
        content: |
            (914) 499-1900
            "914-499-1900"
            "914 499-1900"
            9144991900
            19144991900
          and this is pi: 3.14159265358
          a french number: 06 10 00 10 23
          a cell number from belgium: 0479 20 07 77

    """

    expectation = """

    - copy:
        content: |
            (311) 555-2368
            "(311) 555-2368"
            "(311) 555-2368"
            (311) 555-2368
            (311) 555-2368
          and this is pi: 3.14159265358
          a french number: 06 10 00 10 23
          a cell number from belgium: 0479 20 07 77

    """
    assert anonymize_text_block(source) == expectation
    assert hide_us_phone_numbers(source) == expectation
    assert hide_us_phone_numbers("914-499-1900") == "(311) 555-2368"


def test_anonymize_text_block_credit_cards():
    source = """

    - copy:
        content: |
          a_quoted_cc_number("1234567812345670")
          1234567812345670
          (1234567812345670)
          "1234567812345670"
          "1234 5678 1234 5670"
          "1234-5678-1234-5670"
          a UUID that look like CC number: "34206f73-4e3a-1234-567812345670-b85a"
          and this is pi: 3.1415926535897936

    """

    expectation = """

    - copy:
        content: |
          a_quoted_cc_number("{{ credit_card_number }}")
          {{ credit_card_number }}
          ({{ credit_card_number }})
          "{{ credit_card_number }}"
          "{{ credit_card_number }}"
          "{{ credit_card_number }}"
          a UUID that look like CC number: "34206f73-4e3a-1234-567812345670-b85a"
          and this is pi: 3.1415926535897936

    """
    assert anonymize_text_block(source) == expectation
    assert hide_credit_cards(source) == expectation
    assert hide_credit_cards("1234 5678 1234 5670") == "{{ credit_card_number }}"


def test_anonymize_text_block_comments():
    source = """

    # That a task block
    - copy:  # A comment at the end of line
        content: "some value to #  keep"

    """

    expectation = """


    - copy:
        content: "some value to #  keep"

    """
    assert anonymize_text_block(source) == expectation
    assert hide_comments(dedent(source)) == dedent(expectation)


def test_anonymize_comment_with_quote():
    source = (
        "# NEWCOPY'- "
        "#name: using the zos_operator module, issue command PHASEIN  "
        "#zos_operator:    cmd: 'CEMT SET PROGRAM PHASEIN'"
    )
    assert hide_comments(source) == ""


def test_anonymize_text_block_user_name():
    source = """
    "documentUri": "file:///home/pierre-yves/git_repos/ansible-collections/tag_operations.yml"
    'documentUri': 'file:///Users/rbobbitt/work//full_playbook.yml',
    "dest": "/home/fedora/somewhere-else"
    "dest": "/home/ubuntu/somewhere-else"
    "dest": "c:\\Users\\Gilbert\\été \\directory"
    "unicode": c:\\Users\\Eloïse\\Œufs de pâques\\Fête
    some_field:
      - /home/marie-pier
      - /home/marie-pier"Not the login"
      - c:\\Users\\Bảo
      - c:\\Users\\Bảo"Not the login"

    """

    expectation = """
    "documentUri": "file:///home/ano-user/git_repos/ansible-collections/tag_operations.yml"
    'documentUri': 'file:///Users/ano-user/work//full_playbook.yml',
    "dest": "/home/fedora/somewhere-else"
    "dest": "/home/ubuntu/somewhere-else"
    "dest": "c:\\Users\\ano-user\\été \\directory"
    "unicode": c:\\Users\\ano-user\\Œufs de pâques\\Fête
    some_field:
      - /home/ano-user
      - /home/ano-user"Not the login"
      - c:\\Users\\ano-user
      - c:\\Users\\ano-user"Not the login"

    """
    assert anonymize_text_block(source) == expectation
    assert hide_user_name(dedent(source)) == dedent(expectation)


def test_anonymize_text_block_username_for_linux_path():
    assert (
        anonymize_text_block("path: /home/kaisersoze/.ssh/authorized_keys")
        == "path: /home/ano-user/.ssh/authorized_keys"
    )


def test_anonymize_text_block_username_for_windows_path():
    assert (
        anonymize_text_block("path: C:\\users\\kaisersoze\\test")
        == "path: C:\\users\\ano-user\\test"
    )


def test_anonymize_text_block_username_as_jinja_template_for_linux_path():
    assert (
        anonymize_text_block(
            "path: /home/{{ admin_username | default('azureuser') }}/.ssh/authorized_keys"
        )
        == "path: /home/{{ admin_username | default('azureuser') }}/.ssh/authorized_keys"
    )


def test_anonymize_text_block_username_as_jinja_template_for_windows_path():
    assert (
        anonymize_text_block("path: c:\\users\\{{ admin_username | default('azureuser') }}\\test")
        == "path: c:\\users\\{{ admin_username | default('azureuser') }}\\test"
    )


def test_anonymize_field():
    field = "my_field"
    value = "     a    "

    value_template = Template("{{ $variable_name }}")
    assert anonymize_field(value, field, value_template) == value


def test_unquote():
    assert unquote("'a'") == "a"
    assert unquote('"a"') == "a"
    assert unquote('"a\'') == '"a\''
    assert unquote("a") == "a"
    assert unquote("''") == ""
    assert unquote("'") == "'"


def test_anonymize_uuid_field():
    field = "uuid_field"
    value = "ce34efc1-f5e3-4b0f-bb2c-5272319589a7"
    value_template = Template("{{ $variable_name }}")
    assert anonymize_field(value, field, value_template) == value

    value = "CE34EFC1-F5E3-4B0F-BB2C-5272319589A7"
    value_template = Template("{{ $variable_name }}")
    assert anonymize_field(value, field, value_template) == value


def test_anonymize_special_template():
    field = "secret"
    value = "to_hide"

    value_template = Template("--${variable_name}--")
    assert anonymize_field(value, field, value_template) == "--secret--"


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
    assert anonymize_text_block(dedent(origin)) == dedent(expectation)


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
    assert anonymize_text_block(origin) == expectation


def test_hide_secret_sudo_line():
    source = 'line="%wheel\tALL=(ALL)\tNOPASSWD: ALL"'
    assert anonymize_text_block(source) == source


def test_anonymize_text_block_quoted():
    assert (
        anonymize_text_block("ansible: 'ALL=(ALL) PASSWD: \\\"{{NOPASSWD'")
        == "ansible: 'ALL=(ALL) PASSWD: {{ passwd }}'"
    )
    assert (
        anonymize_text_block("ansible: 'ALL=(ALL) PASSWD: \\\"{{NOPASSWD'")
        == "ansible: 'ALL=(ALL) PASSWD: {{ passwd }}'"
    )
    assert (
        anonymize_text_block("password1: 'foobar'\npassword: 'barfoo'")
        == "password1: '{{ password1 }}'\npassword: '{{ password }}'"
    )
    assert (
        anonymize_text_block('%wheel	ALL=(ALL)	PASSWD: "ALL"')
        == '%wheel	ALL=(ALL)	PASSWD: "{{ passwd }}"'  # noqa: E501
    )


def test_anonymize_text_block_special_template():
    value_template = Template("--")
    assert anonymize_text_block('my_secret: "ÓÐG™ÉÓÖ"', value_template) == 'my_secret: "--"'


def test_anonymize_text_block_preserve_protected_quotes():
    assert (
        anonymize_text_block('line: "%ansible password=\'foobar\'"')
        == 'line: "%ansible password=\'{{ password }}\'"'
    )


def test_anonymize_multi_lines():
    origin = """
    foo: |
      line1
      line2
    my_secret: |
      line3
      line4
    """
    expectation = """
    foo: |
      line1
      line2
    my_secret: "{{ my_secret }}"
    """

    assert anonymize_text_block(origin) == expectation
