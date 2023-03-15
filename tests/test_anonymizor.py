#!/usr/bin/env python3
from ipaddress import IPv4Address
from ipaddress import IPv4Network
from ipaddress import IPv6Address

from textwrap import dedent

from anonymizor.anonymizor import is_password_field_name
from anonymizor.anonymizor import is_path
from anonymizor.anonymizor import redact_ip_address
from anonymizor.anonymizor import redact_ipv4_address
from anonymizor.anonymizor import redact_ipv6_address
from anonymizor.anonymizor import anonymize
from anonymizor.anonymizor import anonymize_struct
from anonymizor.anonymizor import anonymize_text_block

from anonymizor.anonymizor import hide_emails
from anonymizor.anonymizor import hide_secrets
from anonymizor.anonymizor import hide_ip_addresses
from anonymizor.anonymizor import hide_us_ssn
from anonymizor.anonymizor import hide_mac_addresses
from anonymizor.anonymizor import hide_us_phone_numbers
from anonymizor.anonymizor import hide_credit_cards
from anonymizor.anonymizor import hide_comments
from anonymizor.anonymizor import hide_user_name


def test_is_password_field_name():
    assert is_password_field_name("login") is False
    assert is_password_field_name("password") is True
    assert is_password_field_name("passwd") is True
    assert is_password_field_name("db_passwd") is True
    assert is_password_field_name("key_data") is True
    assert is_password_field_name("key_name") is True
    assert is_password_field_name("host_config_key") is True


def test_is_path():
    assert is_path("/etc/fstab") is True
    assert is_path("./opt/fstab") is True
    assert is_path("~/.ssh/id_rsa.pub") is True
    assert is_path(".%/mypassword/f$b") is False
    assert is_path("certificates/CA.key") is True
    assert is_path("a_password") is False


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


def test_anonymize_struct():
    in_ = {
        "name": "Install nginx and nodejs 12",
        "apt": {"name": ["nginx", "nodejs"], "state": "latest"},
        "a_set": {1, 2, 3},
        "dict_wit_with_int_as_index": {1: "1", 2: "2", 3: "3"},
    }
    assert anonymize_struct(in_) == in_

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
    assert changed["a_module"]["password"] == "{{ }}"

    in_ = {"password": ["first_password", "second_password"]}
    assert anonymize_struct(in_) == {"password": ["{{ }}", "{{ }}"]}

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


def test_anonymize():
    in_ = ["my-email-address@somewhe.re"]
    changed = anonymize(in_)
    assert in_ != changed


def test_anonymize_text_block_secret_fields():
    source = """

        - name: some example
            a-broken-key:
                my-secret: a-secret
                private_key: ~/.ssh/id_rsa

    """
    expectation = """

        - name: some example
            a-broken-key:
                my-secret: {{ }}
                private_key: ~/.ssh/id_rsa

    """
    assert hide_secrets(source) == expectation
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
    assert hide_emails(source) == expectation
    assert anonymize_text_block(source) == expectation


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
          here some content with a ssn "{{ }}"
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
          and this is pi: 3.1415926535897936

    """

    expectation = """

    - copy:
        content: |
            (311) 555-2368
            "(311) 555-2368"
            "(311) 555-2368"
            (311) 555-2368
            (311) 555-2368
          and this is pi: 3.1415926535897936

    """
    assert anonymize_text_block(source) == expectation
    assert hide_us_phone_numbers(source) == expectation


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
          and this is pi: 3.1415926535897936

    """

    expectation = """

    - copy:
        content: |
          a_quoted_cc_number("{{ }}")
          {{ }}
          ({{ }})
          "{{ }}"
          "{{ }}"
          "{{ }}"
          and this is pi: 3.1415926535897936
    """
    assert anonymize_text_block(source) == expectation
    assert hide_credit_cards(source) == expectation


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


def test_anonymize_text_block_user_name():
    source = """
    "documentUri": "file:///home/pierre-yves/git_repos/ansible-collections/tag_operations.yml"
    'documentUri': 'file:///Users/rbobbitt/work//full_playbook.yml',
    "dest": "/home/fedora/somewhere-else"
    "dest": "/home/ubuntu/somewhere-else"

    """

    expectation = """
    "documentUri": "file:///home/wisdom-user/git_repos/ansible-collections/tag_operations.yml"
    'documentUri': 'file:///Users/wisdom-user/work//full_playbook.yml',
    "dest": "/home/fedora/somewhere-else"
    "dest": "/home/ubuntu/somewhere-else"

    """
    assert anonymize_text_block(source) == expectation
    assert hide_user_name(dedent(source)) == dedent(expectation)
