#!/usr/bin/env python3
from ipaddress import IPv4Address
from ipaddress import IPv4Network
from ipaddress import IPv6Address

from anonymizor.anonymizor import is_email_address
from anonymizor.anonymizor import is_jinja2
from anonymizor.anonymizor import is_password_field_name
from anonymizor.anonymizor import is_valid_ssn
from anonymizor.anonymizor import is_valid_macaddress
from anonymizor.anonymizor import is_valid_telephone_number
from anonymizor.anonymizor import is_valid_credit_card_number
from anonymizor.anonymizor import is_path
from anonymizor.anonymizor import redact_ip_address
from anonymizor.anonymizor import redact_ipv4_address
from anonymizor.anonymizor import redact_ipv6_address
from anonymizor.anonymizor import remove_email
from anonymizor.anonymizor import anonymize

import pytest


def test_is_jinja2():
    assert is_jinja2("  {{\n\nfoo\n   }}\n  \n") is True
    assert is_jinja2("  {%\n\nfoo\n   %}\n  \n") is True


def test_is_path():
    assert is_path("/etc/fstab") is True
    assert is_path("./opt/fstab") is True
    assert is_path("~/.ssh/id_rsa.pub") is True
    assert is_path(".%/mypassword/f$b") is False
    assert is_path("certificates/CA.key") is True
    assert is_path("a_password") is False


def test_is_email_address():
    assert is_email_address("contact@.somewhe.re") is True
    assert is_email_address("contact@somewhe.re") is True
    assert is_email_address("contact.somewhe.re") is False
    assert is_email_address("été@somewhe.social") is True
    assert is_email_address("some text with an email  a@somewhe.social  fff") is True


def test_is_password_field_name():
    assert is_password_field_name("login") is False
    assert is_password_field_name("password") is True
    assert is_password_field_name("passwd") is True
    assert is_password_field_name("db_passwd") is True
    assert is_password_field_name("key_data") is True
    assert is_password_field_name("key_name") is True
    assert is_password_field_name("host_config_key") is True


def test_is_valid_ssn():
    assert is_valid_ssn("") is False
    assert is_valid_ssn("078-05-1120") is True


def test_is_valid_macaddress():
    assert is_valid_macaddress("") is False
    assert is_valid_macaddress("06:27:c7:") is False
    assert is_valid_macaddress("a0:ce:c8:61:eb:54") is True


def test_is_valid_telephone_number():
    assert is_valid_telephone_number("") is False
    assert is_valid_telephone_number("(914) 499-1900") is True
    assert is_valid_telephone_number("914-499-1900") is True
    assert is_valid_telephone_number("914 499-1900") is True
    assert is_valid_telephone_number("9144991900") is True
    assert is_valid_telephone_number("19144991900") is True


def test_is_valid_credit_card_number():
    assert is_valid_credit_card_number("") is False
    assert is_valid_credit_card_number("4485896627975888") is True
    assert is_valid_credit_card_number("49927398716") is False
    assert is_valid_credit_card_number("49927398717") is False
    assert is_valid_credit_card_number("1234567812345678") is False
    assert is_valid_credit_card_number("1234567812345670") is True


def test_remove_email():
    assert remove_email("fooo@bar.email").endswith("example.com")
    assert remove_email("foo") == "foo"
    assert "foo.bar@bar.re" not in remove_email("fo foo.bar@bar.re o")


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


def test_anonymize():
    in_ = {
        "name": "Install nginx and nodejs 12",
        "apt": {"name": ["nginx", "nodejs"], "state": "latest"},
        "a_set": {1, 2, 3},
        "dict_wit_with_int_as_index": {1: "1", 2: "2", 3: "3"},
    }
    assert anonymize(in_) == in_

    in_ = {
        "name": "foo@montreal.ca",
        "a_module": {
            "ip": ["2001:460:48::888", "192.168.1.1"],
            "password": "@This-should-disapear!",
        },
    }
    changed = anonymize(in_)
    assert "foo@montreal.ca" not in changed["name"]
    assert "2001:460:48::888" not in changed["a_module"]["ip"]
    assert changed["a_module"]["password"] == "{{ }}"

    in_ = {"password": ["first_password", "second_password"]}
    assert anonymize(in_) == {"password": ["{{ }}", "{{ }}"]}

    # Str
    in_ = "my-email-address@somewhe.re"
    changed = anonymize(in_)
    assert in_ not in changed
    assert isinstance(changed, str)
    assert "@" in changed

    # List
    in_ = ["my-email-address@somewhe.re"]
    changed = anonymize(in_)
    print(changed)
    assert in_ != changed
    assert isinstance(changed[0], str)
    assert "@" in changed[0]
