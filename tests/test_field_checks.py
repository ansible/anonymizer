#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring

from ansible_anonymizer.field_checks import (
    is_allowed_password_field,
    is_jinja2_expression,
    is_password_field_name,
    is_path,
    is_uuid_string,
)


def test_is_allowed_password_field():
    assert is_allowed_password_field("NOPASSWD") is True
    assert is_allowed_password_field("NOPASSWD2") is False


def test_is_jinja2_expression():
    assert is_jinja2_expression("{{ foo|defaul('b')  }}") is True
    assert is_jinja2_expression("my_passw'rd") is False


def test_is_password_field_name():
    assert is_password_field_name("login") is False
    assert is_password_field_name("password") is True
    assert is_password_field_name("passwd") is True
    assert is_password_field_name("db_passwd") is True
    assert is_password_field_name("key_data") is True
    assert is_password_field_name("key_name") is True
    assert is_password_field_name("host_config_key") is True
    assert is_password_field_name("quayPassword") is True
    assert is_password_field_name("NOPASSWD") is False
    assert is_password_field_name("nopasswd") is True


def test_is_path():
    assert is_path("/etc/fstab") is True
    assert is_path("./opt/fstab") is True
    assert is_path("~/.ssh/id_rsa.pub") is True
    assert is_path(".%/mypassword/f$b") is False
    assert is_path("certificates/CA.key") is True
    assert is_path("a_password") is False


def test_is_uuid_string():
    assert is_uuid_string("ce34efc1-f5e3-4b0f-bb2c-5272319589a7") is True
    assert is_uuid_string("CE34EFC1-F5E3-4B0F-BB2C-5272319589A7") is True
