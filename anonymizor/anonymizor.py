#!/usr/bin/env python3

import ciso8601
import ipaddress
import json
import logging
import random
import re
import time
import yaml

from detect_secrets.plugins import keyword
from password_strength import PasswordStats


logger = logging.getLogger(__name__)


def gen_sample_password():
    colours = ["red", "blue", "green", "yellow", "purple", "pink", "orange", "brown"]
    fruits = ["papaya", "peach", "apple", "pineapple", "watermelon", "raspberry"]
    countries = ["senegal", "japan", "ukraine"]

    return f"{random.choice(colours)}-{random.choice(fruits)}-{random.choice(countries)}"


def gen_email_address(*kwargs):
    samples = [
        "liam",
        "olivia",
        "noah",
        "emma",
        "oliver",
        "charlotte",
        "elijah",
        "amelia",
        "james",
        "ava",
        "william",
        "sophia",
        "benjamin",
        "isabella",
        "lucas",
        "mia",
        "henry",
        "evelyn",
        "theodore",
        "harper",
    ]
    return f"{random.choice(samples)}{random.randint(0, 100)}@example.com"


def is_jinja2(content: str) -> bool:
    flags = re.MULTILINE | re.DOTALL
    if bool(re.search(r"{{.*\w+.*}}", content, flags)):
        return True
    if bool(re.search(r"{%.*\w+.*%}", content, flags)):
        return True
    return False


def is_ip_address(content: str):
    try:
        ip = ipaddress.ip_address(content)
    except ValueError:
        return False
    return True


def is_email_address(content: str) -> bool:
    return bool(re.match(r".*\w+@[a-z\.]+[a-z]{2,}.*", content, flags=re.IGNORECASE))


def is_date(content: str) -> bool:
    # Py3.11 comes with a very performant solution
    # https://github.com/closeio/ciso8601/blob/master/why_ciso8601.md#do-you-need-to-support-python--311
    try:
        return bool(ciso8601.parse_datetime(content))
    except ValueError:
        return False


def is_password(content):
    stats = PasswordStats(content)
    return stats.strength() > 0.48




def sensitive_field_name(name: str) -> bool:
    return re.search(keyword.DENYLIST_REGEX_WITH_PREFIX, name) is not None


def remove_email(value: str) -> str:
    return re.sub(r".*(\w+@[a-z\.]+[a-z]{2,}).*", gen_email_address, value)



common_ipv4_networks = [
    ipaddress.IPv4Network("1.0.0.1/32"),
    ipaddress.IPv4Network("1.1.1.1/32"),
    ipaddress.IPv4Network("149.112.112.112/32"),
    ipaddress.IPv4Network("208.67.220.220/32"),
    ipaddress.IPv4Network("208.67.222.222/32"),
    ipaddress.IPv4Network("76.223.122.150/32"),
    ipaddress.IPv4Network("76.76.19.19/32"),
    ipaddress.IPv4Network("8.20.247.20/32"),
    ipaddress.IPv4Network("8.26.56.26/32"),
    ipaddress.IPv4Network("8.8.4.4/32"),
    ipaddress.IPv4Network("8.8.8.8/32"),
    ipaddress.IPv4Network("9.9.9.9/32"),
    ipaddress.IPv4Network("94.140.14.14/32"),
    ipaddress.IPv4Network("94.140.15.15/32"),
]


def redact_ipv4_address(value: ipaddress.IPv4Address) -> ipaddress.IPv4Address:
    for i in common_ipv4_networks:
        if value in i:
            return value.exploded
    return value + random.randint(0, 100)


common_ipv6_networks = [
    ipaddress.IPv6Network("2001:4860:4860::8888/128"),
    ipaddress.IPv6Network("2001:4860:4860::8844/128"),
]


def redact_ipv6_address(value: ipaddress.IPv6Address) -> ipaddress.IPv6Address:
    for i in common_ipv6_networks:
        if value in i:
            return value.compressed

    def randomize(block):
        print(block.group(0))
        field = block.group(0)[1:]
        as_int = int(field, 16)
        new_val = random.randint(0, as_int)
        as_hex = hex(new_val)
        hex_without_0x_prefix = as_hex[2:]
        return ":" + hex_without_0x_prefix

    print(f"-> {value.compressed}")
    new_address = ipaddress.IPv6Address(
        re.sub(r":[a-z0-9]+", randomize, value.compressed, flags=re.IGNORECASE)
    )
    return new_address



def redact_ip_address(value: str) -> str:
    func = {4: redact_ipv4_address, 6: redact_ipv6_address}
    ip = ipaddress.ip_address(value)
    return str(func[ip.version](ip))


def anonymize_field(value: str, name) -> str:
    value = value.strip()
    if not value:
        return value
    elif is_jinja2(value):
        return value
    elif is_ip_address(value):
        return redact_ip_address(value)
    elif is_email_address(value):
        return remove_email(value)

    if sensitive_field_name(name):
        if is_path(value):
            return value
        elif is_date(value):
            return value
        elif is_password(value):
            return gen_sample_password()
    return value


def is_path(content: str):
    # Rather conservative on purpose to avoid a false
    # positive
    return bool(re.match(r"^(|~)[a-z0-9_/\.-]+$", content, flags=re.IGNORECASE))


def walker(o, key_name=''):
    def key_name_str(k):
        return k if isinstance(k, str) else ''

    if key_name and not isinstance(key_name, str):
        key_name = str(key_name)
    if isinstance(o, dict):
        return {k: walker(v, key_name=key_name_str(k)) for k, v in o.items()}
    elif isinstance(o, list):
        return [walker(v) for v in o]
    elif isinstance(o, str):
        return anonymize_field(o, key_name)
    return o


def anonymize(predictions):
    def cleanup(p):
        py_struct = yaml.safe_load(p)
        clean = walker(py_struct)
        return yaml.dump(clean)

    return [cleanup(p) for p in predictions]



def benchmark():
    cpt = 0
    duration = 0
    with open("/home/goneri/Downloads/awft_v2.4.2_train.json", "r") as fd:
        while True:
            line = fd.readline()
            if not line:
                break
            train_entry = json.loads(line)
            from pprint import pprint

            prediction = yaml.safe_load(train_entry["output_script"])
            start = time.perf_counter()
            ano = anonymize(prediction)
            duration += time.perf_counter() - start
            cpt += 1
    print(f"cpt: {cpt}")
    print(f"total duration: {duration}")
    print(f"average: {duration/cpt}")
