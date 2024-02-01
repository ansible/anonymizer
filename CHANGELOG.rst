Changelog
=========

Version 1.5.0 (2024-02-01)
-------------

- Handle multilines blocks (#57)
- Enforce the type checking with ``pyright`` in addition to ``mypy``

Version 1.4.2 (2023-08-31)
-------------

- fix the user name anonymization in path definitions when a Jinja template is used instead of a user name


Version 1.4.1 (2023-06-14)
-------------

- fix to ensure anonymize_struct() uses the right value_template when it anoymizes a text blocks

Version 1.4.0 (2023-06-13)
-------------

- fix the parser when a string is an empty quoted string (``""``)
- refactoring to properly isolate the parsing in ``ansible_anonymizer.parser``
- add ability to customize the secret substitution
- README: minor adjustments and a new "limitations" section

Version 1.3.0 (2023-05-24)
-------------

- tests: split up test_anonymizer.py
- pre-commit: only check ansible_anonymizer
- pre-commit: mypy needs types-PyYAML
- pylint: various fixes to get pylint to pass
- pre-commmit: replace reorder_python_imports with ruff
- tests: don't redefine dedent
- cli: don't had an extra \n
- parser: remove an uncessary ParserError exception
- handle : or = in password field
- better handling of unquoted password
- extra tests
- test: cover Node.get_secret()
- properly handle series of spaces before password
- add a .gitleaks.toml file


Version 1.2.2 (2023-05-05)
-------------

- adjustment to handle aws/credentials

Version 1.2.1 (2023-05-05)
-------------

- clean up some debug traces

Version 1.2.0 (2023-05-05)
-------------

- hide_secrets: better management of the quotes (#41)
- tox: skip_install=True with mypy
- tox: test using ruff
- pyproject: configure ruff and reformat the code base
- sudo's NOPASSWD is not a password field

Version 1.1.5 (2023-04-11)
-------------

- comment: ensure the quotes are also removed (#34)

Version 1.1.4  (2023-04-08)
-------------

- is_uuid_string(): do not anonymize UUID strings
- test_anonymizer: add UUID test cases

Version 1.1.3  (2023-04-05)
-------------

- is_password_field_name(): ignore the case of the string

Version 1.1.2  (2023-04-05)
-------------

- hide_secrets(): protect the final jinja2 expression
- MANIFEST.in: clean up some unused files

Version 1.1.1 (2023-04-05)
-------------

- anonymize_field(): don't eat the spaces around the value
- tox: adjust the cmd used to upload the release
- adjust the Github Workflow badge URL

Version 1.1.0 (2023-03-31)
-------------

- add the ansible-anonymizer CLI command
- test_anonymizer: orderize the imports
- properly hide a field with just a CC string
- don't capture a series of 10 digits inside a longer series

Version 1.0.1 (2023-03-30)
-------------

- hide_secrets: fieldname should not be multline or a series of words
- cc: don't match a pattern that is within a bigger series of numbers
