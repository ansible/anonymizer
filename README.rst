==========
Anonymizer
==========


.. image:: https://img.shields.io/pypi/v/ansible-anonymizer.svg
        :target: https://pypi.python.org/pypi/ansible-anonymizer
.. image:: https://github.com/ansible/anonymizer/actions/workflows/tox.yml/badge.svg
        :target: https://github.com/ansible/anonymizer/actions



Library to clean up Ansible tasks from any Personally Identifiable Information (PII)


* Free software: Apache Software License 2.0


Usage
-----

The library can be used to remove the PII from a multi level structure:

.. code-block:: python

    from ansible_anonymizer.anonymizer import anonymize_struct

    example = [{"name": "foo bar", "email": "my-email@address.com"}]

    anonymize_struct(example)
    # [{'name': 'foo bar', 'email': 'noah2@example.com'}]

But you can also anonymize a block of text:

.. code-block:: python

    from ansible_anonymizer.anonymizer import anonymize_text_block

    some_text = """
    - name: a task
      a_module:
        secret: foobar
    """

    anonymize_text_block(some_text)
    # '\n- name: a task\n  a_module:\n    secret: "{{ secret }}"\n'

You can also use the ``ansible-anonymizer`` command:

.. code-block:: console

   ansible-anonymizer my-secret-file

Customize the anonymized strings
================================

By default, the variables are anonymized with a string based on the name of the field.
You can customize it with the ``value_template`` parameter:

.. code-block:: python

    from ansible_anonymizer.anonymizer import anonymize_struct
    from string import Template

    original = {"password": "$RvEDSRW#R"}
    value_template = Template("_${variable_name}_")
    anonymize_struct(original, value_template=value_template)
    #  {'password': '_password_'}


Limitations
-----------

- ``anonymize_text_block()`` relies on its own text parser which only support a subset of YAML features. Because of this, it may not be able to identify some PII. When possible, use ``anonymize_struct`` which accepts a Python structure instead.
- The Anonymizer is not a silver bullet and it's still possible to see PII going through the filters.
