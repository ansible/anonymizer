==========
Anonymizer
==========


.. image:: https://img.shields.io/pypi/v/ansible-anonymizer.svg
        :target: https://pypi.python.org/pypi/ansible-anonymizer
.. image:: https://github.com/ansible/ansible-anonymizer/actions/workflows/tox.yml/badge.svg
        :target: https://github.com/ansible/ansible-anonymizer/actions



Library to clean up Ansible tasks from any Personally Identifiable Information (PII)


* Free software: Apache Software License 2.0


Features
--------

The library can be used to remove the PII from a multi level structure:

.. code-block::

   $ python3
   >>> from ansible_anonymizer import anonymizer
   >>> example = [{"name": "foo bar", "email": "my-email@address.com"}]
   >>> anonymizer.anonymize_struct(example)
   ['- email: lucas27@example.com\n  name: foo bar\n']

But you can also anonymize a block of text:

.. code-block::

   >>> from ansible_anonymizer import anonymizer
   >>> some_text = """
   ... - name: a task
   ...   a_module:
   ...     secret: foobar
   ... """
   >>> anonymizer.anonymize_text_block(some_text)
   '\n- name: a task\n  a_module:\n    secret: {{ }}\n'
