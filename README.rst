==========
Anonymizor
==========


.. image:: https://img.shields.io/pypi/v/anonymizor.svg
        :target: https://pypi.python.org/pypi/anonymizor
.. image:: https://github.com/goneri/ansible-wisdom-anonymizor/actions/workflows/tox.yml/badge.svg
        :target: https://github.com/goneri/ansible-wisdom-anonymizor/actions



Library to clean up Ansible tasks from any Personally Identifiable Information (PII)


* Free software: Apache Software License 2.0


Features
--------

The library can be used to remove the PII from a multi level structure:

.. code-block::

   $ python3
   >>> from anonymizor import anonymizor
   >>> example = [{"name": "foo bar", "email": "my-email@address.com"}]
   >>> anonymizor.anonymize_struct(example)
   ['- email: lucas27@example.com\n  name: foo bar\n']

But you can also anonymize a block of text:

.. code-block::

   >>> from anonymizor import anonymizor
   >>> some_text = """
   ... - name: a task
   ...   a_module:
   ...     secret: foobar
   ... """
   >>> anonymizor.anonymize_text_block(some_text)
   '\n- name: a task\n  a_module:\n    secret: {{ }}\n'
