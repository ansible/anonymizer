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

.. code-block::

   $ python3
   Python 3.9.16 (main, Dec  7 2022, 00:00:00)
   [GCC 12.2.1 20221121 (Red Hat 12.2.1-4)] on linux
   Type "help", "copyright", "credits" or "license" for more information.
   >>> from anonymizor import anonymizor
   >>> example = [{"name": "foo bar", "email": "my-email@address.com"}]
   >>> anonymizor.anonymize(example)
   ['- email: lucas27@example.com\n  name: foo bar\n']
