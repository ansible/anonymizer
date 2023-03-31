Changelog
=========

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
