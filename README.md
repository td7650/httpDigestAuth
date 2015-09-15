http-digest-auth-client
=======================

Go (golang) http digest authentication client.

This fork includes the following changes:

- Changed MD5 hash generation to clean up some code
- Added proper closing of request bodies (urgently needed for many requests in a row)
- Removed fatal errors instead return with error (and log error text) 