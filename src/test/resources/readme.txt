b64fromidp-pkix.txt
Used for testing PKIX path validation in the Engine.
This is base64 encoded SAML Response from the IdP with an entityID of GUANXI--1182852605.
This entity has no embedded X509Certificate in metadata.xml.

b64fromidp.txt
Used for testing direct X509 validation in the Engine.
This is base64 encoded SAML Response from the IdP with an entityID of GUANXI-1235342852
This entity has an embedded X509Certificate in metadata.xml.

metadata.xml
This is the test metadata file containing metadata for the above entities as well as
test CA certificates.