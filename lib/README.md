# SAML parsing library

Lifecycle
* User clicks log in on server
* Request is sent to external authentication server
* Authentication is handled on external server
* User is redirected back to server with SAML response embedded in HTTP body
* Server parses SAML document from Base64
* Server verifies signature in document with preshared key (certificate.pem)
* Server verifies SAML condition statement (within valid date/sent from verified issuer)
* Parse assertion to get user data
