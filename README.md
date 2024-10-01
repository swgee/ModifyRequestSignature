## Modify Request Signature

Burp Suite Extension to support automatic resigning of requests.

Some applications may sign each HTTP request to prevent tampering in-flight. Since the request signature algorithm and secret must be known to the client, the extension can be configured to resign requests so dynamic testing is possible using tools like Repeater, Proxy Intercept, Scanner, and Intruder.

Currently only supports the following configurations:
* Base64, Base64URL SHA256 hashing functions
* Hashing the request body
* HS256 JWT signatures
