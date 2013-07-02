IMQS Authentication REST API
============================

.. http:get:: /check

    Retrieve information for the provided credentials

    **Example 'check' request using HTTP Basic Authentication**:

    .. sourcecode:: http

        GET /check HTTP/1.1
        Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

    
    **Example 'check' request using a session cookie**:

    .. sourcecode:: http

        GET /check HTTP/1.1
        Cookie: session=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw


    **Example 'check' response (success)**:

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Content-Type: application/json
        Content-Length: 123

        {"Identity":"johndoe@mycity.com","Roles":["2"]}


    **Example 'check' response (incorrect password)**:

    .. sourcecode:: http

        HTTP/1.1 403 Forbidden
        Content-Type: text/plain
        Content-Length: 16

        Invalid password

    
.. http:post:: /login

    Perform a login. The input is an identity:password pair, and the resulting response has a 
    Set-Cookie in the header, if the login was successful.

    **Example 'login' request using HTTP Basic Authentication**:

    .. sourcecode:: http

        GET /login HTTP/1.1
        Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==


    **Example 'login' response (success)**:

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Set-Cookie: session=2CimDEYOfJMHIA1uJTDadu4C63hBA9; Path=/; Expires=Thu, 01 Aug 2013 09:58:31 UTC

    **Example 'login' response (incorrect password)**:

    .. sourcecode:: http

        HTTP/1.1 403 Forbidden
        Content-Type: text/plain
        Content-Length: 16

        Invalid password
