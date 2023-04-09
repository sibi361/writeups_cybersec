# Same Origin Policy

> Category: Webex

---

The same-origin policy is a web browser security mechanism that prevents cross origin access unless explicitly specified. Without this policy, websites will be able to access each others' sensitive contents like cookies without any restrictions. An example is a victim clicking on a link in a spam email, being sent to a malicious website which opens a virtually invisible `iframe`, linking to a personal website like `gmail.com` and then hijack all it's cookies. Using them the attacker could take complete control over the victim's account.

For two URLs (Uniform Resource Locator `<scheme>://[<subdomain>.]<host>[:<port>]`) to be on the same origin, they need to have:

- same scheme i.e. protocol, for eg. HTTPS
- same domain, for eg. https://example.com and https://admin.example.com are different origins
- same port, for eg. https://example.com and https://example.com:8080 are different origins

In layman's terms, a different origin could mean a different physical server but since multiple websites can be hosted on a single server e.g. Apache2 VirtualHosts, the URL is the best way to check if a request is cross-origin or not.

---

Same Origin Policy (SOP) doesn't completely restrict access to resources present on a different origin, because that would require extra effort in loading commonly used resources. Hence, SOP allows embedding CSS stylesheets, scripts, images and media elements via the `<video>` tag.

If the developer wishes access resources present on a different origin apart from those allowed, that is, perform more advanced "Cross-origin" requests, they must use Cross-Origin Resource Sharing (CORS).

CORS is an HTTP-header based mechanism that allows a server to indicate any origins (domain, scheme, or port) other than its own from which a browser should permit loading resources. Browsers make a "preflight" request to the server hosting the cross-origin resource, in order to check that the server will permit the actual request. In that `preflight`, the browser sends headers that indicate the HTTP method and headers that will be used in the actual request. If the server wishes to go ahead with the request, it sends `Accept` headers accordingly with a `2xx` response. This `preflight` request is invisible to javascript and hence it has no power to fiddle with it.

Say for example, website A wishes to send a `DELETE` `XMLHttpRequest` request to website B which is a completely different origin, then the browser will spontaneously, by design, send a `preflight` request containing some headers, one of which will be `Access-Control-Request-Method: DELETE`. If website B agrees to receive the `DELETE` request from website A, it will send an `Access-Control-Allow-Methods: DELETE` header, after which the browser will send the actual `DELETE` request, which will have the capability to cause any changes on the server. If the server disagrees, then the response could be a `403 Forbidden`.

---

#### References:

- The Same Origin Policy - Hacker History - LiveOverflow https://youtu.be/bSJm8-zJTzQ
- CSRF Introduction and what is the Same-Origin Policy? - web 0x04 - LiveOverflow https://youtu.be/KaEj_qZgiKY
- The History of XSS Playlist - LiveOverflow https://www.youtube.com/playlist?list=PLhixgUqwRTjyakFK7puB3fHVfXMinqMSi
