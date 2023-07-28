## Lightweight Directory Access Protocol (LDAP)

> Category: Webex - computer networking standard

The Lightweight Directory Access Protocol (LDAP) is an open-source application protocol that allows applications to access and authenticate specific user information across any organization's network. Employees working in most organizations need to regularly access email addresses, usernames, passwords, printers etc. to fulfill their daily tasks. This information is stored on company directories and LDAP is one such protocol that efficiently connects users and devices to this information. The protocol can also be used to

LDAP can be used:

- for user identity verification and authentication to provide Single Sign On (SSO)
- to configure network infrastructure such as firewalls and bridges
- to maintain and provision server infrastructure, printers, scanners etc

The two most popular directory services that communicate using LDAP are:

- Microsoft Active Directory
  Outlook email, managing multiple windows computers etc.
- OpenLDAP
  A free and open source LDAP implementation
  LDAP is a **protocol** whereas Active Directory is an **application**. LDAP can also be used with other programs, including those based on Linux, hence it's a vendor-neutral protocol.

LDAP is a subset of the standards contained within the X.500 standard because of which it's sometimes called X.500-lite.

# Operation

LDAP has three broad types of operations:

- Update
  This includes adding, deleting, or modifying directory information
- Query
  This includes searching and comparing directory information
- Authenticate and authorize
  - Simple
    Basic username and password validation, credentials not encrypted in transit
  - Simple Authentication and Security Layer (SASL)
    Credentials are encrypted in transit and a secondary service such as a Kerberos server performs additional authentication before the user can connect

An LDAP query typically involves:

- Session connection
  The user connects to the server via port 389 (port 636 for LDAP over SSL)
- Request
  The user submits a query to the server, such as an email lookup
- Response
  The LDAP protocol queries the directory, finds the information, and delivers it to the user
- Completion
  The user disconnects from the LDAP port

# Directory structure

- Any entry consists of a set of attributes
  An attribute has a name and one or more values
- Other than the attributes, each entry has a unique identifier called the Distinguished Name (DN)
  The DN is analogous to a full file path and the RDN is like a relative filename

Example entry when represented in LDAP Data Interchange Format (LDIF) which is a plain text format:

```
dn: cn=John Doe,dc=example,dc=com
cn: John Doe
givenName: John
sn: Doe
telephoneNumber: +1 888 555 6789
telephoneNumber: +1 888 555 1232
mail: john@example.com
objectClass: inetOrgPerson
objectClass: organizationalPerson
```

In the above example, "dn" is the distinguished name of the entry whereas "cn=John Doe" is the entry's RDN (Relative Distinguished Name), and "dc=example,dc=com" is the DN of the parent entry, where "dc" denotes 'Domain Component'. The other lines show the attributes in the entry. Attribute names are typically mnemonic strings, like "cn" for common name, "dc" for domain component, "mail" for e-mail address, and "sn" for surname.

LDAP rarely defines any ordering: The server may return the values of an attribute or the entries found by a search operation in any order. This follows from the formal definitions - an entry is defined as a set of attributes, and an attribute is a set of values, and sets need not be ordered.

# URI scheme

LDAP uniform resource identifier (URI) scheme:

```
ldap://host:port/DN?attributes?scope?filter?extensions
```

For example, `"ldap://ldap.example.com/cn=John%20Doe,dc=example,dc=com"` refers to all user attributes in John Doe's entry in `ldap.example.com`, while `"ldap:///dc=example,dc=com??sub?(givenName=John)"` searches for the entry in the default server (note the triple slash, omitting the host, and the double question mark, omitting the attributes). As in other URLs, special characters must be percent-encoded.

# LDAP injection

LDAP injection arises when user-controllable data is copied in an unsafe way into an LDAP query that is performed by the application. If an attacker can inject LDAP metacharacters `(( ) ; , \* | & = \ # + < > , " and whitespace )` into the query, then they can interfere with the query's logic. Depending on the function for which the query is used, the attacker may be able to retrieve sensitive data to which they are not authorized, or subvert the application's logic to perform some unauthorized action.

### References:

- https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol
- https://www.upguard.com/blog/ldap
- https://portswigger.net/kb/issues/00100500_ldap-injection
- https://userpages.umbc.edu/~dgorin1/451/DIR/ldap.pdf
