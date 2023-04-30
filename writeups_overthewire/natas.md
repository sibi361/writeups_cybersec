#### Writeup on https://overthewire.org/wargames/natas/

#### Level 0

Flag is available in website source : `g9D9cREhslqBKtcA2uocGHPfMZVzeFK6`

#### Level 0 → Level 1

Can visit website source using Ctrl + U : `h4ubbcXrWqsTo7GGnnUMLppXbOogfBZ7`

#### Level 1 → Level 2

Go to /files/users.txt : `G6ctbMJ5Nb4cbFwhpMPSvxGHhQ7I6W8Q`

#### Level 2 → Level 3

Comment on website source says "Not even Google will find it this time", hence we go to /robots.txt from where we get to /s3cr3t/users.txt : `tKOcJIbzM4lTs8hbCmzn5Zr4434fGZQm`

#### Level 3 → Level 4

Need to modify "Referer" header to "http://natas5.natas.labs.overthewire.org/" in order to make the server think that we are coming from that domain : `Z0NsrtIkJoKALBCLi5eqFfcRN82Au2oD`

#### Level 4 → Level 5

Set "loggedin" cookie's value to "1" using a cookie editing browser extension : `fOIvE0MDtPTgRhqmmvvAOt2EfXR6uQgR`

#### Level 5 → Level 6

source tells us that the password is located at "includes/secret.inc", submitting in on the form gives the flag : `jmxSiH3SP6Sonf8dv66ng8v1cIEdjXWr`

#### Level 6 → Level 7

IDOR available, i.e. any text passed to the `page` param is directly `cat`, hence utilizing hint in the website source we visit `http://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8` : `a6bZCNYwdKqN5cGP11ZdtPg0iImQQhAB`

#### Level 7 → Level 8

Reverse engineering the `encodeSecret()` function gets us the required password:

- convert the value of the `encodedSecret` variable to binary format using [hex2bin()](https://onlinephp.io/hex2bin)
- reverse the obtained output using the `rev` command and `base64` decode it: `echo ==QcCtmMml1ViV3b | rev | base64 -d`
- enter the obtained string in the form to get the password : `Sda6t0vkOPkM8YeOZkAGVhFoaplvlJFd`

#### Level 8 → Level 9

Source code tells us that user input is being directly substituted in the command `grep -i $key dictionary.txt` hence giving [RCE](https://en.wikipedia.org/wiki/Remote_code_execution). Semicolons can be used to end have multiple commands on a single line, thus entering `; cat /etc/natas_webpass/natas10;` in the form gives us the flag : `D44EcsFkLxPIkAAKLosx8z3hxX1Z4MCE`

#### Level 9 → Level 10

The `preg_match()` function is checking for any character matching the regex `[;|&]` and hence we can't use semicolons anymore. We know that multiple files can be passed to `grep`, thus we pass the `/etc/natas_webpass/natas10` file to `grep` along with the "match everything" regex `.*` with the `-e` flag: `-e ".\*" /etc/natas_webpass/natas10` : `D44EcsFkLxPIkAAKLosx8z3hxX1Z4MCE`

#### End of writeup
