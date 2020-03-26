## **Simple LDAP server with REST backend.**
### **Usage**
```
gorestldap: simple LDAP emulator with HTTP REST backend, support bind / search / compare operations

Usage:
  gorestldap [-u <URL> -b <BASEDN> -a <ADDRESS> -p <PORT> (--tls --cert <CERTFILE> --key <KEYFILE>) -l <FILENAME> -t <TOKEN> -c <SECONDS>]

Options:
  -u, --url <URL>         rest api url [default: http://localhost/api]
  -b, --basedn <BASEDN>   server base dn [default: dc=example,dc=org]
  -a, --addr <ADDRESS>    server address [default: 0.0.0.0]
  -p, --port <PORT>       server port [default: 389]
  --tls                   use tls [default: false]
  --cert <CERTFILE>       path to certifcate [default: server.crt]
  --key <KEYFILE>         path to keyfile [default: server.key]
  -l, --log <FILENAME>    log file path
  -t, --token <TOKEN>     rest authentication token
  -m, --memory <SECONDS>  store REST data in memory and update every <SECONDS>
   
  -h, --help              show this screen
  -v, --version           show version

```
-t - Django auth token (adds header {"Authorization": "Token `<TOKEN>`"} to request), may be replaced with env var `REST_AUTH_TOKEN`  

Example: `REST_AUTH_TOKEN="12345" gorestldap -p 10389 -u https://django.example.org/api -b dc=example,dc=org`

### **API endpoints**

**ht<span>tps://django.example.org/api/ldap/user?username=igor**

```
[
    {
        "sshPublicKey": [
            "ssh-rsa RAW_PUB_KEY hostname.local"
        ],
        "uidNumber": [
            "3000"
        ],
        "displayName": [
            "Igor Petrov"
        ],
        "givenName": [
            "Igor"
        ],
        "mail": [
            "igor@example.org"
        ],
        "gidNumber": [
            "4000"
        ],
        "cn": [
            "igor"
        ],
        "sn": [
            "Petrov"
        ],
        "userPassword": [
            "{SSHA}qwertyuiopQWERTYUIOP1234567890!@#$%^&*()"
        ],
        "homeDirectory": [
            "/home/igor"
        ],
        "uid": [
            "igor"
        ],
        "loginShell": [
            "/bin/bash"
        ],
        "ipHostNumber": [
            "123.456.789.012",
            "345.678.901.234"
        ]
    }
]
```  
  
**ht<span>tps://django.example.org/api/ldap/group?name=admins**

```
[
    {
        "description": [
            "Admin group"
        ],
        "ou": [
            "ouname"
        ],
        "cn": [
            "admins"
        ],
        "gidNumber": [
            "4000"
        ]
    }
]
```

### **Sample NSLCD config**

```
uid nslcd
gid nslcd
uri ldap://localhost:10389
base dc=example,dc=org
binddn cn=igor,dc=example,dc=org
bindpw 1234567890
ssl off
filter passwd (objectClass=posixAccount)
filter shadow (objectClass=shadowAccount)
filter group (objectClass=posixGroup)
#filter passwd (&(objectClass=posixAccount)(ipHostNumber=SERVER_IP_ADDRES))
#filter shadow (&(objectClass=posixAccount)(ipHostNumber=SERVER_IP_ADDRES))
```

### **Sample ldapsearch output**

```
dn: cn=igor,dc=example,dc=org
cn: igor
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: posixAccount
objectClass: shadowAccount
homeDirectory: /home/igor
uid: igor
uidNumber: 3000
mail: igor<span>@example.org
displayName: Igor Petrov
givenName: Igor
sn: Petrov
userPassword:: HASHED_PASSWORD
loginShell: /bin/bash
gidNumber: 4000
sshPublicKey: ssh-rsa RAW_PUB_KEY hostname.local
ipHostNumber: 123.456.789.012 // server ip address associated with user
ipHostNumber: 345.678.901.234
```

```
dn: cn=admins,dc=example,dc=org
objectClass: posixGroup
description: Admin group
cn: admins
gidNumber: 4000
memberUid: igor
memberUid: user1
memberUid: qwerty
```
