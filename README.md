## **Simple LDAP server with REST backend.**
### **Usage**
```
gorestldap: simple LDAP emulator with HTTP REST backend, support bind / search / compare operations

Usage:
  gorestldap [-u <URL> -b <BASEDN> -a <ADDRESS> -p <PORT> (-P <PORT>|--nocallback) (--tls --cert <CERTFILE> --key <KEYFILE>) -l <FILENAME> -t <TOKEN> -T <SECONDS> -C]
  gorestldap [-f <FILE> -b <BASEDN> -a <ADDRESS> -p <PORT> (--tls --cert <CERTFILE> --key <KEYFILE>) -l <FILENAME> -T <SECONDS> -C]

Options:
  -u, --url <URL>          rest api url [default: http://localhost/api]
  -f, --file <FILE>        file with rest data
  -b, --basedn <BASEDN>    server base dn [default: dc=example,dc=org]
  -a, --addr <ADDRESS>     server address [default: 0.0.0.0]
  -p, --port <PORT>        server port [default: 389]
  -P, --httpport <PORT>    http port for callback [default: 8080]
  --nocallback             disable http callback [default: false]
  --tls                    use tls [default: false]
  --cert <CERTFILE>        path to certifcate [default: server.crt]
  --key <KEYFILE>          path to keyfile [default: server.key]
  -l, --log <FILENAME>     log file path
  -t, --token <TOKEN>      rest authentication token
  -T, --timeout <SECONDS>  update REST data every <SECONDS>
  -C, --criticality        respect requested control criticality
   
  -h, --help               show this screen
  -v, --version            show version

```
-t - Django auth token (adds header {"Authorization": "Token `<TOKEN>`"} to request), may be replaced with env var `REST_AUTH_TOKEN`  
Example: `REST_AUTH_TOKEN="12345" gorestldap -p 10389 -u https://django.example.org/api -b dc=example,dc=org -m 300`

Callback url may be used for in-memory user/group updating  
Example: `curl localhost:8080/callback -X POST -H "Content-Type: application/json" -d '{"type":"user","cn":"igor"}'`

### **File JSON structure**
```
{
    "users":[...],
    "groups":[...]
}
```

### **API endpoints**

**ht<span>tps://django.example.org/api/ldap/user?username=igor**

```
[
    {
    {
        "entryUUID": "11111111-1111-1111-1111-111111111111",
        "sshPublicKey": [
            "ssh-rsa RAW_PUB_KEY hostname.local"
        ],
        "uidNumber": "3000",
        "displayName": "Igor Petrov",
        "mail": "igor@example.org",
        "gidNumber": "4000",
        "cn": "igor",
        "userPassword": "{SSHA}qwertyuiopQWERTYUIOP1234567890!@#$%^&*()",
        "memberOf": [
            "group1",
            "group2"
        ],
        "objectClass": [
            "top",
            "posixAccount",
            "shadowAccount",
            "organizationalPerson",
            "inetOrgPerson",
            "person"
        ],
        "hasSubordinates": "FALSE",
        "givenName": "Igor",
        "sn": "Petrov",
        "homeDirectory":"/home/igor",
        "uid": "igor",
        "loginShell": "/bin/bash"
    }
]
```  
  
**ht<span>tps://django.example.org/api/ldap/group?name=admins**

```
[
    {
        "entryUUID": "11111111-1111-1111-1111-111111111111",
        "gidNumber": "4000",
        "description": "Admin group",
        "cn": "admins",
        "ou": [
            "ouname"
        ],
        "objectClass": [
            "top",
            "posixGroup"
        ],
        "hasSubordinates": "FALSE"
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
#filter passwd (&(objectClass=posixAccount)(memberof=group1))
#filter shadow (&(objectClass=posixAccount)(memberof=group1))
```

### **Sample ldapsearch output**

```
dn: cn=igor,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: posixAccount
objectClass: shadowAccount
cn: igor
uidNumber: 3000
userPassword:: HASHED_PASSWORD
gidNumber: 4000
uid: igor
displayName: Igor Petrov
givenName: Igor
sn: Petrov
mail: igor<span>@example.org
homeDirectory: /home/igor
loginShell: /bin/bash
memberOf: group1
memberOf: group2
sshPublicKey: ssh-rsa RAW_PUB_KEY hostname.local
```

```
dn: cn=admins,dc=example,dc=org
objectClass: posixGroup
cn: admins
gidNumber: 4000
description: Admin group
ou: test
memberUid: igor
memberUid: user1
memberUid: qwerty
```
