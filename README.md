## **Simple LDAP server with REST API & file backends.**
Server loads JSON data from backend and holds it in memory for future processing in LDAP requests. Data will be reloaded after timeout specified in `--interval` arg.  
There are two backends: rest (loads json from REST API) and file (loads json from file).  

Server support bind, search, compare and modify (only replace) operations. It can handle paged results search control (1.2.840.113556.1.4.319).  
Search with unsupported critical controls requested can be handled with `respect_control_criticality` set to false.  

### **Usage**
```
gorestldap: LDAP server with REST API & file backends

Usage:
  gorestldap [-b <BACKEND> -c <CONFIGPATH> -B <BASEDN> -L <LISTENADDR> -I <INTERVAL> -l <LOGPATH> -d]

Options:
  -c, --config <CONFIGPATH>  config file path [default: config.yaml, env: CONFIG_PATH]
  -b, --backend <BACKEND>    backend to use [default: rest, env: BACKEND]
  -B, --basedn <BASEDN>      server base dn [default: dc=example,dc=com, env: BASE_DN]
  -L, --listen <LISTENADDR>  listen addr for LDAP [default: 0.0.0.0:389, env: LDAP_LISTEN_ADDR]
  -I, --interval <INTERVAL>  data update interval [default: 300s, env: UPDATE_INTERVAL] 
  -l, --log <LOGPATH>        log file path
  -d, --debug                turn on debug logging [default: false] 

  -h, --help                 show this screen
  --version                  show version

```

### **Compile**
Just type `make`

### **Run**
`./build/gorestldap -L localhost:10389 -d -b <PLUGIN_NAME>`  

### **Examples**
Admin credentials is `admin:admin`.  
To start django server type `make server` and copy auth token from django migration output to config.yaml. Then start ldap server:  
`./build/gorestldap -L localhost:10389 -d -b rest`  
User can be managed through django admin interface at `http://localhost:8000/admin`.  

<img src="https://user-images.githubusercontent.com/31385755/209757267-f78e61d2-b46e-487f-a81c-5afe7bc26950.png" width="50%" height="50%">  

To run with file plugin, set backend to file (`-b file`).  

### **Callback**
Callback listener may be used for data reload (HEAD with auth token `curl -v -I localhost:8080/callback -H "Authorization: Token qwertyuiop1234567890"`).  
