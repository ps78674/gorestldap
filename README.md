## **Simple LDAP server with REST API & file backends.**
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
Server loads JSON data from rest or file backends and holds it in memory. Data will be reloaded after timeout specified in `--interval` arg.  
Rest plugin uses REST API for input data (for example, DRF).  
File plugin - simple file with JSON.  

### **Compile**
Just type `make`

### **Run**
There are some example data in `examples` folder.  
To start django server type `make server` and copy auth token from django migration output to config.yaml. Then start ldap server:  
`./build/gorestldap -L localhost:10389 -d -b rest`  
To run with file plugin, set backend to file (`-b file`).  

Example credetials `admin:admin`.  

Callback listener may be used for data reload (HEAD with auth token `curl -v -I localhost:8080/callback -H "Authorization: Token qwertyuiop1234567890"`).  
