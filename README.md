### HOW TO: SimplifyFramework - IDS/IPS (Intrusion Detection/Prevention)

1. Install Simplify Framework - Intrustion library
- `npm install simplify-intrustion`

2. Create example.js node application

```JavaScript
var { Firewall } = require('simplify-intrusion')
var nodeFirewall = new Firewall({
    allowDomainsOrHostIPs: [],
    allowSHA256OfCodeModules: ["OtbUd5po/kQtu2FweSNa42kOfFYZvlsFuen1xXeOPKs="],
    blockedValues: []
}, 'TestApp/Firewall')

var path = require('path')
var https = require('https')

var httpClient = require('_http_client')

eval('console.log("eval() is not allowed.")')
var requireFromString = require('require-from-string')
var rq = requireFromString('module.exports = function(){console.log("require-from-string: OK")}', 'Test')
typeof rq == 'function' && rq()
var res = new httpClient.ClientRequest("http://google.com", { headers: { "Content-Type": "application/json" }, method: 'GET' }, (res) => {
    var r = https.request("https://google.com", (res) => {
        nodeFirewall.detach()
    })
    r && r.end()
})
res && res.end()

```

3. Run `node example.js`

Expected outcome:

```bash
$ node example.js
╓───────────────────────────────────────────────────────────────╖
║          Simplify Framework - IDS/IPS Version 0.1.0           ║
╙───────────────────────────────────────────────────────────────╜
  >>>> [Blocked] (function:eval) EXEC - console.log("eval() is not allowed.")
require-from-string: OK
  >>>> [Warning] (_http_client) GET - http://google.com
  >>>> [Allowed] (module:compile) Test - OtbUd5po/kQtu2FweSNa42kOfFYZvlsFuen1xXeOPKs=
  >>>> [Warning] (https:request) GET - https://switchmail.com/
```