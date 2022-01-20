### SimplifyFramework - IDS/IPS (Intrusion Detection/Prevention)

![NPM Downloads](https://img.shields.io/npm/dw/simplify-intrusion)
![Package Version](https://img.shields.io/github/package-json/v/simplify-framework/intrusion?color=green)

### Setup your AWS environment or IAM Role in your Lambdas with this permission:

This library requires AWS IAM Role to allow publishing the CloudWatch Metrics to a custom namespace:

```yaml
Policies:
  - PolicyName: cloudwatch-metrics
    PolicyDocument:
      Statement:
      - Effect: Allow
        Action:
        - cloudwatch:PutMetricData
        Resource: "*"
```

The metrics' namespace is set in the constructor at 2nd parameter: 
- new Firewall({}, '`TestApp/Firewall`' /* Custom Namespace */)

### Use the { Firewall } to detect the intrustion outbound network from your code:

1. Load the library with Firewall configuration:

```Javascript
var { Firewall } = require('simplify-intrusion')
var nodeFirewall = new Firewall({
    allowDomainsOrHostIPs: [/* a whitelist of domains or IPs that is allowed to access from your code */],
    allowSHA256OfCodeModules: [ /* a whitelist of SHA-256('code') that will be embeded by using module._complie() */],
    blockedHashOrHostValues: [ /* the blacklist of SHA-256('code'), domains or IPs you want to BLOCK them from your code */]
}, 'YourApp/Firewall' /* your custom CloudWatch NameSpace */)
```

2. Write your code with all the require('...') after the live above.

```Javascript
var http = require('http')
var https = require('https')
var { ClientRequest } = require('_http_client_')
var module = require('module')

/*an example of your lambda code*/
module.exports = function(event, context, callback) {
  //DO SOMETHING LIKE CALL EXTERNAL APIS
  var r = https.request("https://google.com/api/...", (res) => {
      console.log(res)
  })
  r && r.end()
}

```

3. Detaching the library when everything is done:

```Javascript
somePromiseOrCallbackFunction().then(response => {
  nodeFirewall.detach()
  callback(null, response)
})
```

### Running an example of intrusion code.

1. Install Simplify Framework - Intrustion library
- `npm install simplify-intrustion`

2. Create example.js node application

```JavaScript
var { Firewall } = require('simplify-intrusion')
var nodeFirewall = new Firewall({
    allowDomainsOrHostIPs: [],
    allowSHA256OfCodeModules: ["OtbUd5po/kQtu2FweSNa42kOfFYZvlsFuen1xXeOPKs="],
    blockedHashOrHostValues: []
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