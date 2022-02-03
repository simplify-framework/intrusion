### SimplifyFramework - IDS/IPS (Network/Module) : NodeJS version >= 12.x

![NPM Downloads](https://img.shields.io/npm/dw/simplify-intrusion)
![Package Version](https://img.shields.io/github/package-json/v/simplify-framework/intrusion?color=green)

- Host Intrusion Detection and Prevention
  + Detect modules are loaded by require('module').
  + Detect modules are compiled by module._compile('code').
  + Block or allow some modules by names or by hashcodes.

- Network Intrusion Detection and Prevention
  + Detect HTTP/HTTPS/UDP/TCP outbound connection.
  + Block or allow by domain names or IP addresses.
  + Redirect the outbound connection to a honeypot.

````diff
WARNING: This library does not handle the require('net').Socket.connect() function.
````

### Setup your AWS environment or IAM Role in your Lambdas with this permission:

This library requires AWS IAM Role to allow publishing the CloudWatch Metrics to a custom namespace:

**The process.env.`IDS_ENABLE_METRIC_LOGGING`=true|`false` will turn ON or OFF the AWS CloudWatch metric collector.**

**The process.env.`IDS_ENABLE_MODULE_TRACKER`=true|`false` will turn ON or OFF the modules tracker (not listen for require(...)).**

**The process.env.`IDS_PRINT_OUTPUT_LOG`=true|`false` will turn ON or OFF the console output logs (silent mode).**

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
- new IDS({}, '`TestApp/IDS`' /* Custom Namespace */)


### AWS/Lambda - Make a build then attach to a Lambda function by using command line

- `simplify-intrusion --bucket YOUR_BUCKET_NAME --layer-name YOUR_IDS_LAYER_NAME make`
- `simplify-intrusion --function-name YOUR_TARGET_FUNCTION attach`

### SDK/Library - Use the { IDS } module to detect the intrustion outbound network from your code:

1. Load the library with IDS configuration:

```Javascript
var { IDS } = require('simplify-intrusion')
var nodeFirewall = new IDS({
    network: { allowDomainsOrHostIPs: [
      /* a whitelist of domains or IPs that is allowed to access from your code, startsWith('string') rule */
    ], blockDomainsOrHostIPs: [
      /* the blacklist of domains or IPs you want to BLOCK them from your code, startsWith('string') rule */
      /* example: ['*'] => block all outbound network connection from host, allowed all connections by default */
    ] },
    host: { allowModuleOrSHA256OfCode: [
      /* a whitelist of module name or SHA-256('code') that will be embeded by using module._complie(), startsWith('string') rule */
    ], blockModuleOrSHA256OfCode: [
      /* the blacklist of module name or SHA-256('code') that contains the untrusted HASH of modules, startsWith('string') rule */
      /* example: ['QsPV5N10sTZExAjkbZuQn5yEe0Jkpd4rHRnSxH9dF7Y=', 'buffer:4.9.2', 'request:2.88.'] */
    ] }
  },
  'YourApp/IDS' /* log metrics to your custom CloudWatch NameSpace if the CloudWatch Metrics is enabled */,
  'dev.null.org' /* if BLOCKED, reflect the requests to a honeypot server: dev.null.org */,
  false /* true = set the CloudWatch Metrics is enabled */)
```

2. Write your code with all the require('...') after the line above.

```Javascript
var http = require('http')
var https = require('https')
var { ClientRequest } = require('_http_client_')
var module = require('module')

/*an example of your lambda code*/
module.exports.handler = function(event, context, callback) {
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

### EXAMPLE - Running an example of intrusion code.

1. Install Simplify Framework - Intrustion library
- `npm install simplify-intrustion`

2. Create example.js node application

```JavaScript
var { IDS } = require('simplify-intrusion')
var nodeFirewall = new IDS({
    network: { allowDomainsOrHostIPs: [], blockDomainsOrHostIPs: [] },
    host: { allowModuleOrSHA256OfCode: ['OtbUd5po/kQtu2FweSNa42kOfFYZvlsFuen1xXeOPKs='], blockModuleOrSHA256OfCode: ['*'] }
}, 'TestApp/IDS', 'dev.null.org')

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

  >>>> [Blocked] (function:eval) EXEC - console.log("eval() is not allowed.")
require-from-string: OK
  >>>> [Warning] (_http_client) GET - http://google.com
  >>>> [Allowed] (module:compile) Test - OtbUd5po/kQtu2FweSNa42kOfFYZvlsFuen1xXeOPKs=
  >>>> [Warning] (https:request) GET - https://google.com/
```