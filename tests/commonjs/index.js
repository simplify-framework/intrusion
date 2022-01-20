var { Firewall } = require('../../index.js')
var nodeFirewall = new Firewall({
    allowDomainsOrHostIPs: [],
    allowSHA256OfCodeModules: ["QsPV5N10sTZExAjkbZuQn5yEe0Jkpd4rHRnSxH9dF7Y="],
    blockedHashOrHostValues: []
}, 'TestApp/Firewall')

var path = require('path')
var https = require('https')

var httpClient = require('_http_client')

eval('console.log("eval() is not allowed.")')
var Module = require('module')
var filename = 'Test'
var m = new Module();
m.filename = filename;
m._compile('module.exports = function(){}', filename);
m.exports()

var res = new httpClient.ClientRequest("http://google.com", { headers: { "Content-Type": "application/json" }, method: 'GET' }, (res) => {
    var r = https.request("https://pastebin.com/jWKHzPaq", (res) => {
        nodeFirewall.detach()
    })
    r && r.end()
})
res && res.end()

