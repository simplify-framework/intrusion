var { Firewall } = require('../../index.js')
new Firewall({
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
        const net = require('net');
        var socket = new net.Socket()
        var s = socket.connect(443, 'websocketstest.com', () => {
            s.destroy()
            const client = net.createConnection({ port: 443, host: 'websocketstest.com' }, () => {
                client.write('world!\r\n');
                const sc = net.connect({ port: 443, host: '88.198.55.153' }, () => {
                    sc.write('world!\r\n');
                }).on('error', () => { })
                client.on('data', (data) => {
                    client.end();
                });
                client.on('end', () => {
                });
            })
            client.on('data', (data) => {
                client.end();
            });
            client.on('end', () => {
            });
        });
    })
    r && r.end()
})
res && res.end()

