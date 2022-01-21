
const http2 = require('http2');
const client2 = http2.connect('https://google.com');
var Module = require('module')
var httpClient = require('_http_client')
var https = require('https')
const net = require('net');
var dgram = require('dgram');

module.exports = function () {
    return new Promise((resolve) => {
        Promise.all([
            new Promise((resolve) => {
                eval('console.log("eval() is not allowed.")')
                var filename = 'Test'
                var m = new Module();
                m.filename = filename;
                m._compile('module.exports = function(){}', filename);
                m && m.exports && m.exports()
                resolve()
            }),
            new Promise((resolve) => {
                var res = new httpClient.ClientRequest("http://google.com", { headers: { "Content-Type": "application/json" }, method: 'GET' }, (res) => { })
                res && res.on('error', err => { console.log(`_http_client.ClientRequest`, err.message) })
                res && res.end()
                resolve()
            }),
            new Promise((resolve) => {
                var r = https.request({
                    host: "pastebin.com",
                    path: "/jWKHzPaq"
                }, (res) => { resolve() })
                r && r.on('error', err => { console.log(`https.request`, err.message); resolve() })
                r && r.end()
            }),
            new Promise((resolve) => {
                var socket = new net.Socket()
                var s = socket.connect(443, 'websocketstest.com', () => {
                    s.destroy()
                });
                s.on('error', err => { console.log(`net.Socket`, err.message); resolve() })
                s.on('end', () => {
                    resolve()
                })
            }),
            new Promise((resolve) => {
                const client = net.createConnection({ port: 80, host: 'demo.piesocket.com' }, () => {
                    client.write('world!\r\n');
                    client.on('data', (data) => {
                        client.end();
                    });
                })
                client.on('error', err => { console.log(`net.createConnection`, err.message) })
                client.on('end', () => {
                    resolve()
                });
            }),
            new Promise((resolve) => {
                const sc = net.connect({ port: 443, host: '88.198.55.153' }, () => {
                    sc.write('world!\r\n');
                    resolve()
                })
                sc.on('error', err => { console.log(`net.connect`, err.message) })
            }),
            new Promise((resolve) => {
                var { Buffer } = require('buffer');
                const message = Buffer.from('hi');
                const udp = dgram.createSocket('udp4');
                udp.send(message, 53, '8.8.8.8', (err, data) => {
                    udp.close()
                    resolve()
                });
            }),
            new Promise((resolve) => {
                const usock = dgram.createSocket('udp4');
                usock.connect(53, '8.8.4.4', () => {
                    usock.close()
                    resolve()
                });
            }),
            new Promise((resolve) => {
                /* Use the client */
                if (client2) {
                    const req = client2.request({ ':method': 'GET' });
                    req.on('response', (headers) => {
                        client2.close(); resolve()
                    });
                    req.on('error', err => { console.log(`http2`, err.message); resolve() })
                } else {
                    resolve()
                }
            })
        ]).then(() => resolve())
    })
}
