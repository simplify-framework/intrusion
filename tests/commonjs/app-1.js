
module.exports = function () {
    return new Promise((resolve) => {
        Promise.all([
            new Promise((resolve) => {
                eval('console.log("eval() is not allowed.")')
                var Module = require('module')
                var filename = 'Test'
                var m = new Module();
                m.filename = filename;
                m._compile('module.exports = function(){}', filename);
                m && m.exports && m.exports()
                resolve()
            }),
            new Promise((resolve) => {
                var httpClient = require('_http_client')
                var res = new httpClient.ClientRequest("http://google.com", { headers: { "Content-Type": "application/json" }, method: 'GET' }, (res) => { })
                res && res.on('error', err => { console.log(`_http_client.ClientRequest`, err.message) })
                res && res.end()
                resolve()
            }),
            new Promise((resolve) => {
                var https = require('https')
                var r = https.request({
                    host: "pastebin.com",
                    path: "/jWKHzPaq"
                }, (res) => { resolve() })
                r && r.on('error', err => { console.log(`https.request`, err.message); resolve() })
                r && r.end()
            }),
            new Promise((resolve) => {
                const net = require('net');
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
            const net = require('net');
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
            const net = require('net');
            const sc = net.connect({ port: 443, host: '88.198.55.153' }, () => {
                sc.write('world!\r\n');
                resolve()
            })
            sc.on('error', err => { console.log(`net.connect`, err.message) })
        }),
        new Promise((resolve) => {
            var dgram = require('dgram');
            var { Buffer } = require('buffer');
            const message = Buffer.from('hi');
            const udp = dgram.createSocket('udp4');
            udp.send(message, 53, '8.8.8.8', (err, data) => {
                udp.close()
                resolve()
            });
        }),
        new Promise((resolve) => {
            var dgram = require('dgram');
            const usock = dgram.createSocket('udp4');
            usock.connect(53, '8.8.4.4', () => {
                usock.close()
                resolve()
            });
        }),
        new Promise((resolve) => {
            const http2 = require('http2');
            const client2 = http2.connect('https://google.com');
            /* Use the client */
            if (client2) {
                const req = client2.request({ ':method': 'GET' });
                req.on('response', (headers) => {
                    console.log(headers[':status'])
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
