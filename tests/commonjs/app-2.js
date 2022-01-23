
const http2 = require('http2');
const client2 = http2.connect('https://google.com');
var Module = require('module')
var httpClient = require('_http_client')
var https = require('https')
const net = require('net');
var dgram = require('dgram');
var { Buffer } = require('buffer');

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
                var res = new httpClient.ClientRequest("http://google.com", { headers: { "Content-Type": "application/json" }, method: 'GET' }, (res) => {
                    res.on('data', (data) => {
                        console.log(`\t\t_http_client.ClientRequest("http://google.com") - ${data.length}`)
                    });
                })
                res && res.on('error', err => { console.log(`\t\t_http_client.ClientRequest("http://google.com")`, err.message) })
                res && res.end()
                resolve()
            }),
            new Promise((resolve) => {
                var r = https.request({
                    host: "pastebin.com",
                    path: "/jWKHzPaq"
                }, (res) => {
                    res.on('data', (data) => {
                        console.log(`\t\thttps.request("https://pastebin.com//jWKHzPaq") - ${data.length}`)
                        resolve()
                    });
                })
                r && r.on('error', err => { console.log(`https.request`, err.message); resolve() })
                r && r.end()
            }),
            new Promise((resolve) => {
                var socket = new net.Socket()
                var s = socket.connect(443, 'websocketstest.com', () => {
                    s.write('world!\r\n');
                });
                s.on('data', (data) => {
                    console.log(`\t\tsocket.connect("websocketstest.com") - ${data.length}`)
                    s.end();
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
                        console.log(`\t\tnet.createConnection("demo.piesocket.com") - ${data.length}`)
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
                })
                sc.on('data', (data) => {
                    console.log(`\t\tnet.connect("88.198.55.153:443") - ${data.length}`)
                    sc.end();
                });
                sc.on('error', err => { console.log(`net.connect`, err.message) })
                sc.on('end', () => {
                    resolve()
                });
            }),
            new Promise((resolve) => {
                const message = Buffer.from('hi');
                const udp = dgram.createSocket('udp4');
                udp.send(message, 53, '8.8.8.8', (err, data) => {
                    console.log(`\t\tdgram.createSocket("8.8.8.8:53") - ${data}`)
                    udp.close();
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
