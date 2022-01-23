
function checkResult(host, value, defaultValue) {
    return defaultValue ? defaultValue : host == null ? 'UNKNOWN' : host == value ? 'RECEIVED' : 'BLOCK'
}
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
                var res = new httpClient.ClientRequest("http://google.com", { headers: { "Content-Type": "application/json" }, method: 'GET' }, (res) => {
                    res.on('data', (data) => {
                        console.log(`\t\t_http_client.ClientRequest("http://google.com") - ${data.length}`, checkResult(res.socket._host, 'google.com'))
                    });
                })
                res && res.on('error', err => { console.log(`\t\t_http_client.ClientRequest("http://google.com")`, err.message) })
                res && res.end()
                resolve()
            }),
            new Promise((resolve) => {
                var http = require('http')
                var r = http.get("http://google.com/", (res) => {
                    res.on('data', (data) => {
                        console.log(`\t\thttp.request("http://google.com/") - ${data.length}`, checkResult(res.socket._host, 'google.com'))
                        resolve()
                    });
                })
                r && r.on('error', err => { console.log(`http.request`, err.message); resolve() })
                r && r.end()
            }),
            new Promise((resolve) => {
                var https = require('https')
                var r = https.request({
                    host: "pastebin.com",
                    path: "/jWKHzPaq"
                }, (res) => {
                    res.on('data', (data) => {
                        console.log(`\t\thttps.request("https://pastebin.com/jWKHzPaq") - ${data.length}`, checkResult(res.socket._host, 'pastebin.com'))
                        resolve()
                    });
                })
                r && r.on('error', err => { console.log(`https.request`, err.message); resolve() })
                r && r.end()
            }),
            new Promise((resolve) => {
                const net = require('net');
                var socket = new net.Socket()
                var s = socket.connect(443, 'websocketstest.com', () => {
                    s.write('world!\r\n');
                });
                s.on('data', (data) => {
                    console.log(`\t\tsocket.connect("websocketstest.com") - ${data.length}`, checkResult(s._host, 'websocketstest.com'))
                    s.end();
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
                        console.log(`\t\tnet.createConnection("demo.piesocket.com") - ${data.length}`, checkResult(client._host, 'demo.piesocket.com'))
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
                })
                sc.on('data', (data) => {
                    console.log(`\t\tnet.connect("88.198.55.153:443") - ${data.length}`, checkResult(data.length == 280 ? '88.198.55.153' : '', '88.198.55.153'))
                    sc.end();
                });
                sc.on('error', err => { console.log(`net.connect`, err.message) })
                sc.on('end', () => {
                    resolve()
                });
            }),
            new Promise((resolve) => {
                var dgram = require('dgram');
                var { Buffer } = require('buffer');
                const message = Buffer.from('hi');
                const udp = dgram.createSocket('udp4');
                udp.send(message, 53, '8.8.8.8', (err, data) => {
                    console.log(`\t\tdgram.send("8.8.8.8:53") - ${data}`, checkResult(data == 2 ? '8.8.8.8' : '', '8.8.8.8', 'SENT'))
                    udp.close();
                    resolve()
                });
            }),
            new Promise((resolve) => {
                var dgram = require('dgram');
                const usock = dgram.createSocket('udp4');
                usock.connect(53, '8.8.4.4', (err) => {
                    console.log(`\t\tdgram.connect("8.8.4.4:53") - ${err ? err : 'CONNECTED'}`)
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
