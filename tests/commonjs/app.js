function checkResult(host, value, defaultValue) {
    return (defaultValue ? defaultValue : host == null ? 'UNKNOWN' : host == value)
}

function getOptHostName(options) {
    let optURL = options[0]
    if (Number.isInteger(optURL)) {
        optURL = options[1]
        return optURL.startsWith('http') ? new URL(optURL).host : optURL
    }
    return typeof optURL == 'string' ? new URL(optURL).host : optURL.host || optURL.hostname
}

function testCompile(options) {
    return new Promise((resolve, reject) => {
        eval('console.log("eval() is not allowed.")')
        var Module = require('module')
        var filename = options.name || 'Test'
        var m = new Module();
        m.filename = filename;
        var result = m._compile(options.code || 'module.exports = function(){}', filename);
        if (m && m.exports) {
            m.exports()
            result ? resolve() : reject('Cannot compile this module: ' + filename)
        }
    })
}

function testModuleLoad() {
    return new Promise((resolve, reject) => {
        try {
            Object.keys(require.cache).forEach(function(key) { delete require.cache[key] })
            var test = require('requests')
            if (test) {
                Object.keys(test).length ? resolve() :  reject(`module is blocked.`)
            } else {
                reject(`module is not created.`)
            }
        } catch( err) { reject(err.message) }
    })
}


function testHttpClient(...options) {
    return new Promise((resolve, reject) => {
        var httpClient = require('_http_client')
        const optHostName = getOptHostName(options)
        var res = new httpClient.ClientRequest(...options, (res) => {
            res.on('data', (data) => {
                const check = checkResult(res.socket._host, optHostName)
                check ? resolve() : reject('Hostname has been redirected to ' + res.socket._host)
            });
        })
        res && res.on('error', err => {
            reject(err.message)
        })
        res && res.end()
    })
}

function testHttpGet(...options) {
    return new Promise((resolve, reject) => {
        var http = require('http')
        const optHostName = getOptHostName(options)
        var r = http.get(...options, (res) => {
            res.on('data', (data) => {
                const check = checkResult(res.socket._host, optHostName)
                check ? resolve() : reject('Hostname has been redirected to ' + res.socket._host)
            });
        })
        r && r.on('error', err => {
            reject(err.message)
        })
        r && r.end()
    })
}

function testHttpRequest(...options) {
    return new Promise((resolve, reject) => {
        var http = require('http')
        const optHostName = getOptHostName(options)
        var r = http.request(...options, (res) => {
            res.on('data', (data) => {
                const check = checkResult(res.socket._host, optHostName)
                check ? resolve() : reject('Hostname has been redirected to ' + res.socket._host)
            });
        })
        r && r.on('error', err => {
            reject(err.message)
        })
        r && r.end()
    })
}


function testHttpsRequest(...options) {
    return new Promise((resolve, reject) => {
        var https = require('https')
        const optHostName = getOptHostName(options)
        var r = https.request(...options, (res) => {
            res.on('data', (data) => {
                const check = checkResult(res.socket._host, optHostName)
                check ? resolve() : reject('Hostname has been redirected to ' + res.socket._host)
            });
        })
        r && r.on('error', err => {
            reject(err.message)
        })
        r && r.end()
    })
}

function testNetSocketConnect(...options) {
    return new Promise((resolve, reject) => {
        const net = require('net');
        var socket = new net.Socket()
        const optHostName = getOptHostName(options)
        var s = socket.connect(...options, () => {
            s.write('world!\r\n');
        });
        s.on('data', (data) => {
            const check = checkResult(s._host, optHostName)
            s.end();
            check ? resolve() : reject('Hostname has been redirected to ' + s._host)
        });
        s.on('error', err => {
            reject(err.message)
        })
    })
}

function testNetCreateConnection(...options) {
    return new Promise((resolve, reject) => {
        const net = require('net');
        const optHostName = getOptHostName(options)
        const client = net.createConnection(...options, () => {
            client.write('world!\r\n');
            client.on('data', (data) => {
                const check = checkResult(client._host, optHostName)
                client.end();
                check ? resolve() : reject('Hostname has been redirected to ' + client._host)
            });
        })
        client.on('error', err => {
            reject(err.message)
        })
    })
}

function testNetConnect(...options) {
    return new Promise((resolve, reject) => {
        const net = require('net');
        let hasDataResult = false
        const optHostName = getOptHostName(options)
        const sc = net.connect(...options, () => {
            sc.write('world!\r\n');
        })
        sc.on('data', (data) => {
            const check = checkResult(data.length, 280)
            hasDataResult = check
            sc.end();
            check ? resolve() : reject(`Sent data to ${optHostName} has received a wrong data length:` + data.length)
        });
        sc.on('error', err => {
            reject(err.message)
        })
        sc.on('end', () => {
            hasDataResult ? resolve() : reject('Hostname has been redirected to ' + sc._host)
        })
    })
}

function testDgramCreateSocket(...options) {
    return new Promise((resolve, reject) => {
        var dgram = require('dgram');
        const udp = dgram.createSocket('udp4');
        const optHostName = getOptHostName(options.slice(1))
        const result = udp.send(...options, (err, length) => {
            const resultHost = getOptHostName(result.slice(1))
            const check = checkResult(optHostName, resultHost)
            udp.close();
            check ? resolve() : reject(`Hostname has been redirected to ${resultHost}`)
        });
    })
}

function testDgramConnectSocket(...options) {
    return new Promise((resolve, reject) => {
        var dgram = require('dgram');
        const usock = dgram.createSocket('udp4');
        const optHostName = getOptHostName(options)
        const result = usock.connect(...options, (err) => {
            const resultHost = getOptHostName(result)
            const check = checkResult(optHostName, resultHost)
            usock.close()
            check ? resolve() : reject(`Hostname has been redirected to ${resultHost}`)
        });
    })
}

function testHttp2Connect(...options) {
    return new Promise((resolve, reject) => {
        const http2 = require('http2');
        const client2 = http2.connect(...options);
        /* Use the client */
        if (client2) {
            const req = client2.request({ ':method': 'GET' });
            req.on('response', (headers) => {
                console.log(headers[':status'])
                client2.close(); resolve()
            });
            req.on('error', err => {
                reject(`${err.message}`)
            })
        } else {
            reject(`cannot initiate http2.connect()`)
        }
    })
}

module.exports = {
    testCompile,
    testModuleLoad,
    testHttpClient,
    testHttpGet,
    testHttpRequest,
    testHttpsRequest,
    testNetSocketConnect,
    testNetCreateConnection,
    testNetConnect,
    testDgramCreateSocket,
    testDgramConnectSocket,
    testHttp2Connect
}
