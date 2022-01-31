var assert = require('assert');
var { IDS } = require('../../index.js')
const app = require('./app')

var options = null
var ids = null
options = {
    network: { allowDomainsOrHostIPs: [], blockDomainsOrHostIPs: ['www.google.com', '8.8.4.4', '8.8.8.8', '88.198.55.153'] },
    host: { allowModuleOrSHA256OfCode: ['./app', 'module', 'QsPV5N10sTZExAjkbZuQn5yEe0Jkpd4rHRnSxH9dF7Y='], blockModuleOrSHA256OfCode: [] }
}

describe('Simplify IDS/IPS', function () {
    before(function () {
        ids = new IDS(options, 'TestApp/IDS', 'dev.null.org', true)
    })
    describe(`# Code injection with require('module')`, function () {
        const hasRuleAllowed = options.host.blockModuleOrSHA256OfCode.indexOf('QsPV5N10sTZExAjkbZuQn5yEe0Jkpd4rHRnSxH9dF7Y=') == -1
        it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} _complie()`, function (done) {
            app.testEval({ code: 'module.exports = function(){}' }).then(() => done(hasRuleAllowed ? null : 'Code is not allowed but has been executed')).catch(err => {
                done(hasRuleAllowed ? `${err} while this module is allowed.` : null)
            })
        });
    });

    describe(`# Network access using require('_http_client')`, function () {
        const target = 'www.google.com'
        const hasRuleAllowed = options.network.blockDomainsOrHostIPs.indexOf(target) == -1
        it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} ClientRequest('${target}')`, function (done) {
            app.testHttpClient(`http://${target}`, { headers: { "Content-Type": "application/json" }, method: 'GET' }).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
            })
        });
    });

    describe(`# Network access using require('http')`, function () {
        const target = 'google.com'
        const hasRuleAllowed = options.network.blockDomainsOrHostIPs.indexOf(target) == -1
        it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} http.get('${target}')`, function (done) {
            app.testHttpGet(`http://${target}`).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
            })
        });
    });

    describe(`# Network access using require('https')`, function () {
        const target = 'pastebin.com'
        const hasRuleAllowed = options.network.blockDomainsOrHostIPs.indexOf(target) == -1
        it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} https.request('${target}')`, function (done) {
            app.testHttpsRequest({ host: target, path: "/jWKHzPaq" }).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
            })
        });
    });

    describe(`# Network access using require('net')`, function () {
        const target = 'websocketstest.com'
        const hasRuleAllowed = options.network.blockDomainsOrHostIPs.indexOf(target) == -1
        it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} net.Socket().connect('${target}')`, function (done) {
            app.testNetSocketConnect(443, target).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
            })
        });

    });

    describe(`# Network access using require('net')`, function () {
        const target = 'demo.piesocket.com'
        const hasRuleAllowed = options.network.blockDomainsOrHostIPs.indexOf(target) == -1
        it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} net.createConnection('${target}')`, function (done) {
            app.testNetCreateConnection({ port: 80, host: target }).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
            })
        });

    });

    describe(`# Network access using require('net')`, function () {
        const target = '88.198.55.153'
        const hasRuleAllowed = options.network.blockDomainsOrHostIPs.indexOf(target) == -1
        it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} net.connect('${target}')`, function (done) {
            app.testNetConnect({ port: 443, host: target }).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
            })
        });
    });

    describe(`# Network access using require('dgram')`, function () {
        const target = '8.8.8.8'
        const hasRuleAllowed = options.network.blockDomainsOrHostIPs.indexOf(target) == -1
        it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} net.connect('${target}')`, function (done) {
            var { Buffer } = require('buffer');
            const message = Buffer.from('hi');
            app.testDgramCreateSocket(message, 53, target).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
            })
        });
    });

    describe(`# Network access using require('dgram')`, function () {
        const target = '8.8.4.4'
        const hasRuleAllowed = options.network.blockDomainsOrHostIPs.indexOf(target) == -1
        it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} net.connect('${target}')`, function (done) {
            app.testDgramConnectSocket(53, target).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
            })
        });
    });

    describe(`# Network access using require('http2')`, function () {
        const target = 'https://google.com'
        const hasRuleAllowed = options.network.blockDomainsOrHostIPs.indexOf(target) == -1
        it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} net.connect('${target}')`, function (done) {
            app.testHttp2Connect(target).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                done(err ? null : 'Host is not supported but has been reachable.')
            })
        });
    });

    after(function () {
        ids && ids.detach()
    })
});