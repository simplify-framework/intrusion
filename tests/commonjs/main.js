module.exports = {
    run: function (app, type, { name, options }, idx) {
        var { IDS } = require('../../index.js')
        var stdoutWrite = null
        var ids = null
        function checkHasRuleAllowed(blockValues, allowValues, check) {
            return (allowValues.find(x => x == '*' || x == check) ? true : false) ||
                (blockValues.find(x => x == '*' || x == check) ? false : true)
        }
        describe(`(${type}) Option ${idx + 1} - ${name}`, function () {
            before(function () {
                ids = new IDS(options, 'TestApp/IDS', 'dev.null.org', true)
                stdoutWrite = console.log
                console.log = function (...args) { stdoutWrite('\t',...args) }
            })
            describe(`# Code injection with module from string`, function () {
                const hasRuleAllowed = checkHasRuleAllowed(options.host.blockModuleOrSHA256OfCode, options.host.allowModuleOrSHA256OfCode, 'QsPV5N10sTZExAjkbZuQn5yEe0Jkpd4rHRnSxH9dF7Y=')
                it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} _compile()`, function (done) {
                    app.testCompile({ code: 'module.exports = function(){}' }).then(() => done(hasRuleAllowed ? null : 'Code is not allowed but has been executed')).catch(err => {
                        done(hasRuleAllowed ? `${err} while this module is allowed.` : null)
                    })
                });
            });

            describe(`# Module load from file with require('...')`, function () {
                const moduleName = 'requests' /** fixed - donot change to another module */
                const hasRuleAllowed = checkHasRuleAllowed(options.host.blockModuleOrSHA256OfCode, options.host.allowModuleOrSHA256OfCode, moduleName)
                const itFn = process.env.IDS_ENABLE_MODULE_TRACKER == "true" ? it : it.skip
                itFn(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} require('${moduleName}')`, function (done) {
                    app.testModuleLoad().then(() => done(hasRuleAllowed ? null : 'Module is not allowed but has been loaded')).catch(err => {
                        done(hasRuleAllowed ? `${err} while this module is allowed.` : null)
                    })
                });
            });

            describe(`# Network access using require('_http_client')`, function () {
                const target = 'www.google.com'
                const hasRuleAllowed = checkHasRuleAllowed(options.network.blockDomainsOrHostIPs, options.network.allowDomainsOrHostIPs, target)
                it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} ClientRequest('${target}')`, function (done) {
                    app.testHttpClient(`http://${target}`, { headers: { "Content-Type": "application/json" }, method: 'GET' }).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                        done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
                    })
                });
            });

            describe(`# Network access using require('http').get`, function () {
                const target = 'google.com'
                const hasRuleAllowed = checkHasRuleAllowed(options.network.blockDomainsOrHostIPs, options.network.allowDomainsOrHostIPs, target)
                it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} http.get('${target}')`, function (done) {
                    app.testHttpGet(`http://${target}`).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                        done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
                    })
                });
            });
            
            describe(`# Network access using require('http').request`, function () {
                const target = '127.0.0.1:8124'
                const hasRuleAllowed = checkHasRuleAllowed(options.network.blockDomainsOrHostIPs, options.network.allowDomainsOrHostIPs, target)
                it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} http.get('${target}')`, function (done) {
                    app.testHttpRequest(`http://${target}`).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                        done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
                    })
                });
            });

            describe(`# Network access using require('https')`, function () {
                const target = 'pastebin.com'
                const hasRuleAllowed = checkHasRuleAllowed(options.network.blockDomainsOrHostIPs, options.network.allowDomainsOrHostIPs, target)
                it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} https.request('${target}')`, function (done) {
                    app.testHttpsRequest({ host: target, path: "/jWKHzPaq" }).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                        done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
                    })
                });
            });

            describe(`# Network access using require('net')`, function () {
                const target = 'websocketstest.com'
                const hasRuleAllowed = checkHasRuleAllowed(options.network.blockDomainsOrHostIPs, options.network.allowDomainsOrHostIPs, target)
                const itFn = hasRuleAllowed ? it : it.skip
                itFn(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} net.Socket().connect('${target}')`, function (done) {
                    app.testNetSocketConnect(443, target).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                        done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
                    })
                });

            });

            describe(`# Network access using require('net')`, function () {
                const target = 'demo.piesocket.com'
                const hasRuleAllowed = checkHasRuleAllowed(options.network.blockDomainsOrHostIPs, options.network.allowDomainsOrHostIPs, target)
                it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} net.createConnection('${target}')`, function (done) {
                    app.testNetCreateConnection({ port: 80, host: target }).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                        done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
                    })
                });

            });

            describe(`# Network access using require('net')`, function () {
                const target = '88.198.55.153'
                const hasRuleAllowed = checkHasRuleAllowed(options.network.blockDomainsOrHostIPs, options.network.allowDomainsOrHostIPs, target)
                it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} net.connect('${target}')`, function (done) {
                    app.testNetConnect({ port: 443, host: target }).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                        done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
                    })
                });
            });

            describe(`# Network access using require('dgram')`, function () {
                const target = '8.8.8.8'
                const hasRuleAllowed = checkHasRuleAllowed(options.network.blockDomainsOrHostIPs, options.network.allowDomainsOrHostIPs, target)
                it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} dgram.send('${target}')`, function (done) {
                    var { Buffer } = require('buffer');
                    const message = Buffer.from('hi');
                    app.testDgramCreateSocket(message, 53, target).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                        done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
                    })
                });
            });

            describe(`# Network access using require('dgram')`, function () {
                const target = '8.8.4.4'
                const hasRuleAllowed = checkHasRuleAllowed(options.network.blockDomainsOrHostIPs, options.network.allowDomainsOrHostIPs, target)
                it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} dgram.connect('${target}')`, function (done) {
                    app.testDgramConnectSocket(53, target).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                        done(hasRuleAllowed ? `${err} while this host is allowed.` : null)
                    })
                });
            });

            describe(`# Network access using require('http2')`, function () {
                const target = 'https://google.com'
                const hasRuleAllowed = checkHasRuleAllowed(options.network.blockDomainsOrHostIPs, options.network.allowDomainsOrHostIPs, target)
                it(`should return ${hasRuleAllowed ? 'OK' : 'an error'} when ${hasRuleAllowed ? 'allowing' : 'blocking'} http2.connect('${target}')`, function (done) {
                    app.testHttp2Connect(target).then(() => done(hasRuleAllowed ? null : 'Host is not allowed but has been reachable.')).catch(err => {
                        done(err ? null : 'Host is not supported but has been reachable.')
                    })
                });
            });

            after(function () {
                ids && ids.detach(function () {
                })
                console.log = stdoutWrite
            })
        });
    }
}