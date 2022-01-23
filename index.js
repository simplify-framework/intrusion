process.env.AWS_SDK_LOAD_CONFIG = true
var requireHook = require("./require-hook")
var path = require('path')
const dns = require('dns')
var crypto = require('crypto')
var AWS = require('aws-sdk')
var http = require('./node-libs/http')
var https = require('./node-libs/https')
const { connect } = require('http2');
var { ClientRequest } = require('_http_client')
var { Module } = require('module')
var { Socket } = require('net')
var dgram = require('dgram')

global.eval = function (...args) {
    console.log('  >>>>', `[${RED}Blocked${RESET}] (function:eval) EVAL - ${args}`)
}
const GREEN = '\x1b[32m'
const RED = '\x1b[31m'
const YELLOW = '\x1b[33m'
const VIOLET = '\x1b[35m'
const RESET = '\x1b[0m'

function resolveHostAddress(ipaddress) {
    return (ipaddress)
}

// Returns an array [options, cb], where options is an object,
// cb is either a function or null.
// Used to normalize arguments of Socket.prototype.connect() and
// Server.prototype.listen(). Possible combinations of parameters:
//   (options[...][, cb])
//   (path[...][, cb])
//   ([port][, host][...][, cb])
// For Socket.prototype.connect(), the [...] part is ignored
// For Server.prototype.listen(), the [...] part is [, backlog]
// but will not be handled here (handled in listen())
function normalizeArgs(args) {
    let arr;

    if (args.length === 0) {
        arr = [{}, null];
        arr['normalizedArgs'] = true;
        return arr;
    }

    const arg0 = args[0];
    let options = {};
    if (typeof arg0 === 'object' && arg0 !== null) {
        // (options[...][, cb])
        options = arg0;
    } else if (isPipeName(arg0)) {
        // (path[...][, cb])
        options.path = arg0;
    } else {
        // ([port][, host][...][, cb])
        options.port = arg0;
        if (args.length > 1 && typeof args[1] === 'string') {
            options.host = args[1];
        }
    }

    const cb = args[args.length - 1];
    if (typeof cb !== 'function')
        arr = [options, null];
    else
        arr = [options, cb];

    arr['normalizedArgs'] = true;
    return arr;
}

const showBoxBanner = function () {
    console.log("╓───────────────────────────────────────────────────────────────╖")
    console.log(`║          Simplify Framework - IDS/IPS Version ${require('./package.json').version}           ║`)
    console.log("╙───────────────────────────────────────────────────────────────╜")
}

showBoxBanner()

class IDS {
    static ALLOWED_HOSTS = []
    static ALLOWED_MODULES = []
    static BLOCKED_HOSTS = []
    static BLOCKED_MODULES = []
    static AWS_REGION = undefined
    static NAME_SPACE = undefined
    static ALLOW_METRIC_LOGGING = process.env.ALLOW_METRIC_LOGGING || false
    static __Socket = undefined

    constructor({
        network/*: { allowDomainsOrHostIPs, blockDomainsOrHostIPs }*/,
        host/*: { allowModuleOrSHA256OfCode, blockModuleOrSHA256OfCode }*/ },
        applicationNamespace,
        honeypotReflectionHost) {
        IDS.ALLOWED_HOSTS = (network || {}).allowDomainsOrHostIPs || []
        IDS.ALLOWED_MODULES = (host || {}).allowModuleOrSHA256OfCode || []
        IDS.BLOCKED_HOSTS = (network || {}).blockDomainsOrHostIPs || []
        IDS.BLOCKED_MODULES = (host || {}).blockModuleOrSHA256OfCode || []
        IDS.AWS_REGION = AWS.config.region
        IDS.NAME_SPACE = applicationNamespace
        IDS.HONEYPOT_ENDPOINT = honeypotReflectionHost

        class _Module extends Module {
            constructor(...args) {
                super(...args)
            }
            _compile(...args) {
                if (IDS.hookNodeModuleCompile(...args)) {
                    super._compile(...args)
                } else {
                    super._compile('module.exports = ()=>{}', __dirname)
                }
            }
        }

        class _ClientRequest extends ClientRequest {
            constructor(...args) {
                super(...IDS.hookHttpClientRequest(...args))
            }

            end(...args) {
                super.end(...args)
            }
        }

        class _TCPSocket extends Socket {
            constructor(...args) {
                super(...args)
            }

            connect(...args) {
                return super.connect(...IDS.hookNetSocketConnect(...args))
            }
        }

        class _UDPSocket extends dgram.Socket {
            constructor(...args) {
                super(...args)
            }

            connect(...args) {
                return super.connect(...IDS.hookUDPSocketConnect(...args))
            }

            send(...args) {
                super.send(...IDS.hookUDPSocketSend(...args))
            }
        }

        function _TCPSocketWrapper(...args) {
            return IDS.__Socket(...args)
        }

        requireHook.setEvent(function (result, e) {
            if (e && (e.require == "https" || e.require == "http")) {
                result.request = IDS.hookHttpRequest
                result.get = IDS.hookHttpGet
            } else if (e && e.require == "_http_client") {
                result.ClientRequest = _ClientRequest
            } else if (e && e.require == "module") {
                result = _Module
            } else if (e && e.require == "net") {
                result.createConnection = IDS.hookCreateConnection
                result.connect = IDS.hookCreateConnection
            } else if (e && e.require == "dgram") {
                result.Socket = _UDPSocket
                result.createSocket = function (...args) { return new _UDPSocket(...args) }
            } else if (e && e.require == "http2") {
                result.connect = IDS.hookHttp2Connect
            } else if (e && e.require.indexOf('node-libs/https') >= 0 || e && e.require.indexOf('node-libs/http') >= 0) {
                result.request = function (...args) { args.map(a => typeof a === 'function' ? a() : {}) }
                result.get = function (...args) { args.map(a => typeof a === 'function' ? a() : {}) }
            }
            if (IDS.hookNodeModuleLoad(e)) {
                return result
            } else {
                return {}
            }
        })
        requireHook.attach(path.resolve())
    }

    static verifyValueInCheckList(checkValue, checkList, exactEquals) {
        const comparationResult = h => h === '*' || (h && checkValue && (exactEquals ? checkValue == h : checkValue.startsWith(h)))
        return checkList.find(h => comparationResult(h) ? true : false) != undefined
    }

    static redirectHTTPToHoneyPot(args) {
        const firstArg = args.length > 0 ? args.shift() : undefined
        let argsReflex = typeof firstArg === 'string' ? new URL(firstArg) : firstArg
        argsReflex.host = IDS.HONEYPOT_ENDPOINT
        return [argsReflex, ...args]
    }

    static redirectSOCKToHoneyPot(args) {
        if (args.length > 1) {
            args[1] = IDS.HONEYPOT_ENDPOINT
        }
        return args;
    }

    static customMetricCWLogs(metricName, keyName, keyValue, callback) {
        if (`monitoring.${IDS.AWS_REGION}.amazonaws.com` !== keyValue) {
            if (IDS.ALLOW_METRIC_LOGGING) {
                var params = {
                    MetricData: [ /* required */
                        {
                            MetricName: metricName, /* required */
                            Dimensions: [{ Name: keyName, Value: keyValue }],
                            StorageResolution: 60,
                            Timestamp: new Date().toISOString(),
                            Unit: 'Count',
                            Value: 1
                        }
                    ],
                    Namespace: IDS.NAME_SPACE || 'NodeJS/FireWall' /* required */
                };
                var cloudwatch = new AWS.CloudWatch({ apiVersion: '2010-08-01', region: IDS.AWS_REGION });
                cloudwatch.putMetricData(params, (err, data) => {
                    callback && callback()
                    if (err) {
                        console.log('\t\t  ', `connect = monitoring.${IDS.AWS_REGION}.amazonaws.com`)
                        console.log('\t\t  ', `logging = AWS/CloudWatch: { Action: [ "cloudwatch:PutMetricData" ] }`)
                        console.log('\t\t  ', `message = ${err.message}`)
                    }
                });
            } else {
                callback && callback()
            }
        } else {
            callback && callback()
        }
    }

    static hookHttp2Connect(...args) {
        const resolvedHost = args.length > 0 ? args[0] : undefined
        IDS.customMetricCWLogs("Blocked", "http2.connect()", resolvedHost, () => {
            console.log('  >>>>', `[${RED}Blocked${RESET}] (http2:connect) OPEN - ${resolvedHost} | ${VIOLET}Unsupported${RESET}`)
        })
        return undefined
    }

    static hookHttpRequest(...args) {
        const options = typeof args[0] === 'string' ? new URL(args[0]) : args[0]
        const protocol = `${options.protocol || (options.agent || {}).protocol || `${(options.port || 443) === 443 ? 'https:' : 'http:'}`}`
        const moduleName = protocol.replace(':', '')
        const resolvedHost = resolveHostAddress(options.host)
        const argURL = `${protocol}//${resolvedHost}${(options.search ? options.pathname + options.search : options.pathname) || options.path || ''}`
        if (IDS.verifyValueInCheckList(resolvedHost, IDS.ALLOWED_HOSTS)) {
            IDS.customMetricCWLogs("Allowed", "https.request()", resolvedHost, (err, data) => {
                console.log('  >>>>', `[${GREEN}Allowed${RESET}] (${moduleName}:request) ${options.method || 'GET'} - ${argURL}`)
            })
            return (protocol === 'https:' ? https.request(...args) : http.request(...args))
        } else {
            if (IDS.verifyValueInCheckList(resolvedHost, IDS.BLOCKED_HOSTS)) {
                IDS.customMetricCWLogs("Blocked", "https.request()", resolvedHost, (err, data) => {
                    console.log('  >>>>', `[${RED}Blocked${RESET}] (${moduleName}:request) ${options.method || 'GET'} - ${argURL}`)
                })
                return (protocol === 'https:' ? https.request(...IDS.redirectHTTPToHoneyPot(args)) : http.request(...IDS.redirectHTTPToHoneyPot(args)))
            }
            IDS.customMetricCWLogs("Warning", "https.request()", resolvedHost, (err, data) => {
                console.log('  >>>>', `[${YELLOW}Warning${RESET}] (${moduleName}:request) ${options.method || 'GET'} - ${argURL}`)
            })
            return (protocol === 'https:' ? https.request(...args) : http.request(...args))
        }
    }

    static hookHttpGet(...args) {
        const options = typeof args[0] === 'string' ? new URL(args[0]) : typeof args[1] === 'function' ? {} : args[1]
        const protocol = `${options.protocol || (options.agent || {}).protocol || `${(options.port || 443) ? 'https:' : 'http:'}`}`
        const moduleName = protocol.replace(':', '')
        const resolvedHost = resolveHostAddress(options.host)
        const argURL = `${protocol}//${resolvedHost}${(options.search ? options.pathname + options.search : options.pathname) || options.path || ''}`
        if (IDS.verifyValueInCheckList(resolvedHost, IDS.ALLOWED_HOSTS)) {
            IDS.customMetricCWLogs("Allowed", "https.get()", resolvedHost, (err, data) => {
                console.log('  >>>>', `[${GREEN}Allowed${RESET}] (${moduleName}:get) GET - ${argURL}`)
            })
            return (protocol === 'https:' ? https.get(...args) : http.get(...args))
        } else {
            if (ewall.verifyValueInCheckList(resolvedHost, IDS.BLOCKED_HOSTS)) {
                IDS.customMetricCWLogs("Blocked", "https.get()", resolvedHost, (err, data) => {
                    console.log('  >>>>', `[${RED}Blocked${RESET}] (${moduleName}:get) GET - ${argURL}`)
                })
                return (protocol === 'https:' ? https.get(...IDS.redirectHTTPToHoneyPot(args)) : http.get(...IDS.redirectHTTPToHoneyPot(args)))
            }
            IDS.customMetricCWLogs("Warning", "https.get()", resolvedHost, (err, data) => {
                console.log('  >>>>', `[${YELLOW}Warning${RESET}] (${moduleName}:get) GET - ${argURL}`)
            })
            return (protocol === 'https:' ? https.get(...args) : http.get(...args))
        }
    }

    static hookNodeModuleCompile(...args) {
        const moduleCode = args[0]
        const moduleHashValue = crypto.createHash('sha256').update(moduleCode).digest('base64')
        return IDS.hookNodeModule(moduleHashValue, 'CODE', '_compile')
    }

    static hookNodeModuleLoad(module) {
        return IDS.hookNodeModule(`${module.require}${module.version ? ':' + module.version : ''}`, `FILE`, 'load', module.json ? 'json' : module.native ? 'native' : 'module')
    }

    static hookNodeModule(moduleValue, moduleName, moduleMode, moduleType) {
        if (IDS.verifyValueInCheckList(moduleValue, IDS.ALLOWED_MODULES, false)) {
            IDS.customMetricCWLogs("Allowed", `module.${moduleMode}()`, moduleValue, (err, data) => {
                console.log('  >>>>', `[${GREEN}Allowed${RESET}] (module:${moduleMode}) ${moduleName ? moduleName : moduleMode} - ${moduleValue} ${moduleType ? 'type=' + moduleType : ''}`)
            })
            return true
        } else {
            if (IDS.verifyValueInCheckList(moduleValue, IDS.BLOCKED_MODULES, false)) {
                IDS.customMetricCWLogs("Blocked", `module.${moduleMode}()`, moduleValue, (err, data) => {
                    console.log('  >>>>', `[${RED}Blocked${RESET}] (module:${moduleMode}) ${moduleName ? moduleName : moduleMode} - ${moduleValue} ${moduleType ? 'type=' + moduleType : ''}`)
                })
                return false
            }
            IDS.customMetricCWLogs("Warning", `module.${moduleMode}()`, moduleValue, (err, data) => {
                console.log('  >>>>', `[${YELLOW}Warning${RESET}] (module:${moduleMode}) ${moduleName ? moduleName : moduleMode} - ${moduleValue} ${moduleType ? 'type=' + moduleType : ''}`)
            })
            return true
        }
    }

    static hookHttpClientRequest = function (...args) {
        function getHttpOptions(...args) {
            if (args.length > 0 && typeof args[0] === 'object') {
                return args[0]
            }
            return {}
        }
        const requestURL = args.length > 0 ? args[0] : null
        args.shift()
        const options = getHttpOptions(...args)
        const requestHost = new URL(requestURL).host
        const resolvedHost = resolveHostAddress(requestHost)
        if (IDS.verifyValueInCheckList(resolvedHost, IDS.ALLOWED_HOSTS)) {
            IDS.customMetricCWLogs("Allowed", "_http_client()", resolvedHost, (err, data) => {
                console.log('  >>>>', `[${GREEN}Allowed${RESET}] (_http_client) ${options.method || 'GET'} - ${requestURL}`)
            })
            return args
        } else {
            if (IDS.verifyValueInCheckList(resolvedHost, IDS.BLOCKED_HOSTS)) {
                IDS.customMetricCWLogs("Blocked", "_http_client()", resolvedHost, (err, data) => {
                    console.log('  >>>>', `[${RED}Blocked${RESET}] (_http_client) ${options.method || 'GET'} - ${requestURL}`)
                })
                return IDS.redirectHTTPToHoneyPot(args)
            }
            IDS.customMetricCWLogs("Warning", "_http_client()", resolvedHost, (err, data) => {
                console.log('  >>>>', `[${YELLOW}Warning${RESET}] (_http_client) ${options.method || 'GET'} - ${requestURL}`)
            })
            return args
        }
    }

    static hookCreateConnection(...args) {
        const options = typeof args[0] === 'string' ? new URL(args[0]) : args[0]
        function connect(...args) {
            const normalized = normalizeArgs(args);
            const options = normalized[0];
            const socket = new Socket(options);
            if (options.timeout) {
                socket.setTimeout(options.timeout);
            }
            return socket.connect(...normalized);
        }
        const resolvedHost = resolveHostAddress(options.host)
        const argURL = `socket://${resolvedHost}:${options.port}`
        if (IDS.verifyValueInCheckList(resolvedHost, IDS.ALLOWED_HOSTS)) {
            IDS.customMetricCWLogs("Allowed", "net.connect()", resolvedHost, (err, data) => {
                console.log('  >>>>', `[${GREEN}Allowed${RESET}] (net:connect) OPEN - ${argURL}`)
            })
            return connect(...args)
        } else {
            if (IDS.verifyValueInCheckList(resolvedHost, IDS.BLOCKED_HOSTS)) {
                IDS.customMetricCWLogs("Blocked", "net.connect()", resolvedHost, (err, data) => {
                    console.log('  >>>>', `[${RED}Blocked${RESET}] (net:connect) OPEN - ${argURL}`)
                })
                return connect(...IDS.redirectHTTPToHoneyPot(args))
            }
            IDS.customMetricCWLogs("Warning", "net.connect()", resolvedHost, (err, data) => {
                console.log('  >>>>', `[${YELLOW}Warning${RESET}] (net:connect) OPEN - ${argURL}`)
            })
            return connect(...args)
        }
    }

    static hookNetSocketConnect = function (...args) {
        return IDS.hookSocketConnect('net', ...args)
    }

    static hookUDPSocketConnect = function (...args) {
        return IDS.hookSocketConnect('udp', ...args)
    }

    static hookSocketConnect = function (...args) {
        const socketType = args.length > 0 ? args.shift() : null
        const requestPort = args.length > 0 ? args[0] : null
        const requestHost = args.length > 1 ? args[1] : 'localhost'
        const resolvedHost = resolveHostAddress(requestHost)

        if (IDS.verifyValueInCheckList(resolvedHost, IDS.ALLOWED_HOSTS)) {
            IDS.customMetricCWLogs("Allowed", "socket.connect()", resolvedHost, (err, data) => {
                console.log('  >>>>', `[${GREEN}Allowed${RESET}] (${socketType}:socket) OPEN - socket://${resolvedHost}:${requestPort}`)
            })
            return args
        } else {
            if (IDS.verifyValueInCheckList(resolvedHost, IDS.BLOCKED_HOSTS)) {
                IDS.customMetricCWLogs("Blocked", "socket.connect()", resolvedHost, (err, data) => {
                    console.log('  >>>>', `[${RED}Blocked${RESET}] (${socketType}:socket) OPEN - socket://${resolvedHost}:${requestPort}`)
                })
                return IDS.redirectSOCKToHoneyPot(args)
            }
            IDS.customMetricCWLogs("Warning", "socket.connect()", resolvedHost, (err, data) => {
                console.log('  >>>>', `[${YELLOW}Warning${RESET}] (${socketType}:socket) OPEN - socket://${resolvedHost}:${requestPort}`)
            })
            return args
        }
    }

    static hookUDPSocketSend = function (...args) {
        const requestPort = args.length > 1 ? args[1] : null
        const requestHost = args.length > 2 ? args[2] : 'localhost'
        const resolvedHost = resolveHostAddress(requestHost)
        if (IDS.verifyValueInCheckList(resolvedHost, IDS.ALLOWED_HOSTS)) {
            IDS.customMetricCWLogs("Allowed", "socket.send()", resolvedHost, (err, data) => {
                console.log('  >>>>', `[${GREEN}Allowed${RESET}] (udp:socket) SEND - socket://${resolvedHost}:${requestPort}`)
            })
            return args
        } else {
            if (IDS.verifyValueInCheckList(resolvedHost, IDS.BLOCKED_HOSTS)) {
                IDS.customMetricCWLogs("Blocked", "socket.send()", resolvedHost, (err, data) => {
                    console.log('  >>>>', `[${RED}Blocked${RESET}] (udp:socket) SEND - socket://${resolvedHost}:${requestPort}`)
                })
                const message = args.shift()
                return [message, ...IDS.redirectSOCKToHoneyPot(args)]
            }
            IDS.customMetricCWLogs("Warning", "socket.send()", resolvedHost, (err, data) => {
                console.log('  >>>>', `[${YELLOW}Warning${RESET}] (udp:socket) SEND - socket://${resolvedHost}:${requestPort}`)
            })
            return args
        }
    }

    detach() {
        requireHook.detach()
        return true
    }
}

module.exports = { IDS }
