#!/usr/bin/env node
'use strict';
process.env.AWS_SDK_LOAD_CONFIG = true
var requireHook = require("./require-hook")
var path = require('path')
var crypto = require('crypto')
var AWS = require('aws-sdk')
var http = require('./node-libs/http')
var https = require('./node-libs/https')
const { connect } = require('http2');
var { ClientRequest } = require('_http_client')
var { Module } = require('module')
var { Socket } = require('net')
var dgram = require('dgram')

var GREEN = '\x1b[32m'
var RED = '\x1b[31m'
var YELLOW = '\x1b[33m'
var VIOLET = '\x1b[35m'
var RESET = '\x1b[0m'

String.prototype.toBoolean = function () {
    try {
        return JSON.parse(this.toLowerCase())
    } catch {
        return false
    }
}

const PRINT_LOG = function (...args) {
    if (process.env.IDS_PRINT_OUTPUT_LOG && process.env.IDS_PRINT_OUTPUT_LOG.toBoolean() == true) {
        console.log(...args)
    }
}

function getGenericSocketPath(socketPath) {
    return socketPath.startsWith("/tmp/server-") && socketPath.endsWith(".sock") ? "/tmp/server-*.sock" : socketPath
}

if (require.main !== module) {
    GREEN = RED = YELLOW = VIOLET = RESET = ''
}

global.eval = function (...args) {
    return function () { PRINT_LOG('  >>>>', `[${RED}Blocked${RESET}] (function:eval) EVAL`, args) }
}

Array.range = function (n) {
    return Array.apply(null, Array(n)).map((x, i) => i)
}

Object.defineProperty(Array.prototype, 'chunk', {
    value: function (n) {
        return Array.range(Math.ceil(this.length / n)).map((x, i) => this.slice(i * n, i * n + n));

    }
})

function resolveHostAddress(options) {
    return (options)
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
    console.log("???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????")
    console.log(`???          Simplify Framework - IDS/IPS Version ${require('./package.json').version}          ???`)
    console.log("???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????")
}

class IDS {
    static ALLOWED_HOSTS = []
    static ALLOWED_MODULES = []
    static BLOCKED_HOSTS = []
    static BLOCKED_MODULES = []
    static AWS_REGION = undefined
    static NAME_SPACE = undefined
    static ENABLE_METRIC_PRINT_LOGGING = false
    static __Socket = undefined

    constructor({
        network/*: { allowDomainsOrHostIPs, blockDomainsOrHostIPs }*/,
        host/*: { allowModuleOrSHA256OfCode, blockModuleOrSHA256OfCode }*/ },
        applicationNamespace,
        honeypotReflectionHost,
        enableMetricsLogging) {
        IDS.ALLOWED_HOSTS = (network || {}).allowDomainsOrHostIPs || []
        IDS.ALLOWED_MODULES = (host || {}).allowModuleOrSHA256OfCode || []
        IDS.BLOCKED_HOSTS = (network || {}).blockDomainsOrHostIPs || []
        IDS.BLOCKED_MODULES = (host || {}).blockModuleOrSHA256OfCode || []
        IDS.AWS_REGION = AWS.config.region
        IDS.NAME_SPACE = applicationNamespace
        IDS.HONEYPOT_ENDPOINT = honeypotReflectionHost
        IDS.ENABLE_METRIC_PRINT_LOGGING = enableMetricsLogging || process.env.IDS_ENABLE_METRIC_LOGGING
        IDS.CW_METRIC_DATA = []

        class _Module extends Module {
            constructor(...args) {
                super(...args)
            }
            _compile(...args) {
                if (IDS.hookNodeModuleCompile(...args)) {
                    super._compile(...args)
                    return true
                } else {
                    super._compile('module.exports = ()=>{}', __dirname)
                    return false
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
                const newArgs = IDS.hookUDPSocketConnect(...args)
                super.connect(...newArgs)
                return newArgs
            }

            send(...args) {
                const newArgs = IDS.hookUDPSocketSend(...args)
                super.send(...newArgs)
                return newArgs
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
            if (process.env.IDS_ENABLE_MODULE_TRACKER && (process.env.IDS_ENABLE_MODULE_TRACKER.toBoolean()) == true) {
                return IDS.hookNodeModuleLoad(e) ? result : {}
            } else {
                return result
            }
        })
        if (requireHook.attach(path.resolve())) {
            IDS.CW_METRIC_DATA = []
        }
    }

    static verifyValueInCheckList(checkValue, checkList, exactEquals) {
        const comparationResult = h => h === '*' || (h && checkValue && (exactEquals ? checkValue == h : checkValue.startsWith(h)))
        return checkList.find(h => comparationResult(h) ? true : false) != undefined
    }

    static redirectHTTPToHoneyPot(args) {
        const firstArg = args.length > 0 ? args.shift() : undefined
        let argsReflex = typeof firstArg === 'string' ? new URL(firstArg) : { ...firstArg }
        if (argsReflex.hostname) {
            delete argsReflex['host']
            PRINT_LOG('  >>>>', `:redirect ${argsReflex.hostname} to ${IDS.HONEYPOT_ENDPOINT}`)
            argsReflex.hostname = IDS.HONEYPOT_ENDPOINT
        } else if (argsReflex.host) {
            PRINT_LOG('  >>>>', `:redirect ${argsReflex.host} to ${IDS.HONEYPOT_ENDPOINT}`)
            argsReflex.host = IDS.HONEYPOT_ENDPOINT
        }
        return [argsReflex, ...args]
    }

    static redirectSOCKToHoneyPot(args) {
        if (args.length > 1) {
            const lastHost = args[1]
            args[1] = IDS.HONEYPOT_ENDPOINT
            PRINT_LOG('  >>>>', `:redirect ${lastHost} to ${args[1]}`)
        }
        return args;
    }

    static collectMetricForCWLogs(metricName, keyName, keyValue) {
        if (keyValue && IDS.ENABLE_METRIC_PRINT_LOGGING && `monitoring.${IDS.AWS_REGION || '(missing)'}.amazonaws.com` !== keyValue) {
            let lastValidMetric = IDS.CW_METRIC_DATA.find(x => {
                const matchedMetric = x.MetricName == metricName && x.Dimensions[0].Name == keyName && x.Dimensions[0].Value == keyValue
                if ((new Date().getTime() - new Date(x.Timestamp).getTime()) / 1000 < 60 /** in within 60 seconds */) {
                    return matchedMetric
                }
                return false
            })
            if (typeof lastValidMetric !== 'undefined') {
                lastValidMetric.Value += 1 /** Accumulated to the last metric */
            } else {
                IDS.CW_METRIC_DATA.push(
                    {
                        MetricName: metricName, /* required */
                        Dimensions: [{ Name: keyName, Value: keyValue }],
                        StorageResolution: 60,
                        Timestamp: new Date().toISOString(),
                        Unit: 'Count',
                        Value: 1
                    })
            }
        }
    }

    static sendCollectedMetricToCWLogs(callback) {
        if (IDS.ENABLE_METRIC_PRINT_LOGGING) {
            const BATCH_SIZE = 20 /** Max number of Items to put in AWS CW/Metrics */
            Promise.all(IDS.CW_METRIC_DATA.chunk(BATCH_SIZE).map(metricData => {
                return new Promise((resolve, reject) => {
                    var params = {
                        MetricData: metricData,
                        Namespace: IDS.NAME_SPACE || 'NodeJS/FireWall' /* required */
                    };
                    var cloudwatch = new AWS.CloudWatch({ apiVersion: '2010-08-01', region: IDS.AWS_REGION });
                    cloudwatch.putMetricData(params, (err, data) => {
                        err ? reject(err) : resolve(data)
                    });
                })
            })).catch(err => {
                const errs = Array.isArray(err) ? err : [err]
                errs.map(err => {
                    PRINT_LOG('\t\t  ', `connect = monitoring.${IDS.AWS_REGION || '(missing)'}.amazonaws.com`)
                    PRINT_LOG('\t\t  ', `logging = AWS/CloudWatch: { Action: [ "cloudwatch:PutMetricData" ] }`)
                    PRINT_LOG('\t\t  ', `message = ${err.message}`)
                })
                callback && callback(errs)
            }).then((results) => {
                if (results && results.length > 0) {
                    const numberOfMetrics = results.length * BATCH_SIZE < IDS.CW_METRIC_DATA.length ? results.length * BATCH_SIZE : IDS.CW_METRIC_DATA.length
                    PRINT_LOG('\t\t *', `AWS CloudWatch has logged ${numberOfMetrics} metrics to ${IDS.NAME_SPACE || 'NodeJS/FireWall'}.`)
                }
                IDS.CW_METRIC_DATA = new Array()
                callback && callback(null, {})
            })
        } else {
            callback && callback(null, {})
        }
    }

    static hookHttp2Connect(...args) {
        const resolvedHost = args.length > 0 ? args[0] : undefined
        IDS.collectMetricForCWLogs("Blocked", "http2.connect()", resolvedHost)
        PRINT_LOG('  >>>>', `[${RED}Blocked${RESET}] (http2:connect) OPEN - ${resolvedHost} | ${VIOLET}Unsupported${RESET}`)
        return undefined
    }

    static hookHttpRequest(...args) {
        const options = typeof args[0] === 'string' ? new URL(args[0]) : args[0]
        const protocol = `${options.protocol || (options.agent || {}).protocol || `${options.port === 80 ? 'http:' : options.socketPath ? 'file:' : 'https:'}`}`
        const moduleName = protocol.replace(':', '')
        const resolvedHost = resolveHostAddress(options.host || options.hostname || getGenericSocketPath(options.socketPath))
        const argURL = `${protocol}//${resolvedHost}${(options.search ? options.pathname + options.search : options.pathname) || options.path || ''}`
        if (IDS.verifyValueInCheckList(resolvedHost, IDS.ALLOWED_HOSTS)) {
            IDS.collectMetricForCWLogs("Allowed", "https.request()", resolvedHost)
            PRINT_LOG('  >>>>', `[${GREEN}Allowed${RESET}] (${moduleName}:request) ${options.method || 'GET'} - ${argURL}`)
            return (protocol === 'https:' ? https.request(...args) : http.request(...args))
        } else {
            if (IDS.verifyValueInCheckList(resolvedHost, IDS.BLOCKED_HOSTS)) {
                IDS.collectMetricForCWLogs("Blocked", "https.request()", resolvedHost)
                PRINT_LOG('  >>>>', `[${RED}${moduleName == 'file' ? 'Ignored' : 'Blocked'}${RESET}] (${moduleName}:request) ${options.method || 'GET'} - ${argURL}`)
                return (protocol === 'https:' ? https.request(...IDS.redirectHTTPToHoneyPot(args)) : http.request(...IDS.redirectHTTPToHoneyPot(args)))
            }
            IDS.collectMetricForCWLogs("Warning", "https.request()", resolvedHost)
            PRINT_LOG('  >>>>', `[${YELLOW}Warning${RESET}] (${moduleName}:request) ${options.method || 'GET'} - ${argURL}`)
            return (protocol === 'https:' ? https.request(...args) : http.request(...args))
        }
    }

    static hookHttpGet(...args) {
        const options = typeof args[0] === 'string' ? new URL(args[0]) : typeof args[1] === 'function' ? {} : args[1]
        const protocol = `${options.protocol || (options.agent || {}).protocol || `${options.port === 80 ? 'http:' : options.socketPath ? 'file:' : 'https:'}`}`
        const moduleName = protocol.replace(':', '')
        const resolvedHost = resolveHostAddress(options.host || options.hostname || getGenericSocketPath(options.socketPath))
        const argURL = `${protocol}//${resolvedHost}${(options.search ? options.pathname + options.search : options.pathname) || options.path || ''}`
        if (IDS.verifyValueInCheckList(resolvedHost, IDS.ALLOWED_HOSTS)) {
            IDS.collectMetricForCWLogs("Allowed", "https.get()", resolvedHost)
            PRINT_LOG('  >>>>', `[${GREEN}Allowed${RESET}] (${moduleName}:get) GET - ${argURL}`)
            return (protocol === 'https:' ? https.get(...args) : http.get(...args))
        } else {
            if (IDS.verifyValueInCheckList(resolvedHost, IDS.BLOCKED_HOSTS)) {
                IDS.collectMetricForCWLogs("Blocked", "https.get()", resolvedHost)
                PRINT_LOG('  >>>>', `[${RED}Blocked${RESET}] (${moduleName}:get) GET - ${argURL}`)
                return (protocol === 'https:' ? https.get(...IDS.redirectHTTPToHoneyPot(args)) : http.get(...IDS.redirectHTTPToHoneyPot(args)))
            }
            IDS.collectMetricForCWLogs("Warning", "https.get()", resolvedHost)
            PRINT_LOG('  >>>>', `[${YELLOW}Warning${RESET}] (${moduleName}:get) GET - ${argURL}`)
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
            IDS.collectMetricForCWLogs("Allowed", `module.${moduleMode}()`, moduleValue)
            PRINT_LOG('  >>>>', `[${GREEN}Allowed${RESET}] (module:${moduleMode}) ${moduleName ? moduleName : moduleMode} - ${moduleValue} ${moduleType ? 'type=' + moduleType : ''}`)
            return true
        } else {
            if (IDS.verifyValueInCheckList(moduleValue, IDS.BLOCKED_MODULES, false)) {
                IDS.collectMetricForCWLogs("Blocked", `module.${moduleMode}()`, moduleValue)
                PRINT_LOG('  >>>>', `[${RED}Blocked${RESET}] (module:${moduleMode}) ${moduleName ? moduleName : moduleMode} - ${moduleValue} ${moduleType ? 'type=' + moduleType : ''}`)
                return false
            }
            IDS.collectMetricForCWLogs("Warning", `module.${moduleMode}()`, moduleValue)
            PRINT_LOG('  >>>>', `[${YELLOW}Warning${RESET}] (module:${moduleMode}) ${moduleName ? moduleName : moduleMode} - ${moduleValue} ${moduleType ? 'type=' + moduleType : ''}`)
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
        const options = getHttpOptions(...args)
        const requestHost = new URL(requestURL).host
        const resolvedHost = resolveHostAddress(requestHost)
        if (IDS.verifyValueInCheckList(resolvedHost, IDS.ALLOWED_HOSTS)) {
            IDS.collectMetricForCWLogs("Allowed", "_http_client()", resolvedHost)
            PRINT_LOG('  >>>>', `[${GREEN}Allowed${RESET}] (_http_client) ${options.method || 'GET'} - ${requestURL}`)
            return args
        } else {
            if (IDS.verifyValueInCheckList(resolvedHost, IDS.BLOCKED_HOSTS)) {
                IDS.collectMetricForCWLogs("Blocked", "_http_client()", resolvedHost)
                PRINT_LOG('  >>>>', `[${RED}Blocked${RESET}] (_http_client) ${options.method || 'GET'} - ${requestURL}`)
                return IDS.redirectHTTPToHoneyPot(args)
            }
            IDS.collectMetricForCWLogs("Warning", "_http_client()", resolvedHost)
            PRINT_LOG('  >>>>', `[${YELLOW}Warning${RESET}] (_http_client) ${options.method || 'GET'} - ${requestURL}`)
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
        const resolvedHost = resolveHostAddress(options.host || options.hostname)
        const argURL = `socket://${resolvedHost}:${options.port}`
        if (IDS.verifyValueInCheckList(resolvedHost, IDS.ALLOWED_HOSTS)) {
            IDS.collectMetricForCWLogs("Allowed", "net.connect()", resolvedHost)
            PRINT_LOG('  >>>>', `[${GREEN}Allowed${RESET}] (net:connect) OPEN - ${argURL}`)
            return connect(...args)
        } else {
            if (IDS.verifyValueInCheckList(resolvedHost, IDS.BLOCKED_HOSTS)) {
                IDS.collectMetricForCWLogs("Blocked", "net.connect()", resolvedHost)
                PRINT_LOG('  >>>>', `[${RED}Blocked${RESET}] (net:connect) OPEN - ${argURL}`)
                return connect(...IDS.redirectHTTPToHoneyPot(args))
            }
            IDS.collectMetricForCWLogs("Warning", "net.connect()", resolvedHost)
            PRINT_LOG('  >>>>', `[${YELLOW}Warning${RESET}] (net:connect) OPEN - ${argURL}`)
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
        let callbackIndex = args.findIndex(a => typeof a === 'function')
        callbackIndex = callbackIndex >= 2 ? callbackIndex : 2
        const requestPort = args.length > 0 ? args[callbackIndex-2] : null
        const requestHost = args.length > 1 ? args[callbackIndex-1] : 'localhost'
        const resolvedHost = resolveHostAddress(requestHost)
        if (IDS.verifyValueInCheckList(resolvedHost, IDS.ALLOWED_HOSTS)) {
            IDS.collectMetricForCWLogs("Allowed", "socket.connect()", resolvedHost)
            PRINT_LOG('  >>>>', `[${GREEN}Allowed${RESET}] (${socketType}:socket) OPEN - socket://${resolvedHost}:${requestPort}`)
            return args
        } else {
            if (IDS.verifyValueInCheckList(resolvedHost, IDS.BLOCKED_HOSTS)) {
                IDS.collectMetricForCWLogs("Blocked", "socket.connect()", resolvedHost)
                PRINT_LOG('  >>>>', `[${RED}Blocked${RESET}] (${socketType}:socket) OPEN - socket://${resolvedHost}:${requestPort}`)
                return IDS.redirectSOCKToHoneyPot(args)
            }
            IDS.collectMetricForCWLogs("Warning", "socket.connect()", resolvedHost)
            PRINT_LOG('  >>>>', `[${YELLOW}Warning${RESET}] (${socketType}:socket) OPEN - socket://${resolvedHost}:${requestPort}`)
            return args
        }
    }

    static hookUDPSocketSend = function (...args) {
        let callbackIndex = args.findIndex(a => typeof a === 'function')
        callbackIndex = callbackIndex >= 2 ? callbackIndex : 2
        const requestPort = args.length > 1 ? args[callbackIndex-2] : null
        const requestHost = args.length > 2 ? args[callbackIndex-1] : 'localhost'
        const resolvedHost = resolveHostAddress(requestHost)
        if (IDS.verifyValueInCheckList(resolvedHost, IDS.ALLOWED_HOSTS)) {
            IDS.collectMetricForCWLogs("Allowed", "socket.send()", resolvedHost)
            PRINT_LOG('  >>>>', `[${GREEN}Allowed${RESET}] (udp:socket) SEND - socket://${resolvedHost}:${requestPort}`)
            return args
        } else {
            if (IDS.verifyValueInCheckList(resolvedHost, IDS.BLOCKED_HOSTS)) {
                IDS.collectMetricForCWLogs("Blocked", "socket.send()", resolvedHost)
                PRINT_LOG('  >>>>', `[${RED}Blocked${RESET}] (udp:socket) SEND - socket://${resolvedHost}:${requestPort}`)
                const message = args.shift()
                return [message, ...IDS.redirectSOCKToHoneyPot(args)]
            }
            IDS.collectMetricForCWLogs("Warning", "socket.send()", resolvedHost)
            PRINT_LOG('  >>>>', `[${YELLOW}Warning${RESET}] (udp:socket) SEND - socket://${resolvedHost}:${requestPort}`)
            return args
        }
    }

    detach(callback) {
        requireHook.detach()
        IDS.sendCollectedMetricToCWLogs(callback)
    }
}

module.exports = { IDS }

if (require.main === module) {
    showBoxBanner()
    require('./cli.js')
}