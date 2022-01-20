process.env.AWS_SDK_LOAD_CONFIG = true
var requireHook = require("./require-hook")
var path = require('path')
var crypto = require('crypto')
var AWS = require('aws-sdk')
var http = require('./node-libs/http')
var https = require('./node-libs/https')

var { ClientRequest } = require('_http_client')
var { Module } = require('module')

global.eval = function (...args) {
    console.log('  >>>>', `[${RED}Blocked${RESET}] (function:eval) EXEC - ${args}`)
}
const GREEN = '\x1b[32m'
const RED = '\x1b[31m'
const YELLOW = '\x1b[33m'
const WHITE = '\x1b[0m'
const RESET = '\x1b[0m'


const showBoxBanner = function () {
    console.log("╓───────────────────────────────────────────────────────────────╖")
    console.log(`║          Simplify Framework - IDS/IPS Version ${require('./package.json').version}           ║`)
    console.log("╙───────────────────────────────────────────────────────────────╜")
}

showBoxBanner()

class Firewall {
    static ALLOWED_HOSTS = []
    static ALLOWED_HASHES = []
    static BLOCKED_LIST = []
    static AWS_REGION = undefined
    static NAME_SPACE = undefined

    constructor({ allowDomainsOrHostIPs, allowSHA256OfCodeModules, blockedHashOrHostValues }, applicationNamespace) {
        Firewall.ALLOWED_HOSTS = allowDomainsOrHostIPs || []
        Firewall.ALLOWED_HASHES = allowSHA256OfCodeModules || []
        Firewall.BLOCKED_LIST = blockedHashOrHostValues || []
        Firewall.AWS_REGION = AWS.config.region
        Firewall.NAME_SPACE = applicationNamespace
        class _Module extends Module {
            constructor(...args) {
                super(...args)
            }
            _compile(...args) {
                if (Firewall.hookNodeModuleCompile(...args)) {
                    super._compile(...args)
                }
            }
        }

        class _ClientRequest extends ClientRequest {
            constructor(...args) {
                if (Firewall.hookHttpClientRequest(...args)) {
                    super(...args)
                } else {
                    super()
                }
            }

            end(...args) {
                super.end(...args)
            }
        }

        requireHook.setEvent(function (result, e) {
            if (e && (e.require == "https" || e.require == "http")) {
                result.request = Firewall.hookHttpRequest
                result.get = Firewall.hookHttpGet
            }
            if (e && e.require == "_http_client") {
                result.ClientRequest = _ClientRequest
            }
            if (e && e.require == "module") {
                result = _Module
            }
            return result
        })
        requireHook.attach(path.resolve())
    }

    static customMetricCWLogs(metricName, keyName, keyValue, callback) {
        if (`monitoring.${Firewall.AWS_REGION}.amazonaws.com` !== keyValue) {
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
                Namespace: Firewall.NAME_SPACE || 'NodeJS/FireWall' /* required */
            };
            var cloudwatch = new AWS.CloudWatch({ apiVersion: '2010-08-01', region: Firewall.AWS_REGION });
            cloudwatch.putMetricData(params, callback);
        }
    }

    static hookHttpEnd(...args) {
        console.log("hookHttpEnd", args)
    }

    static hookHttpRequest(...args) {
        const options = typeof args[0] === 'string' ? new URL(args[0]) : args[0]
        const protocol = `${options.protocol || options.agent.protocol}`
        const moduleName = protocol.replace(':', '')
        const argURL = `${protocol}//${options.host}${(options.search ? options.pathname + options.search : options.pathname) || options.path || ''}`
        if (Firewall.ALLOWED_HOSTS.find(h => options.host.indexOf(h) >= 0 ? true : false) != undefined) {
            Firewall.customMetricCWLogs("Allowed", "https.request()", options.host, (err, data) => {
                console.log('  >>>>', `[${GREEN}Allowed${RESET}] (${moduleName}:request) ${options.method || 'GET'} - ${argURL}`)
            })
            return (protocol === 'https:' ? https.request(...args) : http.request(...args))
        } else {
            if (Firewall.BLOCKED_LIST.indexOf(options.host) >= 0) {
                Firewall.customMetricCWLogs("Blocked", "https.request()", options.host, (err, data) => {
                    console.error('  >>>>', `[${RED}${RESET}] (${moduleName}:request) ${options.method || 'GET'} - ${argURL}`)
                })
                return (protocol === 'https:' ? https.request() : http.request())
            }
            Firewall.customMetricCWLogs("Warning", "https.request()", options.host, (err, data) => {
                console.warn('  >>>>', `[${YELLOW}Warning${RESET}] (${moduleName}:request) ${options.method || 'GET'} - ${argURL}`)
            })
            return (protocol === 'https:' ? https.request(...args) : http.request(...args))
        }
    }

    static hookHttpGet(...args) {
        const options = typeof args[0] === 'string' ? new URL(args[0]) : typeof args[1] === 'function' ? {} : args[1]
        const protocol = `${options.protocol || options.agent.protocol}`
        const moduleName = protocol.replace(':', '')
        const argURL = `${protocol}//${options.host}${(options.search ? options.pathname + options.search : options.pathname) || options.path || ''}`
        if (Firewall.ALLOWED_HOSTS.find(h => options.host.indexOf(h) >= 0 ? true : false) != undefined) {
            Firewall.customMetricCWLogs("Allowed", "https.get()", options.host, (err, data) => {
                console.log('  >>>>', `[${GREEN}Allowed${RESET}] (${moduleName}:get) GET - ${argURL}`)
            })
            return (protocol === 'https:' ? https.get(...args) : http.get(...args))
        } else {
            if (Firewall.BLOCKED_LIST.indexOf(options.host) >= 0) {
                Firewall.customMetricCWLogs("Blocked", "https.get()", options.host, (err, data) => {
                    console.error('  >>>>', `[${RED}Blocked${RESET}] (${moduleName}:get) GET - ${argURL}`)
                })
                return (protocol === 'https:' ? https.get() : http.get())
            }
            Firewall.customMetricCWLogs("Warning", "https.get()", options.host, (err, data) => {
                console.error('  >>>>', `[${YELLOW}Warning${RESET}] (${moduleName}:get) GET - ${argURL}`)
            })
            return (protocol === 'https:' ? https.get(...args) : http.get(...args))
        }
    }

    static hookNodeModuleCompile(...args) {
        const moduleCode = args[0]
        const moduleName = args.length > 1 ? args[1] : ''
        const moduleHashValue = crypto.createHash('sha256').update(moduleCode).digest('base64')

        if (Firewall.ALLOWED_HASHES.find(h => h === moduleHashValue ? true : false) != undefined) {
            Firewall.customMetricCWLogs("Allowed", "module._compile()", moduleHashValue, (err, data) => {
                console.log('  >>>>', `[${GREEN}Allowed${RESET}] (module:compile) ${moduleName ? moduleName : 'SHA256'} - ${moduleHashValue}`)
            })
            return true
        } else {
            if (Firewall.BLOCKED_LIST.indexOf(moduleHashValue) >= 0) {
                Firewall.customMetricCWLogs("Blocked", "module._compile()", moduleHashValue, (err, data) => {
                    console.error('  >>>>', `[${RED}Blocked${RESET}] (module:compile) ${moduleName ? moduleName : 'SHA256'} - ${moduleHashValue}`)
                })
                return false
            }
            Firewall.customMetricCWLogs("Warning", "module._compile()", moduleHashValue, (err, data) => {
                console.warn('  >>>>', `[${YELLOW}Warning${RESET}] (module:compile) ${moduleName ? moduleName : 'SHA256'} - ${moduleHashValue}`)
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
        if (Firewall.ALLOWED_HOSTS.find(h => requestHost == h ? true : false) != undefined) {
            Firewall.customMetricCWLogs("Allowed", "_http_client()", requestHost, (err, data) => {
                console.log('  >>>>', `[${GREEN}Allowed${RESET}] (_http_client) ${options.method || 'GET'} - ${requestURL}`)
            })
            return true
        } else {
            if (Firewall.BLOCKED_LIST.indexOf(requestHost) >= 0) {
                Firewall.customMetricCWLogs("Blocked", "_http_client()", requestHost, (err, data) => {
                    console.error('  >>>>', `[${RED}Blocked${RESET}] (_http_client) ${options.method || 'GET'} - ${requestURL}`)
                })
                return false
            }
            Firewall.customMetricCWLogs("Warning", "_http_client()", requestHost, (err, data) => {
                console.warn('  >>>>', `[${YELLOW}Warning${RESET}] (_http_client) ${options.method || 'GET'} - ${requestURL}`)
            })
            return true
        }
    }

    detach() {
        requireHook.detach()
    }
}

module.exports = { Firewall }
