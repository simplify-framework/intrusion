var { IDS } = require('./index.js')
var path = require('path')
var fs = require('fs')
String.prototype.toBoolean = function () {
    try {
        return JSON.parse(this.toLowerCase())
    } catch {
        return false
    }
}

var ids = new IDS({
    network: {
        allowDomainsOrHostIPs: (process.env.IDS_ALLOWED_HOSTS || "").split(','),
        blockDomainsOrHostIPs: (process.env.IDS_BLOCKED_HOSTS || "").split(',')
    },
    host: {
        allowModuleOrSHA256OfCode: (process.env.IDS_ALLOWED_MODULES || "").split(','),
        blockModuleOrSHA256OfCode: (process.env.IDS_BLOCKED_MODULES || "").split(',')
    },
}, process.env.IDS_CLOUDWATCH_DOMAIN_NAME, process.env.IDS_HONEYPOT_SERVER, process.env.IDS_ENABLE_METRIC_LOGGING.toBoolean())

var loadedModule = null
var moduleHandler = null
const lambdaHandler = process.env.IDS_LAMBDA_HANDLER
if (typeof lambdaHandler === 'string' && lambdaHandler) {
    const loadedTimestamp = new Date().getTime()
    const handlerString = path.basename(lambdaHandler)
    const moduleRoot = lambdaHandler.substring(0, lambdaHandler.indexOf(handlerString))
    const handlerParts = handlerString.split('.')
    const moduleName = handlerParts[0].trim()
    const fullModulePath = path.resolve(process.env.LAMBDA_TASK_ROOT, moduleRoot, `${moduleName}`)
    moduleHandler = handlerParts[1].trim()
    console.log('IDS/IPS', ` LoadModule STARTED - Timestamp ${parseInt(loadedTimestamp / 1000)}`)
    if (fs.existsSync(fullModulePath) || fs.existsSync(fullModulePath + ".js")) {
        loadedModule = require(fullModulePath)
    } else {
        let nodeStylePath = require.resolve(moduleName, { paths: [process.env.LAMBDA_TASK_ROOT, moduleRoot] });
        loadedModule = require(nodeStylePath);
    }
    console.log('IDS/IPS', ` LoadModule FINISHED - Elapsed in ${new Date().getTime() - loadedTimestamp} ms`)
}

module.exports.handler = function (event, context, callback) {
    const startedTimestamp = new Date().getTime()
    console.log('IDS/IPS', ` Execution STARTED - Timestamp ${parseInt(startedTimestamp / 1000)}`)
    if (loadedModule && moduleHandler) {
        const promiseResult = loadedModule[`${moduleHandler}`](event, {
            ...context, succeed: function (data) {
                ids.detach(function () { context.succeed(data) })
                console.log('IDS/IPS', ` Execution EXISTED - Elapsed in ${new Date().getTime() - startedTimestamp} ms`)
            }, done: function (err, data) {
                ids.detach(function () { context.done(err, data) })
                console.log('IDS/IPS', ` Execution EXISTED - Elapsed in ${new Date().getTime() - startedTimestamp} ms`)
            }
        }, function (err, data) {
            ids.detach(function () { callback && callback(err, data) })
            console.log('IDS/IPS', ` Execution EXISTED - Elapsed in ${new Date().getTime() - startedTimestamp} ms`)
        })
        if (promiseResult && typeof promiseResult.then === 'function') {
            return new Promise((resolve, reject) => {
                promiseResult.then(lambdaResult => {
                    ids.detach(function () { resolve(lambdaResult) })
                    console.log('IDS/IPS', ` Execution EXISTED - Elapsed in ${new Date().getTime() - startedTimestamp} ms`)
                }).catch(lambdaErr => {
                    ids.detach(function () { reject(lambdaErr) })
                    console.log('IDS/IPS', ` Execution EXISTED - Elapsed in ${new Date().getTime() - startedTimestamp} ms`)
                })
            })
        }
    } else {
        console.error({ message: 'Missing or incorrect "IDS_LAMBDA_HANDLER" environment variable.' })
    }
}