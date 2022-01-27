var { IDS } = require('./index.js')
const { getData_thirdParty } = require('./require-hook/index.js')
var ids = new IDS({
    network: {
        allowDomainsOrHostIPs: (process.env.IDS_ALLOWED_HOSTS || "").split(','),
        blockDomainsOrHostIPs: (process.env.IDS_BLOCKED_HOSTS || "").split(',')
    },
    host: {
        allowModuleOrSHA256OfCode: (process.env.IDS_ALLOWED_MODULES || "").split(','),
        blockModuleOrSHA256OfCode: (process.env.IDS_BLOCKED_MODULES || "").split(',')
    },
}, process.env.IDS_CLOUDWATCH_DOMAIN_NAME, process.env.IDS_HONEYPOT_SERVER, process.env.IDS_ENABLE_METRIC_LOGGING == "true")

module.exports.handler = function (event, context, callback) {
    const lambdaHandler = process.env.IDS_LAMBDA_HANDLER
    if (typeof lambdaHandler === 'string' && lambdaHandler) {
        const handlerParts = lambdaHandler.split('.')
        require(`${handlerParts[0].trim()}`)[`${handlerParts[1].trim()}`](event, {
            ...context, succeed: function (data) {
                ids.detach(function () { context.succeed(data) })
            }, done: function (err, data) {
                ids.detach(function () { context.done(err, data) })
            }
        }, function (err, data) {
            ids.detach(function () { callback && callback(err, data) })
        })
    } else {
        callback({ message: 'Missing "IDS_LAMBDA_HANDLER" environment variable.' })
    }
}