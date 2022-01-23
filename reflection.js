var { IDS } = require('./index.js')
var ids = new IDS({
    network: {
        allowDomainsOrHostIPs: (process.env.IDS_ALLOWED_HOSTS || "").split(','),
        blockDomainsOrHostIPs: (process.env.IDS_BLOCKED_HOSTS || "").split(',') },
    host: {
        allowModuleOrSHA256OfCode: (process.env.IDS_ALLOWED_MODULES || "").split(','),
        blockModuleOrSHA256OfCode: (process.env.IDS_BLOCKED_MODULES || "").split(',') },
}, process.env.IDS_DOMAIN_NAME)

module.exports.handler = function (event, context, callback) {
    const lambdaHandler = process.env.ORIGIN_LAMBDA_HANDLER
    if (typeof lambdaHandler === 'string' && lambdaHandler) {
        const handlerParts = lambdaHandler.split('.')
        require(`${handlerParts[0].trim()}`)[`${handlerParts[1].trim()}`](event, context, function (err, data) {
            ids.detach() && callback && callback(err, data)
        })
    } else {
        callback({ message: 'Missing "ORIGIN_LAMBDA_HANDLER" environment variable.' })
    }
}