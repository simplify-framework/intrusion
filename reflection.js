var { Firewall } = require('./index.js')
var firewall = new Firewall({
    allowDomainsOrHostIPs: (process.env.IDS_ALLOWED_HOSTS || "").split(','),
    allowSHA256OfCodeModules: (process.env.IDS_ALLOWED_MODULES || "").split(','),
    blockedHashOrHostValues: (process.env.IDS_BLOCKED_HOSTS_OR_MPDULES || "").split(',')
}, process.env.IDS_DOMAIN_NAME)

module.exports.handler = function (event, context, callback) {
    const lambdaHandler = process.env.ORIGIN_LAMBDA_HANDLER
    if (typeof lambdaHandler === 'string' && lambdaHandler) {
        const handlerParts = lambdaHandler.split('.')
        require(`${handlerParts[0].trim()}`)[`${handlerParts[1].trim()}`](event, context, function (err, data) {
            firewall.detach() && callback && callback(err, data)
        })
    } else {
        callback({ message: 'Missing "ORIGIN_LAMBDA_HANDLER" environment variable.' })
    }
}