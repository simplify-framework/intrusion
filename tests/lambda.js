module.exports.handler = function (event, context, callback) {
    var https = require('https')
    var AWS = require('aws-sdk')
    console.log(AWS.config.region)
    var r = https.request({
        host: "pastebin.com",
        path: "/jWKHzPaq"
    }, (res) => { callback(null, `\t https.request('${res.req.protocol}//${res.req.host}${res.req.path}') - ${res.statusMessage}`) })
    r && r.on('error', err => { console.log(`https.request`, err.message); callback(err) })
    r && r.end()
}