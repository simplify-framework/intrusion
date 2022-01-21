var { Firewall } = require('../../index.js')
var firewall = new Firewall({
    allowDomainsOrHostIPs: ['pastebin.com'],
    allowSHA256OfCodeModules: [],
    blockedHashOrHostValues: ['*']
}, 'TestApp/Firewall')

module.exports = function() {
    return new Promise((resolve) => {
        require('./app-2')().then(() => {
            firewall.detach()
            resolve()
        }).catch(err => resolve(err))
    })
}