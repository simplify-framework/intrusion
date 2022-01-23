var { Firewall } = require('../../index.js')
var firewall = new Firewall({
    allowDomainsOrHostIPs: ['*'],
    allowSHA256OfCodeModules: ['*'],
    blockedHashOrHostValues: []
}, 'TestApp/Firewall', 'dev.null.org')

module.exports = function () {
    return new Promise((resolve, reject) => {
        require('./app-1')().then(() => {
            firewall.detach()
            resolve()
        }).catch(err => reject(err))
    })
}