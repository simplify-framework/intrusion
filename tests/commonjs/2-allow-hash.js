var { IDS } = require('../../index.js')
var firewall = new IDS({
    network: { allowDomainsOrHostIPs: [], blockDomainsOrHostIPs: ['*'] },
    host: { allowSHA256OfCodeModules: ['QsPV5N10sTZExAjkbZuQn5yEe0Jkpd4rHRnSxH9dF7Y'], blockSHA256OfCodeModules: [] }
}, 'TestApp/IDS', 'dev.null.org')

module.exports = function() {
    return new Promise((resolve, reject) => {
        require('./app-1')().then(() => {
            firewall.detach()
            resolve()
        }).catch(err => reject(err))
    })
}