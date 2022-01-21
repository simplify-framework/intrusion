var { Firewall } = require('../../index.js')
var firewall = new Firewall({
    allowDomainsOrHostIPs: [],
    allowSHA256OfCodeModules: ["QsPV5N10sTZExAjkbZuQn5yEe0Jkpd4rHRnSxH9dF7Y="],
    blockedHashOrHostValues: ['*']
}, 'TestApp/Firewall')

module.exports = function() {
    return new Promise((resolve) => {
        require('./app-1')().then(() => {
            firewall.detach()
            resolve()
        }).catch(err => resolve(err))
    })
}