var { IDS } = require('../../index.js')
var ids = new IDS({
    network: { allowDomainsOrHostIPs: ['pastebin.com'], blockDomainsOrHostIPs: ['*'] },
    host: { allowModuleOrSHA256OfCode: [], blockModuleOrSHA256OfCode: [] }
}, 'TestApp/IDS', 'dev.null.org')

module.exports = function() {
    return new Promise((resolve, reject) => {
        require('./app-2')().then(() => {
            ids.detach()
            resolve()
        }).catch(err => reject(err))
    })
}