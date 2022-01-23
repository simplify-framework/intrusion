var { IDS } = require('../../index.js')
var ids = new IDS({
    network: { allowDomainsOrHostIPs: [], blockDomainsOrHostIPs: ['*'] },
    host: { allowModuleOrSHA256OfCode: ['*'], blockModuleOrSHA256OfCode: ['*'] }
}, 'TestApp/IDS', 'dev.null.org')

module.exports = function () {
    return new Promise((resolve, reject) => {
        require('./build/index')().then(() => {
            ids.detach()
            resolve()
        }).catch(err => reject(err))
    })
}