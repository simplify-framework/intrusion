import { IDS } from '../../index.js'

const ids = new IDS({
    network: {
        allowDomainsOrHostIPs: [],
        blockDomainsOrHostIPs: []
    },
    host: {
        allowModuleOrSHA256OfCode: ["OtbUd5po/kQtu2FweSNa42kOfFYZvlsFuen1xXeOPKs="],
        blockModuleOrSHA256OfCode: []
    }
}, 'TestApp/IDS')

import https from 'https'
var r = https.request("https://pastebin.com/jWKHzPaq", (res) => {
    console.log(res.statusCode, res.headers.date)
    ids.detach()
})
r && r.end()


