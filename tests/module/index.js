import { IDS } from '../../index.js'

const firewall = new IDS({
    network: {
        allowDomainsOrHostIPs: [],
        blockDomainsOrHostIPs: []
    },
    host: {
        allowSHA256OfCodeModules: ["OtbUd5po/kQtu2FweSNa42kOfFYZvlsFuen1xXeOPKs="],
        blockSHA256OfCodeModules: []
    }
}, 'TestApp/IDS')

import https from 'https'
var r = https.request("https://pastebin.com/jWKHzPaq", (res) => {
    console.log(res.statusCode, res.headers.date)
    firewall.detach()
})
r && r.end()


