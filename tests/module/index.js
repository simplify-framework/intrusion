import { Firewall } from 'simplify-intrusion'

const firewall = new Firewall({
    allowDomainsOrHostIPs: [],
    allowSHA256OfCodeModules: ["OtbUd5po/kQtu2FweSNa42kOfFYZvlsFuen1xXeOPKs="],
    blockedHashOrHostValues: []
}, 'TestApp/Firewall')

import https from 'https'
var r = https.request("https://pastebin.com/jWKHzPaq", (res) => {
    console.log(res.statusCode, res.headers.date)
    firewall.detach()
})
r && r.end()


