
var LIST_OPTIONS = [
    {
        name: `Block some hosts: '8.8.4.4', '8.8.8.8', '88.198.55.153'`,
        options: {
            network: { allowDomainsOrHostIPs: [], blockDomainsOrHostIPs: ['www.google.com', '8.8.4.4', '8.8.8.8', '88.198.55.153'] },
            host: { allowModuleOrSHA256OfCode: [], blockModuleOrSHA256OfCode: [] }
        }
    },
    {
        name: `Allow all hosts and modules: * * * *`,
        options: {
            network: { allowDomainsOrHostIPs: ['*'], blockDomainsOrHostIPs: ['*'] },
            host: { allowModuleOrSHA256OfCode: ['*'], blockModuleOrSHA256OfCode: ['*'] }
        }
    },
    {
        name: `Block module hash: 'requests', 'QsPV5N10sTZExAjkbZuQn5yEe0Jkpd4rHRnSxH9dF7Y='`,
        options: {
            network: { allowDomainsOrHostIPs: ['*'], blockDomainsOrHostIPs: [] },
            host: { allowModuleOrSHA256OfCode: ['./app', 'module'], blockModuleOrSHA256OfCode: ['requests','QsPV5N10sTZExAjkbZuQn5yEe0Jkpd4rHRnSxH9dF7Y='] }
        }
    }
]

LIST_OPTIONS.map(({ name, options }, idx) => {
    require('./main').run(require('./app'), 'javascript', { name, options }, idx)
    require('./main').run(require('./build/index'), 'webpack', { name, options }, idx)
})