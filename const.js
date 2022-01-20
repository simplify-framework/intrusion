const CUNDERLINE = '\x1b[4m'
const CRESET = '\x1b[0m'

const OPT_COMMANDS = [
    {
        name: "list", desc: "list all options of the service", options: [
            { name: "help", desc: "show a help for the list command" }
        ]
    }, {
        name: "create", desc: "create a service", options: [
            { name: "help", desc: "show a help for the create command" }
        ]
    }
]

module.exports = {
    OPT_COMMANDS
}
