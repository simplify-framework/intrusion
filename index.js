#!/usr/bin/env node
'use strict';
const YAML = require('yaml')
const path = require('path')
const fs = require('fs')
process.env.DISABLE_BOX_BANNER = true
const simplify = require('simplify-sdk')
const { options } = require('yargs');
const readlineSync = require('readline-sync');
const { OPT_COMMANDS } = require('./const')
const yargs = require('yargs');
const opName = `executePipeline`
const CERROR = '\x1b[31m'
const CGREEN = '\x1b[32m'
const CPROMPT = '\x1b[33m'
const CNOTIF = '\x1b[33m'
const CRESET = '\x1b[0m'
const CDONE = '\x1b[37m'
const CBRIGHT = '\x1b[37m'
const CUNDERLINE = '\x1b[4m'
const COLORS = function (name) {
    const colorCodes = ["\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[34m", "\x1b[35m", "\x1b[36m", "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[34m", "\x1b[35m", "\x1b[36m", "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[34m", "\x1b[35m", "\x1b[36m", "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[34m", "\x1b[35m", "\x1b[36m", "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[34m", "\x1b[35m", "\x1b[36m"]
    return colorCodes[(name.toUpperCase().charCodeAt(0) - 65) % colorCodes.length]
}
const envFilePath = path.resolve('.env')
if (fs.existsSync(envFilePath)) {
    require('dotenv').config({ path: envFilePath })
}

const showBoxBanner = function () {
    console.log("╓───────────────────────────────────────────────────────────────╖")
    console.log(`║                 Simplify Sample - Version ${require('./package.json').version}             ║`)
    console.log("╙───────────────────────────────────────────────────────────────╜")
}

const getErrorMessage = function (error) {
    return error.message ? error.message : JSON.stringify(error)
}

const getOptionDesc = function (cmdOpt, optName) {
    const options = (OPT_COMMANDS.find(cmd => cmd.name == cmdOpt) || { options: [] }).options
    return (options.find(opt => opt.name == optName) || { desc: '' }).desc
}

var argv = yargs.usage('simplify-sample create|list [sample] [options]')
    .string('help').describe('help', 'display help for a specific command')
    .string('sample').describe('sample', getOptionDesc('create', 'sample'))
    .demandCommand(1).argv;

showBoxBanner()

var cmdOPS = (argv._[0] || 'create').toUpperCase()
var optCMD = (argv._.length > 1 ? argv._[1] : undefined)
var index = -1
const projectName = argv['project'] || '.simplify-sample'
if (cmdOPS == 'CREATE') {
    if (!optCMD) {
        index = readlineSync.keyInSelect(['option1', 'option2'], `Select an option to execute ?`, {
            cancel: `${CBRIGHT}None${CRESET} - (Escape)`
        })
    } else {
    }
} else if (cmdOPS == 'LIST') {
    ['list', 'create'].map((cmd, idx) => {
        console.log(`\t- ${CPROMPT}${cmd.toLowerCase()}${CRESET}`)
    })
} else {
    yargs.showHelp()
    console.log(`\n`, ` * ${CBRIGHT}Supported command list${CRESET}:`, '\n')
    OPT_COMMANDS.map((cmd, idx) => {
        console.log(`\t- ${CPROMPT}${cmd.name.toLowerCase()}${CRESET} : ${cmd.desc}`)
    })
    console.log(`\n`)
    process.exit(0)
}
