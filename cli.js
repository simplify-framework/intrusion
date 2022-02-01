'use strict';
const path = require('path')
const fs = require('fs')
const simplify = require('simplify-sdk')
const provider = require('simplify-sdk/provider')
const GREEN = '\x1b[32m'
const RED = '\x1b[31m'
const YELLOW = '\x1b[33m'
const WHITE = '\x1b[0m'
const BLUE = '\x1b[34m'
const VIOLET = '\x1b[35m'
const RESET = '\x1b[0m'
const opName = `IDS/IPS`
var argv = require('yargs')
    .usage('simplify-intrusion make|attach|detach [options]')
    .string('profile')
    .describe('profile', 'AWS Profile configuration')
    .alias('p', 'profile')
    .default('profile', 'default')
    .string('region')
    .describe('region', 'Specify your working AWS region')
    .alias('r', 'region')
    .string('bucket')
    .alias('b', 'bucket')
    .describe('bucket', 'S3 bucket to store the IDS/IPS archive code')
    .string('layer-name')
    .alias('l', 'layer-name')
    .describe('layer-name', 'Select a name to deploy the IDS/IPS feature')
    .string('function-name')
    .alias('f', 'function-name')
    .describe('function-name', 'Function name to attach the IDS/IPS feature')
    .string('layer-version-arn')
    .alias('a', 'layer-version-arn')
    .describe('layer-version-arn', 'Set a layer arn to attach the IDS/IPS feature')
    .demandOption([])
    .demandCommand(1)
    .argv;

argv.region = argv.region || (() => { simplify.finishWithErrors(opName, 'Missing --region option. Please specify an AWS Region to work with.') })()

var config = {
    Profile: argv.profile,
    Region: argv.region,
    LayerConfig: {},
    Bucket: {
        Name: argv.bucket,
        Key: new Date().toISOString().replace(/-/g, '').slice(0, 8)
    },
    OutputFile: '.simplify/meta.json'
}
const layerConfig = config.LayerConfig
const bucketName = config.Bucket.Name
const bucketKey = config.Bucket.Key
const inputDirectory = path.join(__dirname)
const distZippedPath = path.join(__dirname, 'dist')
const outputFilePath = path.join(distZippedPath, bucketKey)

var cmdOPS = (argv._[0] || 'make').toUpperCase()
if (cmdOPS == 'MAKE') {
    argv.bucket = argv.bucket || (() => { simplify.finishWithErrors(opName, 'Missing --bucket option. Please specify an S3 bucket name to store the IDS/IPS code.') })()
    argv.layerName = argv.layerName || (() => { simplify.finishWithErrors(opName, 'Missing --layer-name option. Please specify a Layer name to deploy the IDS/IPS feature.') })()
    createIDSLayer(argv.layerName, argv.profile, argv.region)
} else if (cmdOPS == 'ATTACH' || cmdOPS == 'DETACH') {
    let layerVersionArn = argv.layerVersionArn
    if (!layerVersionArn) {
        let metaOutput = getMetaOutputJSON(config)
        layerVersionArn = metaOutput.Output.LayerVersionArn
        if (!layerVersionArn) {
            argv.layerVersionArn = argv.layerVersionArn || (() => { simplify.finishWithErrors(opName, 'Missing --layer-version-arn option. Please specify a Layer ARN with version to deploy the IDS/IPS feature.') })()
        }
    }
    argv.functionName || (() => { simplify.finishWithErrors(opName, 'Missing --function-name option. Please specify a FunctionName to attach the IDS/IPS feature.') })()
    updateFunctionLayer(layerVersionArn, argv.functionName, cmdOPS == 'ATTACH' ? true : false)
} else {
    simplify.finishWithMessage(opName, 'Command not found. Use one of the following: make | attach | detach')
}

function getMetaOutputJSON(config) {
    const metadataFilePath = path.join(__dirname, config.OutputFile)
    if (!fs.existsSync(path.dirname(metadataFilePath))) {
        fs.mkdirSync(path.dirname(metadataFilePath))
    }
    return fs.existsSync(metadataFilePath) ? JSON.parse(fs.readFileSync(metadataFilePath)) : { Output: {}, Configuration: { Environment: { Variables: {} } } }
}

function updateFunctionLayer(layerVersionArn, functionName, attachOrDetach) {
    provider.setConfig(config).then(function () {
        simplify.consoleWithMessage(`${opName}-getFunction`, `${functionName}:${'$LATEST'}`)
        provider.getFunction().getFunction({
            FunctionName: functionName /** Possible to modify a $LATEST function version only */
        }, function (err, data) {
            if (err) {
                simplify.consoleWithMessage(`${opName}-GetFunction`, `${CERROR}(ERROR)${CRESET} ${err}`);
            } else {
                let functionData = { ...data, LayerInfos: [] }
                const layerArnWithoutVersion = layerVersionArn.split(':').slice(0, 7).join(':')
                simplify.consoleWithMessage(`${opName}-AttachLayerARN`, layerVersionArn)
                functionData.Configuration.Layers = functionData.Configuration.Layers.map(layer => {
                    const layerArn = typeof layer === 'string' ? layer : layer.Arn
                    if (layerArn.startsWith(layerArnWithoutVersion)) {
                        return undefined
                    }
                    return layerArn
                }).filter(x => x) || []
                if (attachOrDetach /** TRUE to attach the IDS/IPS layer */) {
                    functionData.Configuration.Layers.push(layerVersionArn)
                }
                const reflectionHandler = '/opt/nodejs/node_modules/simplify-intrusion/reflection.handler'
                let params = {
                    FunctionName: functionName,
                    Layers: functionData.Configuration.Layers,
                    Handler: `${reflectionHandler}`,
                    Environment: {
                        Variables: {
                            IDS_LAMBDA_HANDLER: `/var/task/${functionData.Configuration.Handler}`,
                            IDS_ALLOWED_HOSTS: "127.0.0.1,local",
                            IDS_BLOCKED_HOSTS: "127.0.0.2,malware.domain",
                            IDS_ALLOWED_MODULES: "fs,zlib",
                            IDS_BLOCKED_MODULES: "fake-module:1.0,test",
                            IDS_ENABLE_METRIC_LOGGING: "true",
                            IDS_CLOUDWATCH_DOMAIN_NAME: `${functionName}/IDS`,
                            IDS_HONEYPOT_SERVER: '127.0.0.1',
                            ...functionData.Configuration.Environment.Variables
                        }
                    }
                }
                if (functionData.Configuration.Handler != reflectionHandler) {
                    params.Environment.Variables['IDS_LAMBDA_HANDLER'] = `/var/task/${functionData.Configuration.Handler}`
                } else {
                    /** Keep the existing Environment Variables with no change */
                    params.Environment.Variables = functionData.Configuration.Environment.Variables
                }
                provider.getFunction().updateFunctionConfiguration(params, function (err, _) {
                    if (err) {
                        simplify.consoleWithMessage(`${opName}-UpdateFunctionConfig`, `${functionName} ${RED}(ERROR)${RESET} ${err}`);
                    } else {
                        simplify.consoleWithMessage(`${opName}-UpdateFunctionConfig`, `${functionName} ${GREEN}(OK)${RESET}`);
                    }
                })
            }
        })
    })
}

function createIDSLayer(layerName) {
    try {
        config.LayerConfig.LayerName = layerName
        provider.setConfig(config).then(function () {
            const LAYER_NAME = layerConfig.LayerName.split('-').join('_').toUpperCase()
            if (fs.existsSync(distZippedPath)) {
                fs.rmSync(distZippedPath, { recursive: true })
            }
            const metadataFilePath = path.join(__dirname, config.OutputFile)
            const metaOutput = getMetaOutputJSON(config)
            metaOutput.Output = {} /** RESET for every time to be consistent with the hash. */
            fs.writeFileSync(metadataFilePath, JSON.stringify(metaOutput, null, 4));

            simplify.uploadDirectoryAsZip({
                adaptor: provider.getStorage(),
                bucketName, bucketKey, inputDirectory, outputFilePath, fileName: 'layer', zippedDirectory: 'nodejs/node_modules/simplify-intrusion',
                hashInfo: simplify.getFunctionSha256(metadataFilePath, `SHA256_LAYER_${LAYER_NAME}_HASH`)
            }).then(function (uploadInfor) {
                if (uploadInfor.Key) {
                    var params = {
                        Content: {
                            S3Bucket: bucketName,
                            S3Key: `${bucketKey}/layer.zip`
                        },
                        ...layerConfig
                    };
                    provider.getFunction().publishLayerVersion(params, function (err, data) {
                        if (err) {
                            simplify.consoleWithMessage(`${opName}-CreateLayerVersion`, `${RED}(ERROR)${RESET} ${err}`);
                        } else {
                            metaOutput.Configuration.Environment.Variables[`SHA256_LAYER_${LAYER_NAME}_HASH`] = uploadInfor.FileSha256
                            metaOutput.Output = { LayerVersionArn: data.LayerVersionArn }
                            fs.writeFileSync(metadataFilePath, JSON.stringify(metaOutput, null, 4));
                            simplify.consoleWithMessage(`${opName}-CreateLayerVersion`, `${GREEN}(OK)${RESET} ${data.LayerVersionArn}`);
                        }
                    })
                } else {
                    simplify.finishWithSuccess(`${uploadInfor.HashSource} is UP_TO_DATE`)
                }
            }, function (err) {
                simplify.finishWithErrors(`${opName}-UploadZip`, err);
            })
        }).catch(function (err) {
            simplify.finishWithErrors(`${opName}-UploadDirectory`, err)
        })
    } catch (err) {
        simplify.finishWithErrors(`${opName}-LoadConfig`, err)
    }
}