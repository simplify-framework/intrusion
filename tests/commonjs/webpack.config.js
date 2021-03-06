const fs = require('fs')
const path = require('path')
const nodeExternals = require('webpack-node-externals')
const LicenseCheckerWebpackPlugin = require("license-checker-webpack-plugin")
var nodeModules = {};

// note the path.resolve(__dirname, ...) part
// without it, eslint-import-resolver-webpack fails
// since eslint might be invoked with different cwd
fs.readdirSync(path.resolve(__dirname, 'node_modules'))
    .filter(x => ['.bin'].indexOf(x) === -1)
    .forEach(mod => { nodeModules[mod] = `commonjs ${mod}`; });

module.exports = {
    entry: {
        index: './app.js',
    },
    output: {
        path: path.join(__dirname, 'build'),
        publicPath: '/',
        filename: '[name].js',
        libraryTarget: 'umd'
    },
    target: 'node',
    mode: 'production',
    node: {
        // Need this when working with express, otherwise the build fails
        __dirname: false,     // if you don't put this is, __dirname
        __filename: false,    // and __filename return blank or /
    },
    externals: { '_http_client':'commonjs _http_client', ...nodeModules}, // Need this to avoid error when working with Express
    module: {
        rules: [
            {
                // Transpiles ES6-8 into ES5
                test: /\.js$/,
                exclude: [
                    /node_modules/
                ],
                use: ["babel-loader", "remove-hashbag-loader"]
            },
            {
                // Transpiles files into memory
                test: /\.yaml$/,
                exclude: [
                    /node_modules/
                ],
                use: ["file-loader", "remove-hashbag-loader"]
            }
        ]
    },
    resolveLoader: {
        alias: {
          "remove-hashbag-loader": path.join(__dirname, "./loaders/hashbag")
        }
    },
    plugins: [
        new LicenseCheckerWebpackPlugin({
            allow: "(Apache-2.0 OR BSD-2-Clause OR BSD-3-Clause OR MIT OR ISC OR 0BSD)",
            ignore: ["@microsoft/*"],
            override: {
              "assignment@2.0.0": { licenseName: "MIT" },
              "intersection-observer@0.5.0": { licenseName: "MIT" },
              "querystring-es3@0.2.1": { licenseName: "MIT" }
            },
            emitError: true
        })
    ],
    stats: {
        warnings: false
    }
}