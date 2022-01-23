'use strict';
const CBEGIN = '\x1b[32m'
const CRESET = '\x1b[0m'
var spinnerChars = ['|', '/', '-', '\\'];
var spinnerIndex = 0;
const silentWithSpinner = function () {
    spinnerIndex = (spinnerIndex > 3) ? 0 : spinnerIndex;
    process.stdout.write('\r' + spinnerChars[spinnerIndex++] + ` ${CBEGIN}Simplify${CRESET} | Packing with webpack...`);
}

module.exports = function(source) {
    silentWithSpinner()
    return source.replace(/^#! .*\n/, "");
}