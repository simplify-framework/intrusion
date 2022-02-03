#!/usr/bin/bash
export IDS_LAMBDA_HANDLER=$(pwd)/tests/lambda.handler;
export IDS_ENABLE_MODULE_TRACKER="true"
export IDS_PRINT_OUTPUT_LOG="true"
node -e "require('./reflection').handler(null,null,function(err,data) {console.log(err?err:data)})"