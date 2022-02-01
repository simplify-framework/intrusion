#!/usr/bin/bash
export IDS_LAMBDA_HANDLER=$(pwd)/tests/lambda.handler;
node -e "require('./reflection').handler(null,null,function(err,data) {console.log(err?err:data)})"