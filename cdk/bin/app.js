#!/usr/bin/env node
// OnMind-XID CDK app (JavaScript, CJS). See ../ARCHITECTURE.md.
'use strict'
const cdk = require('aws-cdk-lib')
const { XidStack } = require('../lib/xid-stack')

const app = new cdk.App()

const termination = app.node.tryGetContext('terminationProtection')
const terminationProtection = termination === true || termination === 'true'

new XidStack(app, 'XidStack', {
  description: 'OnMind-XID: Lambda + DynamoDB (xusers/xclients/xmeta) + HTTP API',
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  terminationProtection,
})

app.synth()
