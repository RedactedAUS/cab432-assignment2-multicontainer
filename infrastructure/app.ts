#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { MpegVideoApiStack } from './lib/mpeg-video-api-stack';

const app = new cdk.App();
new MpegVideoApiStack(app, 'MpegVideoApiStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT || '901444280953',
    region: process.env.CDK_DEFAULT_REGION || 'ap-southeast-2',
  },
  tags: {
    Project: 'CAB432-Assessment2',
    Student: 'n11538082',
    Purpose: 'video-processing-api',
  },
});
