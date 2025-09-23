// src/services/aws.js
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient } = require('@aws-sdk/lib-dynamodb');
const { S3Client } = require('@aws-sdk/client-s3');

const region = process.env.AWS_REGION || 'ap-southeast-2';

// DynamoDB setup
const dynamoClient = new DynamoDBClient({ region });
const docClient = DynamoDBDocumentClient.from(dynamoClient);

// S3 setup
const s3Client = new S3Client({ region });

module.exports = {
  docClient,
  s3Client
};