// aws-setup.js - Run this script to create your AWS resources
require('dotenv').config();
const { S3Client, CreateBucketCommand } = require('@aws-sdk/client-s3');
const { DynamoDBClient, CreateTableCommand } = require('@aws-sdk/client-dynamodb');

// Your QUT username
const QUT_USERNAME = 'n11538082';
const BUCKET_NAME = `${QUT_USERNAME}-cab432-images`;
const TABLE_NAME = `${QUT_USERNAME}-cab432-images`;

async function setupAWS() {
    const s3Client = new S3Client({ region: 'ap-southeast-2' });
    const dynamoClient = new DynamoDBClient({ region: 'ap-southeast-2' });

    console.log('Setting up AWS resources...');
    console.log('Bucket:', BUCKET_NAME);
    console.log('Table:', TABLE_NAME);

    // Create S3 Bucket
    try {
        const bucketCommand = new CreateBucketCommand({
            Bucket: BUCKET_NAME,
            CreateBucketConfiguration: {
                LocationConstraint: 'ap-southeast-2'
            }
        });
        
        const bucketResponse = await s3Client.send(bucketCommand);
        console.log('âœ… S3 Bucket created:', BUCKET_NAME);
    } catch (error) {
        if (error.name === 'BucketAlreadyOwnedByYou') {
            console.log('âœ… S3 Bucket already exists:', BUCKET_NAME);
        } else {
            console.error('âŒ Error creating S3 bucket:', error.message);
        }
    }

    // Create DynamoDB Table
    try {
        const tableCommand = new CreateTableCommand({
            TableName: TABLE_NAME,
            AttributeDefinitions: [
                {
                    AttributeName: 'pk',
                    AttributeType: 'S'
                },
                {
                    AttributeName: 'sk', 
                    AttributeType: 'S'
                }
            ],
            KeySchema: [
                {
                    AttributeName: 'pk',
                    KeyType: 'HASH'
                },
                {
                    AttributeName: 'sk',
                    KeyType: 'RANGE'
                }
            ],
            ProvisionedThroughput: {
                ReadCapacityUnits: 5,
                WriteCapacityUnits: 5
            }
        });

        const tableResponse = await dynamoClient.send(tableCommand);
        console.log('âœ… DynamoDB Table created:', TABLE_NAME);
    } catch (error) {
        if (error.name === 'ResourceInUseException') {
            console.log('âœ… DynamoDB Table already exists:', TABLE_NAME);
        } else {
            console.error('âŒ Error creating DynamoDB table:', error.message);
        }
    }

    console.log('\nðŸ“ Add these to your .env file:');
    console.log(`S3_BUCKET=${BUCKET_NAME}`);
    console.log(`DDB_TABLE=${TABLE_NAME}`);
}

setupAWS().catch(console.error);