// src/models/image.js - DynamoDB model for image metadata
const { PutCommand, QueryCommand, DeleteCommand } = require('@aws-sdk/lib-dynamodb');
const { docClient } = require('../services/aws');

const TABLE_NAME = process.env.DDB_TABLE;

exports.create = async (username, imageData) => {
    const timestamp = new Date().toISOString();
    
    const item = {
        pk: `USER#${username}`,
        sk: `IMG#${imageData.id}`,
        owner: username,
        id: imageData.id,
        filename: imageData.filename,
        mime: imageData.mime,
        size: imageData.size,
        bucket: imageData.bucket,
        key: imageData.key,
        createdAt: timestamp,
        enhancement: imageData.enhancement || null,
        originalId: imageData.originalId || null,
        cloudinaryId: imageData.cloudinaryId || null,
        cloudinaryUrl: imageData.cloudinaryUrl || null,
        processingStats: imageData.processingStats || null,
        cpuProcessingTime: imageData.cpuProcessingTime || null
    };

    const command = new PutCommand({
        TableName: TABLE_NAME,
        Item: item
    });

    await docClient.send(command);
    return item;
};

exports.listForUser = async (username) => {
    const command = new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'pk = :pk AND begins_with(sk, :sk)',
        ExpressionAttributeValues: {
            ':pk': `USER#${username}`,
            ':sk': 'IMG#'
        },
        ScanIndexForward: false
    });

    const result = await docClient.send(command);
    
    return (result.Items || []).map(item => ({
        id: item.sk.slice(4),
        filename: item.filename,
        mime: item.mime,
        size: item.size,
        createdAt: item.createdAt,
        bucket: item.bucket,
        key: item.key,
        enhancement: item.enhancement,
        enhancementType: item.enhancement,
        originalId: item.originalId,
        cloudinaryId: item.cloudinaryId,
        cloudinaryUrl: item.cloudinaryUrl,
        processingStats: item.processingStats,
        cpuProcessingTime: item.cpuProcessingTime
    }));
};

exports.getForUser = async (username, imageId) => {
    const command = new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'pk = :pk AND sk = :sk',
        ExpressionAttributeValues: {
            ':pk': `USER#${username}`,
            ':sk': `IMG#${imageId}`
        }
    });

    const result = await docClient.send(command);
    
    if (!result.Items || result.Items.length === 0) {
        return null;
    }

    const item = result.Items[0];
    return {
        id: imageId,
        filename: item.filename,
        mime: item.mime,
        size: item.size,
        createdAt: item.createdAt,
        bucket: item.bucket,
        key: item.key,
        enhancement: item.enhancement,
        enhancementType: item.enhancement,
        originalId: item.originalId,
        cloudinaryId: item.cloudinaryId,
        cloudinaryUrl: item.cloudinaryUrl,
        processingStats: item.processingStats,
        cpuProcessingTime: item.cpuProcessingTime
    };
};

exports.deleteForUser = async (username, imageId) => {
    const command = new DeleteCommand({
        TableName: TABLE_NAME,
        Key: {
            pk: `USER#${username}`,
            sk: `IMG#${imageId}`
        }
    });

    await docClient.send(command);
    return true;
};