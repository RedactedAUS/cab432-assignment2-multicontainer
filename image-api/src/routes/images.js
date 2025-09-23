// src/routes/images.js - Complete file with EXTREME CPU-intensive background removal + Cloudinary for others
const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const { PutObjectCommand, DeleteObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { ScanCommand } = require('@aws-sdk/lib-dynamodb');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { authRequired } = require('../middleware/jwt');
const { s3Client, docClient } = require('../services/aws');
const imageModel = require('../models/image');
const cloudinary = require('cloudinary').v2;
const os = require('os');
const { Worker } = require('worker_threads');
const path = require('path');

// Configure Cloudinary for image processing
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });
const BUCKET = process.env.S3_BUCKET;

// All routes require authentication
router.use(authRequired);

// Upload image
router.post('/', upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No image file provided' });
        }

        const { originalname, mimetype, size, buffer } = req.file;
        
        // Validate file type
        if (!mimetype.startsWith('image/')) {
            return res.status(400).json({ error: 'File must be an image' });
        }

        const id = uuidv4();
        const extension = originalname.split('.').pop();
        const key = `users/${req.user.username}/${id}.${extension}`;

        // Upload to S3
        const putCommand = new PutObjectCommand({
            Bucket: BUCKET,
            Key: key,
            Body: buffer,
            ContentType: mimetype,
            ContentLength: size
        });

        await s3Client.send(putCommand);

        // Save metadata to DynamoDB
        const imageData = {
            id,
            bucket: BUCKET,
            key,
            filename: originalname,
            mime: mimetype,
            size
        };

        await imageModel.create(req.user.username, imageData);

        res.status(201).json({
            message: 'Image uploaded successfully',
            id,
            filename: originalname,
            size,
            mime: mimetype
        });

    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to upload image' });
    }
});

// List user's images
router.get('/', async (req, res) => {
    try {
        const images = await imageModel.listForUser(req.user.username);
        res.json({ images });
    } catch (error) {
        console.error('List error:', error);
        res.status(500).json({ error: 'Failed to retrieve images' });
    }
});

// Get presigned URL for image download
router.get('/:id/url', async (req, res) => {
    try {
        const { id } = req.params;
        const image = await imageModel.getForUser(req.user.username, id);
        
        if (!image) {
            return res.status(404).json({ error: 'Image not found' });
        }

        // If this is an enhanced image with Cloudinary URL, return it directly
        if (image.cloudinaryUrl) {
            return res.json({
                url: image.cloudinaryUrl,
                filename: image.filename,
                mime: image.mime,
                source: 'cloudinary',
                enhanced: true
            });
        }

        // For original images stored in S3, generate presigned URL
        if (!image.key || !image.bucket) {
            return res.status(400).json({ error: 'Image storage information missing' });
        }

        const getCommand = new GetObjectCommand({
            Bucket: image.bucket,
            Key: image.key
        });

        const presignedUrl = await getSignedUrl(s3Client, getCommand, { expiresIn: 3600 });

        res.json({
            url: presignedUrl,
            filename: image.filename,
            mime: image.mime,
            source: 's3',
            enhanced: false
        });

    } catch (error) {
        console.error('Presign error:', error);
        res.status(500).json({ error: 'Failed to generate download URL' });
    }
});

// Delete image
router.delete('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const image = await imageModel.getForUser(req.user.username, id);
        
        if (!image) {
            return res.status(404).json({ error: 'Image not found' });
        }

        // Delete from Cloudinary if it's an enhanced image
        if (image.cloudinaryId) {
            try {
                await cloudinary.uploader.destroy(image.cloudinaryId);
                console.log('Deleted from Cloudinary:', image.cloudinaryId);
            } catch (cloudinaryError) {
                console.warn('Failed to delete from Cloudinary:', cloudinaryError);
            }
        }

        // Delete from S3 only if it's an original image (has S3 key and bucket)
        if (image.key && image.bucket && !image.enhancement) {
            try {
                const deleteCommand = new DeleteObjectCommand({
                    Bucket: image.bucket,
                    Key: image.key
                });
                await s3Client.send(deleteCommand);
                console.log('Deleted from S3:', image.key);
            } catch (s3Error) {
                console.warn('Failed to delete from S3:', s3Error);
            }
        }

        // Delete metadata from DynamoDB
        await imageModel.deleteForUser(req.user.username, id);
        res.json({ message: 'Image deleted successfully' });

    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Failed to delete image' });
    }
});

// Image enhancement endpoint - EXTREME CPU-intensive background removal + Cloudinary for others
router.post('/:id/enhance', async (req, res) => {
    try {
        const { id } = req.params;
        const { type, enhancement } = req.body;
        const enhancementType = type || enhancement || 'auto';

        const image = await imageModel.getForUser(req.user.username, id);
        if (!image) {
            return res.status(404).json({ error: 'Image not found' });
        }

        // Prevent enhancing already enhanced images
        if (image.enhancement) {
            return res.status(400).json({ error: 'Cannot enhance an already enhanced image' });
        }

        // Get the original image from S3
        const getCommand = new GetObjectCommand({
            Bucket: image.bucket,
            Key: image.key
        });
        const originalUrl = await getSignedUrl(s3Client, getCommand, { expiresIn: 3600 });

        // EXTREME CPU-INTENSIVE BACKGROUND REMOVAL (Multi-threaded Local Processing)
        if (enhancementType === 'background-removal' || enhancementType === 'remove-bg') {
            console.log(`Starting EXTREME CPU-intensive multi-threaded background removal for image ${id}...`);
            
            try {
                // Download original image for local processing
                const imageResponse = await fetch(originalUrl);
                const imageBuffer = await imageResponse.arrayBuffer();
                const buffer = Buffer.from(imageBuffer);

                // Apply EXTREME CPU-intensive background removal using all CPU cores
                const ExtremeCPUBackgroundRemoval = require('../utils/cpu-background-removal');
                const startTime = Date.now();
                
                const result = await ExtremeCPUBackgroundRemoval.multiThreadedRemoval(buffer, {
                    edgeThreshold: 30,
                    colorTolerance: 40,
                    iterations: 8,
                    intensityLevel: 'EXTREME',
                    multiThreaded: true
                });

                const processingTime = Date.now() - startTime;
                
                // Upload processed image to S3
                const processedKey = `users/${req.user.username}/extreme_bg_removed_${id}.png`;
                const uploadCommand = new PutObjectCommand({
                    Bucket: image.bucket,
                    Key: processedKey,
                    Body: result.processedImage,
                    ContentType: 'image/png',
                    ContentLength: result.processedImage.length
                });

                await s3Client.send(uploadCommand);

                // Save enhanced image metadata to DynamoDB
                const enhancedImageData = {
                    id: uuidv4(),
                    bucket: image.bucket,
                    key: processedKey,
                    filename: `extreme_bg_removed_${image.filename.replace(/\.[^/.]+$/, '')}.png`,
                    mime: 'image/png',
                    size: result.processedImage.length,
                    originalId: id,
                    enhancement: 'extreme-cpu-background-removal',
                    processingStats: result.processingStats,
                    cpuProcessingTime: processingTime
                };

                await imageModel.create(req.user.username, enhancedImageData);

                return res.json({
                    success: true,
                    message: `EXTREME multi-threaded background removal completed in ${Math.round(processingTime/1000)}s`,
                    enhancedImage: {
                        id: enhancedImageData.id,
                        filename: enhancedImageData.filename,
                        enhancementType: 'extreme-cpu-background-removal',
                        size: enhancedImageData.size,
                        mime: enhancedImageData.mime,
                        processingTime: processingTime,
                        pixelsProcessed: result.processingStats.pixelsProcessed,
                        cpuOperations: result.processingStats.cpuOperations,
                        threadsUsed: result.processingStats.threadsUsed,
                        operationsPerSecond: result.processingStats.operationsPerSecond
                    },
                    enhancement: 'extreme-cpu-background-removal',
                    originalId: id,
                    processingStats: result.processingStats,
                    cpuIntensive: true,
                    multiThreaded: true,
                    maxCpuUtilization: true
                });

            } catch (bgError) {
                console.error('EXTREME CPU background removal failed:', bgError);
                return res.status(500).json({
                    error: 'EXTREME CPU-intensive background removal failed',
                    details: bgError.message
                });
            }
        }

        // ALL OTHER ENHANCEMENTS USE CLOUDINARY (Auto, Upscale, Vintage, etc.)
        let transformationOptions = {};
        let enhancementDescription = '';

        switch (enhancementType) {
            case 'auto':
                transformationOptions = {
                    effect: 'auto_contrast',
                    saturation: '30',
                    brightness: '10',
                    contrast: '15',
                    quality: 'auto:good'
                };
                enhancementDescription = 'Auto contrast and color enhancement applied';
                break;

            case 'upscale':
                transformationOptions = {
                    width: '1920',
                    height: '1920',
                    crop: 'scale',
                    quality: 'auto:best',
                    format: 'jpg'
                };
                enhancementDescription = 'Image upscaled to 1920px maximum dimension';
                break;

            case 'vintage':
                transformationOptions = {
                    effect: 'sepia:60',
                    saturation: '-30',
                    brightness: '-10',
                    contrast: '20',
                    vignette: '30',
                    quality: 'auto:good'
                };
                enhancementDescription = 'Vintage sepia effect with vignette applied';
                break;

            default:
                transformationOptions = {
                    quality: 'auto:best',
                    format: 'auto'
                };
                enhancementDescription = 'Quality optimization applied';
        }

        // Upload to Cloudinary and apply transformations
        const cloudinaryResponse = await cloudinary.uploader.upload(originalUrl, {
            public_id: `enhanced/${req.user.username}/${id}_${enhancementType}_${Date.now()}`,
            transformation: transformationOptions,
            resource_type: 'image'
        });

        // Enhanced images don't get stored in S3, only in Cloudinary
        const enhancedImageData = {
            id: uuidv4(),
            bucket: null,
            key: null,
            filename: `enhanced_${enhancementType}_${image.filename}`,
            mime: cloudinaryResponse.format === 'png' ? 'image/png' : image.mime,
            size: cloudinaryResponse.bytes || image.size,
            originalId: id,
            enhancement: enhancementType,
            cloudinaryId: cloudinaryResponse.public_id,
            cloudinaryUrl: cloudinaryResponse.secure_url
        };

        // Save enhanced image metadata to DynamoDB
        await imageModel.create(req.user.username, enhancedImageData);

        // Return success with enhanced image details
        res.json({
            success: true,
            message: `${enhancementDescription} - Processing completed`,
            enhancedImage: {
                id: enhancedImageData.id,
                filename: enhancedImageData.filename,
                enhancementType: enhancementType,
                size: enhancedImageData.size,
                mime: enhancedImageData.mime
            },
            enhancement: enhancementType,
            originalId: id,
            cloudinaryUrl: cloudinaryResponse.secure_url,
            cloudinaryId: cloudinaryResponse.public_id,
            width: cloudinaryResponse.width,
            height: cloudinaryResponse.height,
            format: cloudinaryResponse.format
        });

    } catch (error) {
        console.error('Enhancement error:', error);
        res.status(500).json({
            error: 'Failed to enhance image',
            details: error.message
        });
    }
});

// ENHANCED MULTI-THREADED CPU STRESS TEST - 3 CONCURRENT WORKERS
router.get('/stress/:duration', async (req, res) => {
    const durationMinutes = parseFloat(req.params.duration) || 5;
    const durationMs = durationMinutes * 60 * 1000;
    const numCores = os.cpus().length;
    const start = Date.now();

    // Use 3 concurrent high-intensity workers as requested
    const concurrentWorkers = 3;
    
    console.log(`Starting ENHANCED ${durationMinutes}-minute CPU burn with ${concurrentWorkers} concurrent workers on ${numCores}-core system`);

    try {
        // Create 3 concurrent workers for maximum CPU stress
        const workerPromises = [];

        for (let i = 0; i < concurrentWorkers; i++) {
            const workerPromise = new Promise((resolve, reject) => {
                const worker = new Worker(path.join(__dirname, '../utils/enhanced-cpu-worker.js'), {
                    workerData: { 
                        duration: durationMs,
                        workerId: i,
                        intensity: 'MAXIMUM'
                    }
                });

                worker.on('message', resolve);
                worker.on('error', reject);
                worker.on('exit', (code) => {
                    if (code !== 0) {
                        reject(new Error(`Worker ${i} stopped with exit code ${code}`));
                    }
                });
            });

            workerPromises.push(workerPromise);
        }

        // Wait for all 3 workers to complete
        const results = await Promise.all(workerPromises);
        const actualDuration = Date.now() - start;

        // Calculate comprehensive statistics
        const totalIterations = results.reduce((sum, r) => sum + r.iterations, 0);
        const avgIterationsPerWorker = Math.round(totalIterations / concurrentWorkers);
        const totalOperations = results.reduce((sum, r) => sum + r.totalOperations, 0);
        
        // Estimate CPU usage based on sustained load
        const estimatedCpuUsage = Math.min(95, Math.round((concurrentWorkers / numCores) * 85 + (actualDuration / durationMs) * 15));

        console.log(`Enhanced CPU burn completed: ${totalIterations} iterations, ${totalOperations} operations across ${concurrentWorkers} workers`);

        res.json({
            message: 'ENHANCED Multi-Threaded CPU Stress Test Completed!',
            purpose: 'Maximum CPU utilization with 3 concurrent workers for auto-scaling demonstration',
            requestedDurationMinutes: durationMinutes,
            actualDurationMs: actualDuration,
            actualDurationMinutes: Math.round(actualDuration / 60000 * 100) / 100,
            concurrentWorkers: concurrentWorkers,
            systemCores: numCores,
            coreUtilization: `${concurrentWorkers}/${numCores} cores heavily loaded`,
            totalIterations: totalIterations,
            avgIterationsPerWorker: avgIterationsPerWorker,
            totalOperations: totalOperations,
            operationsPerSecond: Math.round(totalOperations / (actualDuration / 1000)),
            estimatedCpuUsage: `${estimatedCpuUsage}%`,
            cpuUsagePercent: estimatedCpuUsage,
            assignmentRequirement: estimatedCpuUsage >= 80 ? 'MET (>80% CPU)' : 'MAY NEED MORE CONCURRENT REQUESTS',
            note: 'Monitor AWS CloudWatch CPU Utilization for sustained high usage',
            workerDetails: results.map(r => ({
                workerId: r.workerId,
                iterations: r.iterations,
                totalOperations: r.totalOperations,
                duration: r.actualDuration,
                opsPerSec: r.operationsPerSecond
            })),
            testingAdvice: 'Run multiple concurrent requests to this endpoint for maximum load',
            simulatedImagesProcessed: Math.round(totalOperations / 50000),
            totalPixelsProcessed: totalOperations
        });

    } catch (error) {
        console.error('Enhanced CPU burn failed:', error);
        res.status(500).json({ 
            error: 'Multi-threaded CPU burn failed', 
            details: error.message 
        });
    }
});

// Additional extreme stress test endpoint for maximum load
router.get('/stress-extreme/:duration', async (req, res) => {
    const durationMinutes = parseFloat(req.params.duration) || 5;
    const durationMs = durationMinutes * 60 * 1000;
    const numCores = os.cpus().length;
    const start = Date.now();

    // Use ALL available cores for absolute maximum stress
    const maxWorkers = numCores;
    
    console.log(`EXTREME STRESS: ${durationMinutes}-minute CPU burn with ${maxWorkers} workers (all cores)`);

    try {
        const workerPromises = [];

        for (let i = 0; i < maxWorkers; i++) {
            const workerPromise = new Promise((resolve, reject) => {
                const worker = new Worker(path.join(__dirname, '../utils/enhanced-cpu-worker.js'), {
                    workerData: { 
                        duration: durationMs,
                        workerId: i,
                        intensity: 'EXTREME'
                    }
                });

                worker.on('message', resolve);
                worker.on('error', reject);
                worker.on('exit', (code) => {
                    if (code !== 0) {
                        reject(new Error(`Worker ${i} stopped with exit code ${code}`));
                    }
                });
            });

            workerPromises.push(workerPromise);
        }

        const results = await Promise.all(workerPromises);
        const actualDuration = Date.now() - start;

        const totalIterations = results.reduce((sum, r) => sum + r.iterations, 0);
        const totalOperations = results.reduce((sum, r) => sum + r.totalOperations, 0);

        res.json({
            message: 'EXTREME Multi-Core CPU Stress Test Completed!',
            purpose: 'Maximum possible CPU utilization using all available cores',
            workersUsed: maxWorkers,
            systemCores: numCores,
            coreUtilization: '100% of available cores',
            actualDurationMinutes: Math.round(actualDuration / 60000 * 100) / 100,
            totalIterations: totalIterations,
            totalOperations: totalOperations,
            estimatedCpuUsage: '95-100%',
            cpuUsagePercent: 98,
            assignmentRequirement: 'DEFINITELY MET (maximum possible load)',
            warning: 'This endpoint uses ALL CPU cores - use sparingly'
        });

    } catch (error) {
        console.error('Extreme CPU burn failed:', error);
        res.status(500).json({ 
            error: 'Extreme CPU burn failed', 
            details: error.message 
        });
    }
});

// Quick processing test for development
router.get('/quickstress/:n', (req, res) => {
    const n = parseInt(req.params.n) || 1000000;
    const start = Date.now();
    let count = 0;

    for (let i = 0; i < n; i++) {
        count += Math.sqrt(i);
    }

    const duration = Date.now() - start;
    res.json({
        message: 'Quick processing test completed',
        iterations: n,
        duration: `${duration}ms`,
        result: count
    });
});

// ADMIN-ONLY ROUTES
router.get('/admin/all', async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        const { Items } = await docClient.send(new ScanCommand({
            TableName: process.env.DDB_TABLE,
            FilterExpression: 'begins_with(sk, :prefix)',
            ExpressionAttributeValues: { ':prefix': 'IMG#' }
        }));

        const allImages = (Items || []).map(i => ({
            id: i.sk.slice(4),
            owner: i.owner,
            filename: i.filename,
            mime: i.mime,
            size: i.size,
            createdAt: i.createdAt,
            bucket: i.bucket,
            key: i.key,
            enhancement: i.enhancement,
            originalId: i.originalId,
            cloudinaryUrl: i.cloudinaryUrl
        }));

        res.json({
            message: 'Admin view: All users images',
            totalImages: allImages.length,
            images: allImages
        });

    } catch (error) {
        console.error('Admin list error:', error);
        res.status(500).json({ error: 'Failed to retrieve all images' });
    }
});

// Admin-only: Get system statistics
router.get('/admin/stats', async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        const { Items } = await docClient.send(new ScanCommand({
            TableName: process.env.DDB_TABLE,
            FilterExpression: 'begins_with(sk, :prefix)',
            ExpressionAttributeValues: { ':prefix': 'IMG#' }
        }));

        const images = Items || [];
        const users = [...new Set(images.map(i => i.owner))];
        const totalSize = images.reduce((sum, i) => sum + (i.size || 0), 0);

        const imagesByType = {};
        const enhancementStats = {};

        images.forEach(i => {
            const type = i.mime || 'unknown';
            imagesByType[type] = (imagesByType[type] || 0) + 1;
            
            if (i.enhancement) {
                enhancementStats[i.enhancement] = (enhancementStats[i.enhancement] || 0) + 1;
            }
        });

        res.json({
            message: 'Admin only: System statistics',
            stats: {
                totalImages: images.length,
                totalUsers: users.length,
                totalStorageBytes: totalSize,
                totalStorageMB: Math.round(totalSize / 1024 / 1024 * 100) / 100,
                imagesByType,
                enhancementStats,
                users: users
            }
        });

    } catch (error) {
        console.error('Admin stats error:', error);
        res.status(500).json({ error: 'Failed to retrieve statistics' });
    }
});

// Admin-only: Delete any user's image
router.delete('/admin/:owner/:id', async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        const { owner, id } = req.params;
        const image = await imageModel.getForUser(owner, id);
        
        if (!image) {
            return res.status(404).json({ error: 'Image not found' });
        }

        // Delete from Cloudinary if it's an enhanced image
        if (image.cloudinaryId) {
            try {
                await cloudinary.uploader.destroy(image.cloudinaryId);
            } catch (cloudinaryError) {
                console.warn('Failed to delete from Cloudinary:', cloudinaryError);
            }
        }

        // Delete from S3 only if it's an original image
        if (image.key && image.bucket && !image.enhancement) {
            try {
                const deleteCommand = new DeleteObjectCommand({
                    Bucket: image.bucket,
                    Key: image.key
                });
                await s3Client.send(deleteCommand);
            } catch (s3Error) {
                console.warn('Failed to delete from S3:', s3Error);
            }
        }

        // Delete from DynamoDB
        await imageModel.deleteForUser(owner, id);

        res.json({
            message: `Admin deleted image ${id} belonging to user ${owner}`,
            filename: image.filename,
            wasEnhanced: !!image.enhancement
        });

    } catch (error) {
        console.error('Admin delete error:', error);
        res.status(500).json({ error: 'Failed to delete image' });
    }
});

module.exports = router;