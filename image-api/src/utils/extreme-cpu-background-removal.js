// src/utils/cpu-background-removal.js - Fixed EXTREME CPU-intensive background removal
const sharp = require('sharp');
const { Worker } = require('worker_threads');
const os = require('os');
const path = require('path');

class ExtremeCPUBackgroundRemoval {
    
    /**
     * Multi-threaded version using worker threads for maximum CPU utilization
     */
    static async multiThreadedRemoval(imageBuffer, options = {}) {
        const numCores = os.cpus().length;
        const startTime = Date.now();
        
        console.log(`Starting multi-threaded EXTREME background removal on ${numCores} cores`);
        
        try {
            // Get image metadata for processing
            const image = sharp(imageBuffer);
            const metadata = await image.metadata();
            const targetWidth = Math.min(metadata.width || 800, 1000);
            const targetHeight = Math.round((targetWidth / (metadata.width || 800)) * (metadata.height || 600));
            
            // Get raw pixel data
            const { data: imageData } = await image
                .resize(targetWidth, targetHeight)
                .removeAlpha()
                .raw()
                .toBuffer({ resolveWithObject: true });
            
            // Process with multiple threads for maximum CPU load
            const workerPromises = [];
            
            for (let i = 0; i < numCores; i++) {
                const workerOptions = {
                    imageData: Array.from(imageData),
                    width: targetWidth,
                    height: targetHeight,
                    workerId: i,
                    iterations: 5 + (i * 2), // Different intensity per worker
                    edgeThreshold: 30 + (i * 5),
                    colorTolerance: 40 + (i * 5)
                };
                
                const workerPromise = new Promise((resolve, reject) => {
                    const worker = new Worker(path.join(__dirname, 'extreme-bg-worker.js'), {
                        workerData: workerOptions
                    });

                    worker.on('message', resolve);
                    worker.on('error', reject);
                    worker.on('exit', (code) => {
                        if (code !== 0) {
                            reject(new Error(`Background removal worker ${i} failed`));
                        }
                    });
                });
                
                workerPromises.push(workerPromise);
            }

            const results = await Promise.all(workerPromises);
            const processingTime = Date.now() - startTime;
            
            // Use the result from the first successful worker
            const bestResult = results.find(r => r && r.mask) || results[0];
            const totalOperations = results.reduce((sum, r) => sum + (r.operations || 0), 0);
            const totalPixelsProcessed = results.reduce((sum, r) => sum + (r.pixelsProcessed || 0), 0);
            
            // Create final image with transparency
            const finalImage = await this.createFinalImage(imageBuffer, bestResult.mask, targetWidth, targetHeight);
            
            return {
                processedImage: finalImage,
                processingStats: {
                    processingTime,
                    pixelsProcessed: totalPixelsProcessed,
                    cpuOperations: totalOperations,
                    algorithmsUsed: ['multi-threaded-processing', 'extreme-algorithms'],
                    intensityLevel: 'MAXIMUM',
                    width: targetWidth,
                    height: targetHeight,
                    threadsUsed: numCores,
                    operationsPerSecond: Math.round(totalOperations / (processingTime / 1000))
                }
            };
            
        } catch (error) {
            console.error('Multi-threaded background removal failed:', error);
            throw error;
        }
    }

    /**
     * Create final image with transparency using processed mask
     */
    static async createFinalImage(originalBuffer, mask, maskWidth, maskHeight) {
        const image = sharp(originalBuffer);
        const metadata = await image.metadata();
        
        // Resize mask if needed to match original image
        let finalMask;
        if (metadata.width !== maskWidth || metadata.height !== maskHeight) {
            finalMask = await sharp(Buffer.from(mask), {
                raw: { width: maskWidth, height: maskHeight, channels: 1 }
            })
            .resize(metadata.width, metadata.height)
            .raw()
            .toBuffer();
        } else {
            finalMask = Buffer.from(mask);
        }

        // Get original image as RGBA
        const rgbaImage = await image
            .ensureAlpha()
            .raw()
            .toBuffer();

        // Apply mask to alpha channel
        for (let i = 0; i < finalMask.length; i++) {
            const alphaIndex = i * 4 + 3;
            if (alphaIndex < rgbaImage.length) {
                // If mask is white (255), make transparent (0)
                // If mask is black (0), keep opaque (255)
                rgbaImage[alphaIndex] = 255 - finalMask[i];
            }
        }

        // Convert back to PNG
        return await sharp(rgbaImage, {
            raw: { width: metadata.width, height: metadata.height, channels: 4 }
        })
        .png()
        .toBuffer();
    }

    /**
     * Fallback single-threaded method for compatibility
     */
    static async removeBackground(imageBuffer, options = {}) {
        return await this.multiThreadedRemoval(imageBuffer, options);
    }
}

module.exports = ExtremeCPUBackgroundRemoval;