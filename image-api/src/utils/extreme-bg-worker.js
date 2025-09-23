// src/utils/extreme-bg-worker.js - Fixed worker for EXTREME background removal
const { parentPort, workerData } = require('worker_threads');

async function extremeBackgroundProcessing() {
    const { imageData, width, height, workerId, iterations, edgeThreshold, colorTolerance } = workerData;
    
    const startTime = Date.now();
    let operations = 0;
    const totalPixels = width * height;
    
    console.log(`Worker ${workerId}: Starting EXTREME processing ${width}x${height} with ${iterations} iterations`);
    
    try {
        // Convert array back to Uint8Array
        const pixelData = new Uint8Array(imageData);
        
        // EXTREME ALGORITHM 1: Multi-pass edge detection
        const edgeMaps = [];
        const kernels = [
            [[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]], // Sobel X
            [[-1, -2, -1], [0, 0, 0], [1, 2, 1]], // Sobel Y
            [[-1, 0, 1], [-1, 0, 1], [-1, 0, 1]], // Prewitt X
            [[-1, -1, -1], [0, 0, 0], [1, 1, 1]], // Prewitt Y
            [[0, -1, 0], [-1, 4, -1], [0, -1, 0]], // Laplacian 4
            [[-1, -1, -1], [-1, 8, -1], [-1, -1, -1]], // Laplacian 8
            [[1, 0, -1], [2, 0, -2], [1, 0, -1]], // Custom 1
            [[0, 1, 2], [-1, 0, 1], [-2, -1, 0]], // Custom 2
        ];

        for (let pass = 0; pass < iterations; pass++) {
            for (const kernel of kernels) {
                const edgeMap = new Uint8Array(totalPixels);
                
                for (let y = 1; y < height - 1; y++) {
                    for (let x = 1; x < width - 1; x++) {
                        const idx = y * width + x;
                        let convolution = 0;
                        
                        for (let ky = 0; ky < kernel.length; ky++) {
                            for (let kx = 0; kx < kernel[ky].length; kx++) {
                                const py = y + ky - 1;
                                const px = x + kx - 1;
                                const pixelIdx = py * width + px;
                                
                                const r = pixelData[pixelIdx * 3];
                                const g = pixelData[pixelIdx * 3 + 1];
                                const b = pixelData[pixelIdx * 3 + 2];
                                
                                // EXTREME intensity calculations
                                const intensity1 = 0.299 * r + 0.587 * g + 0.114 * b;
                                const intensity2 = (r + g + b) / 3;
                                const intensity3 = Math.sqrt(r * r + g * g + b * b) / Math.sqrt(3);
                                const intensity4 = Math.max(r, g, b);
                                const intensity5 = Math.min(r, g, b);
                                const avgIntensity = (intensity1 + intensity2 + intensity3 + intensity4 + intensity5) / 5;
                                
                                // Extra mathematical operations for CPU load
                                const enhanced1 = Math.pow(avgIntensity, 1.2);
                                const enhanced2 = avgIntensity * Math.sin(avgIntensity * 0.01);
                                const enhanced3 = avgIntensity * Math.cos(avgIntensity * 0.02);
                                const enhanced4 = Math.tanh(avgIntensity / 128) * 255;
                                const finalIntensity = (enhanced1 + enhanced2 + enhanced3 + enhanced4) / 4;
                                
                                convolution += finalIntensity * kernel[ky][kx];
                                operations += 20;
                            }
                        }
                        
                        const magnitude = Math.abs(convolution);
                        const normalized = magnitude / (255 * 9);
                        const enhanced = Math.pow(normalized, 0.8) * 255;
                        
                        edgeMap[idx] = enhanced > edgeThreshold ? 255 : 0;
                        operations += 5;
                    }
                }
                
                edgeMaps.push(edgeMap);
            }
        }

        // EXTREME ALGORITHM 2: Color-based segmentation with border sampling
        const colorMasks = [];
        
        for (let pass = 0; pass < iterations; pass++) {
            const colorMask = new Uint8Array(totalPixels);
            
            // Sample border colors for background detection
            const borderSamples = [];
            const sampleSize = Math.min(50, Math.floor(Math.min(width, height) / 10));
            
            // Sample from all four borders
            for (let i = 0; i < sampleSize; i++) {
                const positions = [
                    { x: i, y: 0 }, // Top
                    { x: i, y: height - 1 }, // Bottom
                    { x: 0, y: i }, // Left
                    { x: width - 1, y: i }, // Right
                    { x: width - 1 - i, y: 0 }, // Top-right
                    { x: width - 1 - i, y: height - 1 }, // Bottom-right
                ];
                
                for (const pos of positions) {
                    if (pos.x >= 0 && pos.x < width && pos.y >= 0 && pos.y < height) {
                        const idx = pos.y * width + pos.x;
                        const r = pixelData[idx * 3];
                        const g = pixelData[idx * 3 + 1];
                        const b = pixelData[idx * 3 + 2];
                        
                        borderSamples.push({ r, g, b });
                        operations += 3;
                    }
                }
            }

            // Calculate average background color
            let avgR = 0, avgG = 0, avgB = 0;
            for (const sample of borderSamples) {
                avgR += sample.r;
                avgG += sample.g;
                avgB += sample.b;
                operations += 3;
            }
            avgR /= borderSamples.length;
            avgG /= borderSamples.length;
            avgB /= borderSamples.length;

            // Apply color-based segmentation with EXTREME CPU operations
            for (let i = 0; i < totalPixels; i++) {
                const r = pixelData[i * 3];
                const g = pixelData[i * 3 + 1];
                const b = pixelData[i * 3 + 2];
                
                // Multiple distance calculations for CPU intensity
                const euclideanDist = Math.sqrt(
                    Math.pow(r - avgR, 2) + 
                    Math.pow(g - avgG, 2) + 
                    Math.pow(b - avgB, 2)
                );
                
                const manhattanDist = Math.abs(r - avgR) + Math.abs(g - avgG) + Math.abs(b - avgB);
                const chebyshevDist = Math.max(Math.abs(r - avgR), Math.abs(g - avgG), Math.abs(b - avgB));
                
                // EXTREME combined distance with trigonometric functions
                const combinedDist = (euclideanDist * 0.5 + manhattanDist * 0.3 + chebyshevDist * 0.2);
                const weightedDist = combinedDist * Math.sin(combinedDist * 0.01) * Math.cos(combinedDist * 0.01);
                
                // Additional CPU-intensive calculations
                const normalizedDist = weightedDist / (Math.sqrt(3) * 255);
                const adaptiveTolerance = colorTolerance * (1 + Math.sin(i * 0.001) * 0.2);
                const confidence = Math.exp(-normalizedDist * adaptiveTolerance);
                const finalScore = confidence * Math.tanh(confidence * 2);
                
                colorMask[i] = finalScore > 0.6 ? 255 : 0;
                operations += 20;
            }
            
            colorMasks.push(colorMask);
        }

        // EXTREME ALGORITHM 3: Texture analysis
        const textureMaps = [];
        
        for (let pass = 0; pass < iterations; pass++) {
            const textureMap = new Uint8Array(totalPixels);
            
            for (let y = 2; y < height - 2; y++) {
                for (let x = 2; x < width - 2; x++) {
                    const idx = y * width + x;
                    
                    // Calculate texture features in 5x5 neighborhood
                    let variance = 0, entropy = 0, contrast = 0;
                    const intensities = [];
                    
                    for (let dy = -2; dy <= 2; dy++) {
                        for (let dx = -2; dx <= 2; dx++) {
                            const neighborIdx = (y + dy) * width + (x + dx);
                            const r = pixelData[neighborIdx * 3];
                            const g = pixelData[neighborIdx * 3 + 1];
                            const b = pixelData[neighborIdx * 3 + 2];
                            
                            // Multiple intensity calculations for CPU load
                            const intensity1 = 0.299 * r + 0.587 * g + 0.114 * b;
                            const intensity2 = (r + g + b) / 3;
                            const intensity3 = Math.sqrt(r * r + g * g + b * b) / Math.sqrt(3);
                            const avgIntensity = (intensity1 + intensity2 + intensity3) / 3;
                            
                            intensities.push(avgIntensity);
                            operations += 8;
                        }
                    }
                    
                    // Calculate texture statistics
                    const mean = intensities.reduce((a, b) => a + b, 0) / intensities.length;
                    
                    for (const intensity of intensities) {
                        const diff = intensity - mean;
                        variance += diff * diff;
                        
                        // Entropy calculation
                        if (intensity > 0) {
                            const probability = intensity / 255;
                            entropy += probability * Math.log2(probability + 1e-10);
                        }
                        
                        contrast += diff * diff;
                        operations += 5;
                    }
                    
                    variance /= intensities.length;
                    entropy = Math.abs(entropy) / intensities.length;
                    contrast /= intensities.length;
                    
                    // Combine texture features
                    const textureComplexity = variance * 0.4 + entropy * 0.3 + contrast * 0.3;
                    const normalizedTexture = Math.min(255, textureComplexity / 10);
                    
                    // High texture = likely foreground (0), low texture = background (255)
                    textureMap[idx] = normalizedTexture > 30 ? 0 : 255;
                    operations += 10;
                }
            }
            
            textureMaps.push(textureMap);
        }

        // EXTREME ALGORITHM 4: Combine all masks
        const combinedMask = new Uint8Array(totalPixels);
        
        for (let i = 0; i < totalPixels; i++) {
            // Combine edge maps
            let edgeScore = 0;
            for (const edgeMap of edgeMaps) {
                edgeScore += edgeMap[i] / 255;
                operations += 2;
            }
            edgeScore /= edgeMaps.length;
            
            // Combine color masks
            let colorScore = 0;
            for (const colorMap of colorMasks) {
                colorScore += colorMap[i] / 255;
                operations += 2;
            }
            colorScore /= colorMasks.length;
            
            // Combine texture maps
            let textureScore = 0;
            for (const textureMap of textureMaps) {
                textureScore += textureMap[i] / 255;
                operations += 2;
            }
            textureScore /= textureMaps.length;
            
            // EXTREME weighted combination
            const edgeWeight = 0.3 + 0.1 * Math.sin(i * 0.001);
            const colorWeight = 0.4 + 0.1 * Math.cos(i * 0.001);
            const textureWeight = 0.3 + 0.1 * Math.tan(i * 0.0005);
            
            const combinedScore = 
                (1 - edgeScore) * edgeWeight + 
                colorScore * colorWeight + 
                textureScore * textureWeight;
                
            // Additional CPU-intensive calculations
            const sigmoid = 1 / (1 + Math.exp(-combinedScore * 8 + 4));
            const tanh = Math.tanh(combinedScore * 6 - 3);
            const finalScore = (sigmoid * 0.7 + tanh * 0.3);
            
            combinedMask[i] = finalScore > 0.6 ? 255 : 0;
            operations += 15;
        }

        // EXTREME ALGORITHM 5: Morphological refinement
        let currentMask = combinedMask;
        
        for (let iter = 0; iter < iterations; iter++) {
            const newMask = new Uint8Array(totalPixels);
            const kernelSize = 5; // 5x5 kernel
            const radius = 2;
            
            for (let y = radius; y < height - radius; y++) {
                for (let x = radius; x < width - radius; x++) {
                    const idx = y * width + x;
                    
                    let minVal = 255, maxVal = 0, avgVal = 0, count = 0;
                    let variance = 0;
                    
                    // 5x5 neighborhood processing
                    for (let dy = -radius; dy <= radius; dy++) {
                        for (let dx = -radius; dx <= radius; dx++) {
                            const neighborIdx = (y + dy) * width + (x + dx);
                            const val = currentMask[neighborIdx];
                            
                            minVal = Math.min(minVal, val);
                            maxVal = Math.max(maxVal, val);
                            avgVal += val;
                            count++;
                            
                            operations += 4;
                        }
                    }
                    
                    avgVal /= count;
                    
                    // Calculate variance for additional CPU load
                    for (let dy = -radius; dy <= radius; dy++) {
                        for (let dx = -radius; dx <= radius; dx++) {
                            const neighborIdx = (y + dy) * width + (x + dx);
                            const val = currentMask[neighborIdx];
                            const diff = val - avgVal;
                            variance += diff * diff;
                            operations += 3;
                        }
                    }
                    variance /= count;
                    
                    // EXTREME morphological decision
                    let morphResult;
                    if (variance > 2000) {
                        morphResult = maxVal; // High variance - preserve details
                    } else if (variance < 500) {
                        morphResult = (iter % 2 === 0) ? minVal : maxVal; // Low variance - erode/dilate
                    } else {
                        morphResult = avgVal; // Medium variance - median
                    }
                    
                    // Additional CPU-intensive smoothing
                    const smoothed = morphResult * Math.sin(morphResult * 0.01) * Math.cos(variance * 0.001);
                    const enhanced = Math.pow(Math.abs(smoothed) / 255, 1.1) * 255;
                    
                    newMask[idx] = enhanced > 127 ? 255 : 0;
                    operations += 8;
                }
            }
            
            currentMask = newMask;
        }

        // EXTREME ALGORITHM 6: Final refinement with distance transform
        const finalMask = new Uint8Array(totalPixels);
        const featherRadius = 3;
        
        for (let i = 0; i < totalPixels; i++) {
            const x = i % width;
            const y = Math.floor(i / width);
            
            if (currentMask[i] === 0) { // Foreground pixel
                let minBgDist = featherRadius + 1;
                
                // Find distance to nearest background pixel
                for (let dy = -featherRadius; dy <= featherRadius; dy++) {
                    for (let dx = -featherRadius; dx <= featherRadius; dx++) {
                        const ny = y + dy;
                        const nx = x + dx;
                        
                        if (ny >= 0 && ny < height && nx >= 0 && nx < width) {
                            const neighborIdx = ny * width + nx;
                            if (currentMask[neighborIdx] === 255) {
                                const dist = Math.sqrt(dx * dx + dy * dy);
                                minBgDist = Math.min(minBgDist, dist);
                            }
                        }
                        operations += 3;
                    }
                }
                
                // Apply feathering
                const featherFactor = Math.min(1, minBgDist / featherRadius);
                const smoothed = Math.pow(featherFactor, 0.7);
                finalMask[i] = Math.round(255 * (1 - smoothed));
            } else {
                finalMask[i] = 255; // Background
            }
            
            operations += 5;
        }

        const processingTime = Date.now() - startTime;
        
        console.log(`Worker ${workerId}: Completed ${operations.toLocaleString()} operations in ${processingTime}ms`);

        return {
            mask: Array.from(finalMask),
            operations,
            pixelsProcessed: totalPixels,
            width,
            height,
            processingTime,
            workerId
        };

    } catch (error) {
        console.error(`Worker ${workerId} failed:`, error);
        throw error;
    }
}

// Execute the processing
extremeBackgroundProcessing()
    .then(result => {
        parentPort.postMessage(result);
    })
    .catch(error => {
        console.error(`Worker error:`, error);
        parentPort.postMessage({ error: error.message });
    });