// src/utils/enhanced-cpu-worker.js - Complete multi-layered CPU burning worker
const { parentPort, workerData } = require('worker_threads');

function enhancedCPUBurn(durationMs, workerId, intensity) {
    const start = Date.now();
    let iterations = 0;
    let totalOperations = 0;
    
    console.log(`Worker ${workerId}: Starting ${intensity} intensity CPU burn for ${durationMs}ms`);
    
    // Multi-layered CPU burning with different computational patterns
    while (Date.now() - start < durationMs) {
        // Layer 1: Mathematical computations
        for (let i = 0; i < 1000000; i++) {
            const x = Math.random() * 1000;
            Math.sqrt(x * Math.PI);
            Math.pow(x, 2.7);
            Math.sin(x) + Math.cos(x) + Math.tan(x);
            Math.log(Math.abs(x) + 1);
            Math.exp(x / 1000);
            totalOperations += 6;
        }
        
        // Layer 2: Complex trigonometric operations
        for (let j = 0; j < 500000; j++) {
            const angle = Math.random() * Math.PI * 2;
            const radius = Math.random() * 100;
            Math.atan2(Math.sin(angle) * radius, Math.cos(angle) * radius);
            Math.asin(Math.random());
            Math.acos(Math.random());
            Math.sinh(angle / 10);
            Math.cosh(angle / 10);
            totalOperations += 5;
        }
        
        // Layer 3: Array and string operations for memory pressure
        for (let k = 0; k < 100000; k++) {
            const arr = Array(100).fill(0).map(() => Math.random());
            const sorted = arr.sort((a, b) => a - b);
            const filtered = sorted.filter(x => x > 0.5);
            const mapped = filtered.map(x => x * Math.PI);
            const reduced = mapped.reduce((a, b) => a + b, 0);
            totalOperations += 5;
        }
        
        // Layer 4: String manipulation for additional CPU load
        for (let l = 0; l < 50000; l++) {
            let str = Math.random().toString(36).repeat(10);
            str = str.toUpperCase().toLowerCase();
            str = str.split('').reverse().join('');
            str = str.replace(/[0-9]/g, 'x');
            totalOperations += 4;
        }
        
        // Layer 5: Intensive mathematical matrix operations
        for (let m = 0; m < 10000; m++) {
            const matrix = Array(50).fill(0).map(() => Array(50).fill(0).map(() => Math.random()));
            
            // Matrix operations
            for (let row = 0; row < 50; row++) {
                for (let col = 0; col < 50; col++) {
                    matrix[row][col] = Math.sqrt(matrix[row][col]) + Math.pow(matrix[row][col], 1.3);
                    totalOperations++;
                }
            }
            
            // Additional intensive calculations
            const determinant = matrix[0].reduce((sum, val, idx) => sum + val * Math.random(), 0);
            const eigenvalue = Math.sqrt(Math.abs(determinant)) + Math.log(Math.abs(determinant) + 1);
            totalOperations += 2;
        }
        
        iterations++;
        
        // Occasional progress log (every 50 iterations for more feedback)
        if (iterations % 50 === 0) {
            const elapsed = Date.now() - start;
            const progress = Math.round((elapsed / durationMs) * 100);
            console.log(`Worker ${workerId}: ${progress}% complete, ${iterations} iterations, ${totalOperations.toLocaleString()} operations`);
        }
    }
    
    const actualDuration = Date.now() - start;
    const result = {
        workerId,
        iterations,
        totalOperations,
        actualDuration,
        operationsPerSecond: Math.round(totalOperations / (actualDuration / 1000)),
        intensity
    };
    
    console.log(`Worker ${workerId}: COMPLETED - ${iterations} iterations, ${totalOperations.toLocaleString()} operations in ${actualDuration}ms`);
    return result;
}

// Execute the CPU burn and send result back to main thread
const result = enhancedCPUBurn(workerData.duration, workerData.workerId, workerData.intensity);
parentPort.postMessage(result);