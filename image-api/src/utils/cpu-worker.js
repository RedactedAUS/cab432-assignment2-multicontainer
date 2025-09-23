const { parentPort, workerData } = require('worker_threads');

function burnCPU(durationMs) {
    const start = Date.now();
    let iterations = 0;
    
    // Hardcore CPU burning - multiple intensive operations
    while (Date.now() - start < durationMs) {
        // Multiple tight loops with heavy math operations
        for (let i = 0; i < 500000; i++) {
            Math.sqrt(i * Math.random());
            Math.pow(i, 1.5);
            Math.sin(i) + Math.cos(i) + Math.tan(i);
            Math.log(Math.abs(i) + 1);
        }
        iterations++;
        
        // Additional CPU-intensive work
        for (let j = 0; j < 100000; j++) {
            const temp = Math.random() * 1000;
            Math.atan2(temp, j) + Math.exp(temp / 1000);
        }
    }
    
    return { 
        iterations, 
        actualDuration: Date.now() - start,
        workerId: workerData.workerId 
    };
}

const result = burnCPU(workerData.duration);
parentPort.postMessage(result);
