// scripts/enhanced-loadtest.js - Complete multi-threaded CPU load testing with 3 concurrent workers

const endpoint = process.argv[2];
const auth = process.argv[3] || '';
const concurrentRequests = Number(process.argv[4] || 3); // Default to 3 concurrent requests

if (!endpoint) {
  console.error('Usage: node scripts/enhanced-loadtest.js <endpoint> "Bearer <token>" [concurrent_requests]');
  console.error('');
  console.error('Examples:');
  console.error(' Enhanced 5-min test: node scripts/enhanced-loadtest.js http://HOST:3000/images/stress/5 "Bearer <token>" 3');
  console.error(' Extreme load test: node scripts/enhanced-loadtest.js http://HOST:3000/images/stress-extreme/5 "Bearer <token>" 2');
  console.error(' Quick burst test: node scripts/enhanced-loadtest.js http://HOST:3000/images/quickstress/50000000 "Bearer <token>" 10');
  process.exit(1);
}

console.log(`=== ENHANCED LOAD TESTING FOR CAB432 ASSIGNMENT ===`);
console.log(`Target Endpoint: ${endpoint}`);
console.log(`Concurrent Requests: ${concurrentRequests}`);
console.log(`Assignment Goal: >80% CPU utilization for 5 minutes`);
console.log(`Each request spawns 3 worker threads for maximum CPU load\n`);

let completed = 0;
let errors = 0;
let totalOperations = 0;
let totalWorkers = 0;
const start = Date.now();
const requestTimes = [];
const requestResults = [];

function makeRequest(requestId) {
  const requestStart = Date.now();
  console.log(`[${new Date().toISOString()}] Launching multi-threaded stress test ${requestId}...`);
  
  return fetch(endpoint, {
    headers: { Authorization: auth },
    timeout: 900000 // 15 minute timeout for sustained tests
  })
  .then(r => r.json())
  .then(data => {
    const requestTime = Date.now() - requestStart;
    requestTimes.push(requestTime);
    requestResults.push(data);
    completed++;
    
    console.log(`\n=== STRESS TEST ${requestId} COMPLETED ===`);
    console.log(`Request Duration: ${Math.round(requestTime / 1000)}s`);
    
    if (data.actualDurationMinutes) {
      console.log(`CPU Test Duration: ${data.actualDurationMinutes} minutes`);
      console.log(`Workers Used: ${data.concurrentWorkers || data.workersUsed || 'N/A'}`);
      console.log(`System Cores: ${data.systemCores || 'N/A'}`);
      console.log(`Total Iterations: ${(data.totalIterations || 0).toLocaleString()}`);
      console.log(`Total Operations: ${(data.totalOperations || 0).toLocaleString()}`);
      console.log(`Estimated CPU: ${data.estimatedCpuUsage || data.cpuUsagePercent + '%' || 'N/A'}`);
      console.log(`Assignment Status: ${data.assignmentRequirement || 'Check manually'}`);
      
      if (data.totalOperations) {
        totalOperations += data.totalOperations;
      }
      if (data.concurrentWorkers) {
        totalWorkers += data.concurrentWorkers;
      } else if (data.workersUsed) {
        totalWorkers += data.workersUsed;
      }
    }
    
    return data;
  })
  .catch(e => {
    const requestTime = Date.now() - requestStart;
    errors++;
    console.error(`\n=== STRESS TEST ${requestId} FAILED ===`);
    console.error(`Duration: ${Math.round(requestTime / 1000)}s`);
    console.error(`Error: ${e.message}`);
  });
}

// Enhanced load testing with multiple concurrent stress tests
if (endpoint.includes('/stress')) {
  console.log('RUNNING ENHANCED MULTI-THREADED LOAD TEST');
  console.log('Each request spawns 3 worker threads for maximum CPU utilization');
  console.log('Perfect for demonstrating >80% CPU load required by assignment\n');
  
  // Start multiple concurrent stress test requests with staggered timing
  for (let i = 0; i < concurrentRequests; i++) {
    setTimeout(() => {
      console.log(`Launching enhanced stress test ${i + 1}/${concurrentRequests}...`);
      makeRequest(i + 1);
    }, i * 3000); // 3 second stagger between launches for better load distribution
  }
  
  // Progress monitoring for sustained tests
  const progressInterval = setInterval(() => {
    const elapsed = Math.round((Date.now() - start) / 1000);
    const completionRate = Math.round((completed / concurrentRequests) * 100);
    
    console.log(`\n=== ENHANCED LOAD TEST PROGRESS ===`);
    console.log(`Test Time Elapsed: ${Math.floor(elapsed / 60)}m ${elapsed % 60}s`);
    console.log(`Requests Completed: ${completed}/${concurrentRequests} (${completionRate}%)`);
    console.log(`Requests Failed: ${errors}`);
    console.log(`Total CPU Operations: ${totalOperations.toLocaleString()}`);
    console.log(`Total Worker Threads: ${totalWorkers}`);
    console.log(`*** Monitor AWS CloudWatch CPU graph now! ***`);
    
    if (completed + errors >= concurrentRequests) {
      clearInterval(progressInterval);
      
      // Final comprehensive statistics
      const totalTestTime = Date.now() - start;
      const avgRequestTime = requestTimes.length > 0 ?
        Math.round(requestTimes.reduce((a, b) => a + b, 0) / requestTimes.length) : 0;
      
      console.log(`\n==================================================`);
      console.log(`     ENHANCED LOAD TEST COMPLETE - FINAL RESULTS`);
      console.log(`==================================================`);
      console.log(`Total Test Duration: ${Math.floor(totalTestTime / 60000)}m ${Math.round((totalTestTime % 60000) / 1000)}s`);
      console.log(`Concurrent Stress Requests: ${concurrentRequests}`);
      console.log(`Successful Requests: ${completed}/${concurrentRequests}`);
      console.log(`Failed Requests: ${errors}/${concurrentRequests}`);
      console.log(`Average Request Duration: ${Math.floor(avgRequestTime / 60000)}m ${Math.round((avgRequestTime % 60000) / 1000)}s`);
      console.log(`Total CPU Operations: ${totalOperations.toLocaleString()}`);
      console.log(`Total Worker Threads Used: ${totalWorkers}`);
      console.log(`\n*** ASSIGNMENT VERIFICATION ***`);
      console.log(`✓ Check AWS CloudWatch CPU Utilization Graph`);
      console.log(`✓ Target: Sustained >80% CPU for 5+ minutes`);
      console.log(`✓ Each request used 3 concurrent worker threads`);
      console.log(`✓ Multiple requests = even higher CPU load`);
      console.log(`\nThis enhanced system should easily meet assignment requirements!`);
    }
  }, 25000); // Progress update every 25 seconds

} else {
  // Quick burst testing for development/debugging
  console.log('RUNNING ENHANCED BURST TEST\n');
  
  const promises = [];
  for (let i = 0; i < concurrentRequests; i++) {
    promises.push(makeRequest(i + 1));
  }
  
  Promise.all(promises).then(() => {
    const totalTime = Date.now() - start;
    const avgTime = requestTimes.length > 0 ?
      Math.round(requestTimes.reduce((a, b) => a + b, 0) / requestTimes.length) : 0;
    
    console.log(`\n=== ENHANCED BURST TEST COMPLETE ===`);
    console.log(`${concurrentRequests} requests completed in ${totalTime}ms`);
    console.log(`Average request time: ${avgTime}ms`);
    console.log(`Requests per second: ${Math.round(concurrentRequests / (totalTime / 1000) * 100) / 100}`);
    console.log(`Total operations: ${totalOperations.toLocaleString()}`);
  });
}

// Graceful shutdown handling
process.on('SIGINT', () => {
  console.log('\n\n=== STOPPING ENHANCED LOAD TEST ===');
  const elapsed = Math.round((Date.now() - start) / 1000);
  console.log(`Test Duration: ${Math.floor(elapsed / 60)}m ${elapsed % 60}s`);
  console.log(`Completed Requests: ${completed}`);
  console.log(`Failed Requests: ${errors}`);
  console.log(`Total CPU Operations: ${totalOperations.toLocaleString()}`);
  console.log(`Check AWS CloudWatch for CPU utilization results!`);
  process.exit(0);
});