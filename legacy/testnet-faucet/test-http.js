#!/usr/bin/env node

const http = require('http');

const data = JSON.stringify({
  address: 'BLKTestResponseCheck456789'
});

const options = {
  hostname: 'localhost',
  port: 3003,
  path: '/api/request',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': data.length
  },
  timeout: 5000
};

const req = http.request(options, (res) => {
  console.log(`Status: ${res.statusCode}`);
  console.log(`Headers: ${JSON.stringify(res.headers)}`);
  
  let body = '';
  res.on('data', (chunk) => {
    body += chunk;
  });
  
  res.on('end', () => {
    console.log('Response body:', body);
  });
});

req.on('timeout', () => {
  console.log('Request timeout');
  req.destroy();
});

req.on('error', (e) => {
  console.error(`Request error: ${e.message}`);
});

req.write(data);
req.end();
