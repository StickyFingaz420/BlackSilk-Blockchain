#!/bin/bash

echo "Testing POST request to faucet..."

# Test with curl
curl -v -m 10 -X POST http://localhost:3003/api/request \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"address": "BLKTestAddress123456789"}' \
  2>&1

echo -e "\n\nDone."
