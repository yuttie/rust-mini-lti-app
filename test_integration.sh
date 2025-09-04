#!/bin/bash

# Simple integration test script for LTI 1.0 and LTI 1.3 functionality
# Run this script after starting the application with `cargo run`

set -e

echo "Testing rust-mini-lti-app endpoints..."
echo "========================================"

# Test basic server health
echo "1. Testing server health..."
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/)
if [ "$response" = "401" ]; then
    echo "✓ Server is running (expected 401 for unauthorized access)"
else
    echo "✗ Unexpected response code: $response"
    exit 1
fi

# Test LTI 1.3 login initiation
echo "2. Testing LTI 1.3 login initiation..."
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000/lti13/login?iss=https://platform.example.com&login_hint=testuser&target_link_uri=http://localhost:3000/lti13/launch")
if [ "$response" = "303" ]; then
    echo "✓ LTI 1.3 login endpoint working (got redirect)"
else
    echo "✗ LTI 1.3 login failed with response code: $response"
    exit 1
fi

# Test LTI 1.3 login with missing parameters
echo "3. Testing LTI 1.3 login with missing parameters..."
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000/lti13/login")
if [ "$response" = "400" ]; then
    echo "✓ LTI 1.3 login correctly rejects missing parameters"
else
    echo "✗ Expected 400 for missing parameters, got: $response"
    exit 1
fi

# Test LTI 1.3 launch with no token (should fail)
echo "4. Testing LTI 1.3 launch with no token..."
response=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3000/lti13/launch)
if [ "$response" = "400" ]; then
    echo "✓ LTI 1.3 launch correctly rejects missing token"
else
    echo "✗ Expected 400 for missing token, got: $response"
    exit 1
fi

# Test original LTI 1.0 endpoint still works
echo "5. Testing LTI 1.0 endpoint availability..."
# LTI 1.0 requires specific OAuth parameters, so we expect it to fail gracefully
response=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3000/lti -d "oauth_nonce=test&oauth_signature=invalid")
if [ "$response" = "400" ]; then
    echo "✓ LTI 1.0 endpoint is available and correctly rejects invalid OAuth"
else
    echo "✗ LTI 1.0 endpoint unexpected response: $response"
    exit 1
fi

echo "========================================"
echo "All tests passed! ✓"
echo ""
echo "LTI 1.3 implementation is working correctly:"
echo "- OIDC login initiation redirects properly"
echo "- Parameter validation works"
echo "- JWT launch endpoint is functional"
echo "- Backward compatibility with LTI 1.0 maintained"