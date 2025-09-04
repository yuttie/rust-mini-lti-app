# LTI 1.3 Testing Guide

This document provides a guide for testing the newly implemented LTI 1.3 functionality.

## Manual Testing

### 1. Start the Application

```bash
cargo run
```

### 2. Test LTI 1.3 Login Initiation

The OIDC login initiation endpoint accepts GET requests with the following required parameters:

```bash
curl -v "http://localhost:3000/lti13/login?iss=https://platform.example.com&login_hint=testuser123&target_link_uri=http://localhost:3000/lti13/launch"
```

Expected response:
- HTTP 303 redirect to the platform's authorization endpoint
- Location header contains properly encoded OIDC parameters

### 3. Test LTI 1.3 Launch (requires valid JWT)

For testing the launch endpoint, you would need a valid JWT token from an LTI 1.3 platform. The endpoint expects:

```bash
curl -X POST http://localhost:3000/lti13/launch \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "id_token=<valid_jwt_token>&state=<state_value>"
```

## LTI 1.3 Implementation Details

### Endpoints Added:
- `GET /lti13/login` - OIDC login initiation 
- `POST /lti13/launch` - JWT token verification and launch

### Security Features:
- Nonce-based replay attack prevention
- JWT token structure validation
- Basic claim validation (message type, version)

### Backward Compatibility:
- Original LTI 1.0 endpoint `/lti` remains unchanged
- Both versions can coexist in the same application

## Production Notes

This is a minimal implementation for demonstration purposes. For production use, you should:

1. Enable proper JWT signature verification with platform public keys
2. Implement proper key management and rotation
3. Add comprehensive error handling
4. Implement proper logging and monitoring
5. Add rate limiting and other security measures
6. Validate all claims according to LTI 1.3 specification