#!/bin/bash
# Test invitation endpoints on Digital Ocean

echo "🧪 Testing Invitation Endpoints..."
echo ""

# Get your droplet IP or domain
DROPLET_URL="http://localhost:8000"  # Change to your actual domain/IP if needed

echo "📋 Testing endpoints at: $DROPLET_URL"
echo ""

# Test 1: Check if endpoints are registered
echo "1️⃣ Checking API schema for invitation endpoints..."
curl -s "$DROPLET_URL/api/v1/api/schema/" | grep -i "invitation" || echo "❌ Endpoints not found in schema"
echo ""

# Test 2: List invitations (requires auth)
echo "2️⃣ Testing GET /api/v1/auth/invitations/ (List)"
curl -X GET "$DROPLET_URL/api/v1/auth/invitations/" \
  -H "Content-Type: application/json" \
  -w "\nStatus: %{http_code}\n"
echo ""

# Test 3: Check Swagger UI
echo "3️⃣ Checking Swagger documentation..."
curl -s "$DROPLET_URL/api/v1/swagger/" | grep -i "Employee Invitations" && echo "✅ Found in Swagger" || echo "❌ Not in Swagger"
echo ""

# Test 4: Check specific endpoint pattern
echo "4️⃣ Testing endpoint with ID pattern..."
curl -X GET "$DROPLET_URL/api/v1/auth/invitations/1/" \
  -H "Content-Type: application/json" \
  -w "\nStatus: %{http_code}\n"
echo ""

echo "✅ Test complete!"
echo ""
echo "📝 Note: You'll need authentication tokens to actually use these endpoints."
echo "   The important thing is that they return 401 (Unauthorized) not 404 (Not Found)"
