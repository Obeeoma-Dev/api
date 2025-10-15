#!/usr/bin/env python3
"""
Test script for refresh token functionality
"""

import requests
import json

# Configuration
BASE_URL = "http://localhost:8000"

def test_refresh_token():
    """Test the refresh token flow"""
    print("🔄 Testing Refresh Token Endpoint")
    print("=" * 50)
    
    # Step 1: Get access and refresh tokens
    print("📝 Step 1: Getting initial tokens...")
    login_data = {
        "username": "your-username",  # Replace with actual username
        "password": "your-password"   # Replace with actual password
    }
    
    try:
        # First, try to login to get tokens
        login_response = requests.post(
            f"{BASE_URL}/auth/login/",
            json=login_data,
            headers={"Content-Type": "application/json"}
        )
        
        if login_response.status_code == 200:
            tokens = login_response.json()
            refresh_token = tokens.get('refresh')
            access_token = tokens.get('access')
            
            print(f"✅ Login successful!")
            print(f"🔑 Access token: {access_token[:20]}...")
            print(f"🔄 Refresh token: {refresh_token[:20]}...")
            
            # Step 2: Test refresh token endpoint
            print("\n🔄 Step 2: Testing refresh token endpoint...")
            refresh_data = {
                "refresh": refresh_token
            }
            
            refresh_response = requests.post(
                f"{BASE_URL}/auth/token/refresh/",
                json=refresh_data,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"📊 Response status: {refresh_response.status_code}")
            print(f"📄 Response: {refresh_response.text}")
            
            if refresh_response.status_code == 200:
                new_tokens = refresh_response.json()
                print("✅ Refresh token endpoint working!")
                print(f"🔑 New access token: {new_tokens.get('access', 'N/A')[:20]}...")
            else:
                print("❌ Refresh token endpoint failed!")
                print(f"Error: {refresh_response.text}")
                
        else:
            print(f"❌ Login failed: {login_response.status_code}")
            print(f"Response: {login_response.text}")
            print("\n💡 Note: You need to create a user account first or use existing credentials")
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed. Make sure the Django server is running on localhost:8000")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_server_status():
    """Test if the server is running"""
    try:
        response = requests.get(f"{BASE_URL}/")
        if response.status_code == 200:
            print("✅ Server is running")
            return True
        else:
            print(f"❌ Server responded with status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Server is not running. Start it with: python manage.py runserver")
        return False

if __name__ == "__main__":
    print("🚀 Refresh Token Test Script")
    print("=" * 50)
    
    # Check server status
    if test_server_status():
        print()
        test_refresh_token()
    else:
        print("\n💡 To start the server:")
        print("   1. Activate virtual environment: venv\\Scripts\\activate")
        print("   2. Run server: python manage.py runserver")
        print("   3. Run this test again")
    
    print("\n📋 What was fixed:")
    print("   ✅ Removed duplicate refresh token endpoints")
    print("   ✅ Added proper JWT configuration")
    print("   ✅ Fixed URL routing conflicts")
    print("   ✅ Added token rotation and blacklisting")
