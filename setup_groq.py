#!/usr/bin/env python3
"""
Setup script for Groq API configuration
"""

import os
from pathlib import Path

def setup_groq_api():
    """Setup Groq API key in environment"""
    
    print("🤖 Groq AI API Setup")
    print("=" * 50)
    
    # Check if .env file exists
    env_file = Path(".env")
    if not env_file.exists():
        print("❌ No .env file found. Creating one...")
        with open(env_file, "w") as f:
            f.write("# Django Settings\n")
            f.write("DEBUG=True\n")
            f.write("SECRET_KEY=your-secret-key-here\n")
            f.write("ALLOWED_HOSTS=localhost,127.0.0.1,64.225.122.101\n\n")
            f.write("# Database\n")
            f.write("DATABASE_URL=sqlite:///db.sqlite3\n\n")
            f.write("# Groq AI API\n")
            f.write("GROQ_API_KEY=\n\n")
            f.write("# JWT Settings\n")
            f.write("JWT_SECRET_KEY=your-jwt-secret-key-here\n")
        print("✅ Created .env file")
    
    # Read current .env
    with open(env_file, "r") as f:
        env_content = f.read()
    
    # Check if GROQ_API_KEY is set
    if "GROQ_API_KEY=" in env_content and not env_content.split("GROQ_API_KEY=")[1].split("\n")[0].strip():
        print("\n🔑 Groq API Key Setup")
        print("-" * 30)
        print("To get your Groq API key:")
        print("1. Go to https://console.groq.com/")
        print("2. Sign up/login")
        print("3. Go to API Keys section")
        print("4. Create a new API key")
        print("5. Copy the key")
        print("\nThen add it to your .env file:")
        print("GROQ_API_KEY=your-actual-api-key-here")
        print("\n⚠️  Without the API key, the chat feature will not work!")
        return False
    else:
        print("✅ Groq API key is configured")
        return True

def test_groq_connection():
    """Test Groq API connection"""
    try:
        from groq import Groq
        
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            print("❌ GROQ_API_KEY not found in environment")
            return False
            
        client = Groq(api_key=api_key)
        
        # Test with a simple message
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": "Hello"}],
            model="llama-3.3-70b-versatile",
            max_tokens=10
        )
        
        print("✅ Groq API connection successful!")
        print(f"📝 Test response: {response.choices[0].message.content}")
        return True
        
    except Exception as e:
        print(f"❌ Groq API connection failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("🚀 Setting up Groq AI for your chat application...")
    
    # Setup API key
    if setup_groq_api():
        # Test connection
        test_groq_connection()
    
    print("\n📚 Next steps:")
    print("1. Get your Groq API key from https://console.groq.com/")
    print("2. Add it to your .env file")
    print("3. Restart your Django server")
    print("4. Test the chat feature in your app")
