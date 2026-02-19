#!/usr/bin/env python
import os
import django

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

print("=== Environment Variables Check ===")
print(f"GROQ_API_KEY: {'✅ SET' if os.environ.get('GROQ_API_KEY') else '❌ MISSING'}")
print(f"API Key starts with 'gsk_': {'✅ YES' if os.environ.get('GROQ_API_KEY', '').startswith('gsk_') else '❌ NO'}")
print(f"API Key length: {len(os.environ.get('GROQ_API_KEY', ''))}")

# Test Groq service
try:
    from obeeomaapp.Services.groq_service import GroqService
    groq = GroqService()
    print("✅ GroqService initialized successfully")
    
    # Test a simple call
    response = groq.get_response("Hello", [])
    print(f"✅ Groq API call successful: {response[:50]}...")
except Exception as e:
    print(f"❌ Groq API error: {str(e)}")
