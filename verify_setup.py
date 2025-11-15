#!/usr/bin/env python
"""
Verify that everything is set up correctly
"""
import os
import sys

print("=" * 60)
print("SETUP VERIFICATION")
print("=" * 60)
print()

# Check 1: Environment variables
print("1. Checking environment variables...")
# Try to load from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

openai_key = os.getenv('OPENAI_API_KEY')
if openai_key and openai_key.startswith('sk-'):
    print("   ✅ OPENAI_API_KEY is set")
else:
    print("   ⚠️  OPENAI_API_KEY not detected in environment")
    print("   → Check .env file or Django settings")

# Check 2: OpenAI package
print("\n2. Checking OpenAI package...")
try:
    import openai
    print("   ✅ openai package installed")
except ImportError:
    print("   ❌ openai package not installed")
    print("   → Run: pip install openai")

# Check 3: Django setup
print("\n3. Checking Django...")
try:
    import django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
    django.setup()
    print("   ✅ Django configured")
except Exception as e:
    print(f"   ❌ Django error: {e}")

# Check 4: Database tables
print("\n4. Checking database tables...")
try:
    from obeeomaapp.models import Employee, AssessmentQuestion, AssessmentResponse
    
    # Try to query (will fail if tables don't exist)
    Employee.objects.count()
    print("   ✅ Employee table exists")
    
    AssessmentQuestion.objects.count()
    print("   ✅ AssessmentQuestion table exists")
    
    AssessmentResponse.objects.count()
    print("   ✅ AssessmentResponse table exists")
    
except Exception as e:
    print(f"   ❌ Database tables missing: {e}")
    print("   → Run: python manage.py migrate")

# Check 5: Assessment questions
print("\n5. Checking assessment questions...")
try:
    from obeeomaapp.models import AssessmentQuestion
    phq9_count = AssessmentQuestion.objects.filter(assessment_type='PHQ-9').count()
    gad7_count = AssessmentQuestion.objects.filter(assessment_type='GAD-7').count()
    
    if phq9_count == 9:
        print(f"   ✅ PHQ-9 questions: {phq9_count}/9")
    else:
        print(f"   ⚠️  PHQ-9 questions: {phq9_count}/9 (should be 9)")
        print("   → Run: python populate_assessments.py")
    
    if gad7_count == 7:
        print(f"   ✅ GAD-7 questions: {gad7_count}/7")
    else:
        print(f"   ⚠️  GAD-7 questions: {gad7_count}/7 (should be 7)")
        print("   → Run: python populate_assessments.py")
        
except Exception as e:
    print(f"   ❌ Cannot check questions: {e}")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print("\nIf all checks passed ✅, you're ready to:")
print("1. Run server: python manage.py runserver")
print("2. Test endpoints with Postman or mobile/web app")
print("\nIf any checks failed ❌, follow the instructions above.")
