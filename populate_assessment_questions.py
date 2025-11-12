#!/usr/bin/env python
"""
Script to populate PHQ-9 and GAD-7 assessment questions
Run: python manage.py shell < populate_assessment_questions.py
"""
import os
import sys
import django

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from obeeomaapp.models import AssessmentQuestion

print("=" * 60)
print("Populating Assessment Questions")
print("=" * 60)
print()

# PHQ-9 Questions
phq9_questions = [
    "Little interest or pleasure in doing things.",
    "Feeling down, depressed, or hopeless.",
    "Trouble falling or staying asleep, or sleeping too much.",
    "Feeling tired or having little energy.",
    "Poor appetite or overeating.",
    "Feeling bad about yourself - or that you are a failure or have let yourself or your family down.",
    "Trouble concentrating on things, such as reading the newspaper or watching television.",
    "Moving or speaking so slowly that other people could have noticed. Or the opposite - being so fidgety or restless that you have been moving around a lot more than usual.",
    "Thoughts that you would be better off dead, or of hurting yourself in some way."
]

print("Creating PHQ-9 questions...")
for i, question_text in enumerate(phq9_questions, 1):
    question, created = AssessmentQuestion.objects.update_or_create(
        assessment_type='PHQ-9',
        question_number=i,
        defaults={'question_text': question_text, 'is_active': True}
    )
    if created:
        print(f"  ✓ PHQ-9 Q{i}: {question_text[:50]}...")
    else:
        print(f"  ℹ️  PHQ-9 Q{i}: Already exists")

print()

# GAD-7 Questions
gad7_questions = [
    "Feeling nervous, anxious, or on edge.",
    "Not being able to stop or control worrying.",
    "Worrying too much about different things.",
    "Trouble relaxing.",
    "Being so restless that it's hard to sit still.",
    "Becoming easily annoyed or irritable.",
    "Feeling afraid as if something awful might happen."
]

print("Creating GAD-7 questions...")
for i, question_text in enumerate(gad7_questions, 1):
    question, created = AssessmentQuestion.objects.update_or_create(
        assessment_type='GAD-7',
        question_number=i,
        defaults={'question_text': question_text, 'is_active': True}
    )
    if created:
        print(f"  ✓ GAD-7 Q{i}: {question_text[:50]}...")
    else:
        print(f"  ℹ️  GAD-7 Q{i}: Already exists")

print()
print("=" * 60)
print("✓ Assessment questions populated successfully!")
print("=" * 60)
print()
print("Summary:")
print(f"  PHQ-9 questions: {AssessmentQuestion.objects.filter(assessment_type='PHQ-9').count()}")
print(f"  GAD-7 questions: {AssessmentQuestion.objects.filter(assessment_type='GAD-7').count()}")
print()
print("Next steps:")
print("1. Run migrations: python manage.py makemigrations && python manage.py migrate")
print("2. Test endpoints:")
print("   - GET /api/assessments/questions/by_type/?type=PHQ-9")
print("   - GET /api/assessments/questions/by_type/?type=GAD-7")
print("   - POST /api/assessments/responses/")
print("3. Start server: python manage.py runserver")
print("4. Visit: http://localhost:8000/api/docs/")
