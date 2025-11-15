#!/usr/bin/env python
"""
Populate Assessment Questions for PHQ-9 and GAD-7
Run this after migrations to add the standard mental health assessment questions.
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from obeeomaapp.models import AssessmentQuestion

def populate_phq9():
    """Create PHQ-9 (Depression) questions"""
    print("Creating PHQ-9 questions...")
    
    phq9_questions = [
        "Little interest or pleasure in doing things",
        "Feeling down, depressed, or hopeless",
        "Trouble falling or staying asleep, or sleeping too much",
        "Feeling tired or having little energy",
        "Poor appetite or overeating",
        "Feeling bad about yourself - or that you are a failure or have let yourself or your family down",
        "Trouble concentrating on things, such as reading the newspaper or watching television",
        "Moving or speaking so slowly that other people could have noticed. Or the opposite - being so fidgety or restless that you have been moving around a lot more than usual",
        "Thoughts that you would be better off dead, or of hurting yourself in some way"
    ]
    
    for i, question_text in enumerate(phq9_questions, 1):
        question, created = AssessmentQuestion.objects.get_or_create(
            assessment_type='PHQ-9',
            question_number=i,
            defaults={
                'question_text': question_text,
                'is_active': True
            }
        )
        if created:
            print(f"  ✓ Created PHQ-9 Q{i}: {question_text[:50]}...")
        else:
            print(f"  - PHQ-9 Q{i} already exists")
    
    print(f"✅ PHQ-9 complete: {len(phq9_questions)} questions\n")


def populate_gad7():
    """Create GAD-7 (Anxiety) questions"""
    print("Creating GAD-7 questions...")
    
    gad7_questions = [
        "Feeling nervous, anxious, or on edge",
        "Not being able to stop or control worrying",
        "Worrying too much about different things",
        "Trouble relaxing",
        "Being so restless that it's hard to sit still",
        "Becoming easily annoyed or irritable",
        "Feeling afraid as if something awful might happen"
    ]
    
    for i, question_text in enumerate(gad7_questions, 1):
        question, created = AssessmentQuestion.objects.get_or_create(
            assessment_type='GAD-7',
            question_number=i,
            defaults={
                'question_text': question_text,
                'is_active': True
            }
        )
        if created:
            print(f"  ✓ Created GAD-7 Q{i}: {question_text[:50]}...")
        else:
            print(f"  - GAD-7 Q{i} already exists")
    
    print(f"✅ GAD-7 complete: {len(gad7_questions)} questions\n")


def main():
    print("=" * 60)
    print("POPULATING ASSESSMENT QUESTIONS")
    print("=" * 60)
    print()
    
    try:
        populate_phq9()
        populate_gad7()
        
        # Summary
        total_phq9 = AssessmentQuestion.objects.filter(assessment_type='PHQ-9').count()
        total_gad7 = AssessmentQuestion.objects.filter(assessment_type='GAD-7').count()
        
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"PHQ-9 Questions: {total_phq9}")
        print(f"GAD-7 Questions: {total_gad7}")
        print(f"Total Questions: {total_phq9 + total_gad7}")
        print()
        print("✅ Assessment questions are ready!")
        print()
        print("Next steps:")
        print("1. Create a superuser: python manage.py createsuperuser")
        print("2. Run the server: python manage.py runserver")
        print("3. Test the API endpoints")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        print("\nMake sure you've run migrations first:")
        print("  python manage.py migrate")


if __name__ == '__main__':
    main()
