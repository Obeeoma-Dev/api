with open('obeeomaapp/serializers.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_code = """class EmployeeOnboardingSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)
    avatar = serializers.ImageField(required=True)

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already taken.")
        return value

    def validate(self, attrs):
        if attrs["password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return attrs

    def update(self, user, validated_data):
        user.avatar = validated_data["avatar"]
        user.onboarding_completed = True
        user.is_first_time = False   # this marks onboarding done
        user.save()
        return user"""

new_code = """class EmployeeOnboardingSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)
    avatar = serializers.ImageField(required=True)
    
    # Assessment fields - all required for onboarding
    gad7_scores = serializers.ListField(
        child=serializers.IntegerField(min_value=0, max_value=3),
        required=True,
        min_length=7,
        max_length=7,
        help_text="GAD-7 anxiety assessment: 7 scores (0-3 each)"
    )
    phq9_scores = serializers.ListField(
        child=serializers.IntegerField(min_value=0, max_value=3),
        required=True,
        min_length=9,
        max_length=9,
        help_text="PHQ-9 depression assessment: 9 scores (0-3 each)"
    )
    pss10_scores = serializers.ListField(
        child=serializers.IntegerField(min_value=0, max_value=4),
        required=True,
        min_length=10,
        max_length=10,
        help_text="PSS-10 stress assessment: 10 scores (0-4 each)"
    )

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already taken.")
        return value

    def validate(self, attrs):
        if attrs["password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return attrs

    def update(self, user, validated_data):
        # Update user profile
        user.username = validated_data["username"]
        user.set_password(validated_data["password"])
        user.avatar = validated_data["avatar"]
        user.onboarding_completed = True
        user.is_first_time = False
        user.save()
        
        # Create GAD-7 assessment
        gad7_total = sum(validated_data["gad7_scores"])
        MentalHealthAssessment.objects.create(
            user=user,
            assessment_type='GAD-7',
            gad7_scores=validated_data["gad7_scores"],
            gad7_total=gad7_total
        )
        
        # Create PHQ-9 assessment
        phq9_total = sum(validated_data["phq9_scores"])
        MentalHealthAssessment.objects.create(
            user=user,
            assessment_type='PHQ-9',
            phq9_scores=validated_data["phq9_scores"],
            phq9_total=phq9_total
        )
        
        # Create PSS-10 assessment
        pss10_total = sum(validated_data["pss10_scores"])
        # Determine stress category
        if pss10_total <= 13:
            category = "Low stress"
        elif pss10_total <= 26:
            category = "Moderate stress"
        else:
            category = "High stress"
            
        PSS10Assessment.objects.create(
            user=user,
            score=pss10_total,
            category=category
        )
        
        return user"""

content = content.replace(old_code, new_code)

with open('obeeomaapp/serializers.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Updated EmployeeOnboardingSerializer with assessments!")
