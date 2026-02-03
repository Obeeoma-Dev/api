#!/bin/bash
# Debug script to check Company Mood data issues

echo "🔍 Debugging Company Mood Feature..."
echo ""

# 1. Check if MoodTracking table exists and has data
echo "1️⃣ Checking MoodTracking table..."
docker-compose exec -T backend python manage.py dbshell << 'EOF'
SELECT COUNT(*) as mood_entries FROM obeeomaapp_moodtracking;
SELECT mood, COUNT(*) as count FROM obeeomaapp_moodtracking GROUP BY mood;
SELECT * FROM obeeomaapp_moodtracking ORDER BY checked_in_at DESC LIMIT 5;
\q
EOF

echo ""

# 2. Check if CompanyMood table exists and has data
echo "2️⃣ Checking CompanyMood table..."
docker-compose exec -T backend python manage.py dbshell << 'EOF'
SELECT COUNT(*) as company_mood_entries FROM obeeomaapp_companymood;
SELECT * FROM obeeomaapp_companymood ORDER BY created_at DESC LIMIT 5;
\q
EOF

echo ""

# 3. Check URL routing
echo "3️⃣ Checking URL routing..."
docker-compose exec backend python manage.py show_urls | grep -i "mood"

echo ""

# 4. Test the employer summary endpoint
echo "4️⃣ Testing employer mood summary endpoint..."
curl -X GET http://localhost:8000/api/v1/employee/mood-tracking/employer-summary/ \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n"

echo ""

# 5. Test company mood endpoint
echo "5️⃣ Testing company mood endpoint..."
curl -X GET http://localhost:8000/api/v1/company-mood/ \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n"

echo ""
echo "✅ Debug complete!"
