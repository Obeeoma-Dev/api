@echo off
echo ========================================
echo Setting up Meditation & Mood Tracking App
echo ========================================
echo.

echo Step 1: Installing dependencies...
pip install qrcode pyotp pillow
echo.

echo Step 2: Creating migrations...
python manage.py makemigrations
echo.

echo Step 3: Running migrations...
python manage.py migrate
echo.

echo Step 4: Would you like to populate sample data? (Y/N)
set /p populate="Enter choice: "

if /i "%populate%"=="Y" (
    echo.
    echo Populating meditation data...
    python manage.py shell < setup_meditation_data.py
    echo.
    echo Populating mood tracking data...
    python manage.py shell < setup_mood_tracking_data.py
    echo.
)

echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Run the development server: python manage.py runserver
echo 2. Access API docs: http://localhost:8000/api/docs/
echo 3. Test endpoints using the API_QUICK_REFERENCE.md
echo.
pause
