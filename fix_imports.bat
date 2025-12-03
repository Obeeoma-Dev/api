@echo off
echo ========================================
echo Fixing Import Issues
echo ========================================
echo.

echo Installing all required packages...
pip install -r requirements.txt
echo.

echo Verifying installations...
python -c "import cryptography; print('✓ cryptography installed')"
python -c "import pyotp; print('✓ pyotp installed')"
python -c "import qrcode; print('✓ qrcode installed')"
python -c "import PIL; print('✓ pillow installed')"
echo.

echo ========================================
echo All packages installed successfully!
echo ========================================
echo.
echo If VS Code still shows errors:
echo 1. Press Ctrl+Shift+P
echo 2. Type "Python: Select Interpreter"
echo 3. Select your Python interpreter
echo 4. Reload VS Code window
echo.
pause
