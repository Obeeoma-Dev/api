with open('obeeomaapp/serializers.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove the unused token and temp password generation code
old_code = """        token = token_urlsafe(32)

        # Generate temporary username (email prefix + random digits)
        email_prefix = validated_data['email'].split('@')[0]
        random_suffix = ''.join(secrets.choice(string.digits) for _ in range(4))
        temp_username = f"{email_prefix}{random_suffix}"

        # Generate temporary password (12 characters: letters, digits, special chars)
        temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits + '!@#$%') for _ in range(12))

"""

content = content.replace(old_code, '')

# Also remove the temp_password_plain line
content = content.replace('        # Store plain password temporarily for email (not saved to DB)\n        invitation.temp_password_plain = temp_password\n\n', '')

with open('obeeomaapp/serializers.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Cleaned up serializer!")
