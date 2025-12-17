import uuid
from django.core.cache import cache

def create_mfa_settings_token(user_id):
    token = str(uuid.uuid4())
    cache.set(f"mfa_settings_token:{token}", user_id, timeout=300)  # 5 mins
    return token

def verify_mfa_settings_token(token):
    return cache.get(f"mfa_settings_token:{token}")
