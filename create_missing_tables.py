#!/usr/bin/env python
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from django.db import connection

# Create achievement table if it doesn't exist
create_achievement_table = """
CREATE TABLE IF NOT EXISTS obeeomaapp_achievement (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description VARCHAR(500),
    icon VARCHAR(50) NOT NULL,
    category VARCHAR(30) NOT NULL,
    target_count INTEGER,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
"""

# Create userachievement table if it doesn't exist
create_userachievement_table = """
CREATE TABLE IF NOT EXISTS obeeomaapp_userachievement (
    id BIGSERIAL PRIMARY KEY,
    achieved BOOLEAN DEFAULT FALSE,
    achieved_date DATE,
    progress_count INTEGER DEFAULT 0,
    achievement_id INTEGER REFERENCES obeeomaapp_achievement(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES auth_user(id) ON DELETE CASCADE,
    UNIQUE(user_id, achievement_id)
);
"""

with connection.cursor() as cursor:
    try:
        print("Creating achievement table...")
        cursor.execute(create_achievement_table)
        print("Achievement table created successfully")
        
        print("Creating userachievement table...")
        cursor.execute(create_userachievement_table)
        print("Userachievement table created successfully")
        
        print("Tables created successfully!")
    except Exception as e:
        print(f"Error: {e}")
