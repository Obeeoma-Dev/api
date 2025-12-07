-- SQL to remove old invitation fields from the database
-- Run this directly on your Neon database if migration fails

ALTER TABLE obeeomaapp_employeeinvitation DROP COLUMN IF EXISTS token;
ALTER TABLE obeeomaapp_employeeinvitation DROP COLUMN IF EXISTS expires_at;
ALTER TABLE obeeomaapp_employeeinvitation DROP COLUMN IF EXISTS temporary_username;
ALTER TABLE obeeomaapp_employeeinvitation DROP COLUMN IF EXISTS temporary_password;
ALTER TABLE obeeomaapp_employeeinvitation DROP COLUMN IF EXISTS credentials_used;

-- Verify the table structure
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'obeeomaapp_employeeinvitation'
ORDER BY ordinal_position;
