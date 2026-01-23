-- Fix for test database: Add missing last_message_at column
-- Connect to your test_neondb database and run this:

ALTER TABLE test_neondb.obeeomaapp_chatsession 
ADD COLUMN last_message_at TIMESTAMP NULL;

-- Verify the column was added:
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'obeeomaapp_chatsession' 
  AND table_schema = 'public'
ORDER BY ordinal_position;
