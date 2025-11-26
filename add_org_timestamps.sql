-- Add created_at and updated_at columns to Organization table
ALTER TABLE obeeomaapp_organization 
ADD COLUMN created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL;

ALTER TABLE obeeomaapp_organization 
ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL;
