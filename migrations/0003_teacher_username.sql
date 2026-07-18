-- Add username field to users table (used for teacher/student login instead of email)
ALTER TABLE users ADD COLUMN username TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Add phone number and gender to teachers profile
ALTER TABLE teachers ADD COLUMN phone TEXT;
ALTER TABLE teachers ADD COLUMN gender TEXT;
