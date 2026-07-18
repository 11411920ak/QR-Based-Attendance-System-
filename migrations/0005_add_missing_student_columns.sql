-- Migration 0004 assumed branch/section/gender/year existed but they were never created.
-- This migration adds the missing columns to the students table.
ALTER TABLE students ADD COLUMN branch TEXT;
ALTER TABLE students ADD COLUMN section TEXT;
ALTER TABLE students ADD COLUMN gender TEXT;
ALTER TABLE students ADD COLUMN year TEXT;
