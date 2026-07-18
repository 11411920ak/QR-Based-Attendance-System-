-- Add roll_no column for student login (branch/year/section/gender already added previously)
ALTER TABLE students ADD COLUMN roll_no TEXT;

-- roll_no is the student's login identifier — must be unique
CREATE UNIQUE INDEX IF NOT EXISTS idx_students_roll_no ON students(roll_no);
