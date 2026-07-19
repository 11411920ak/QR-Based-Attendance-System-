-- Migration 0006: Face Verification
-- Adds face descriptor storage to students and audit flag to attendance.
-- face_descriptor: JSON-stringified Float32Array of 128 floats (face-api.js format).
-- verified_by_face: 1 = server confirmed face matched before attendance was recorded.

-- Add face descriptor column to students table
ALTER TABLE students ADD COLUMN face_descriptor TEXT;

-- Track when the descriptor was last enrolled (rate-limiting re-enrollment)
ALTER TABLE students ADD COLUMN face_enrolled_at DATETIME;

-- Add audit column to attendance records
ALTER TABLE attendance ADD COLUMN verified_by_face INTEGER DEFAULT 0;

-- Sparse index: speeds up the "is enrolled?" check on the dashboard
CREATE INDEX IF NOT EXISTS idx_students_face_enrolled
  ON students(face_descriptor)
  WHERE face_descriptor IS NOT NULL;
