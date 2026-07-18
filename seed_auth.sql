-- Insert users with hashed passwords
-- Password for all demo accounts: password123
-- Hash generated using PBKDF2 with 100,000 iterations (compatible with auth.ts verifyPassword)

-- Admin user
INSERT OR IGNORE INTO users (id, email, password_hash, role) VALUES 
  (1, 'admin@college.edu', 's+ar6k43jthgPanIPyTfHEPAKIe/R4u9/UzLB432lIOfCYI/J1UeLbdyOcoz1S12', 'admin');

-- Teacher users
INSERT OR IGNORE INTO users (id, email, password_hash, role) VALUES 
  (2, 'john.smith@college.edu', 's+ar6k43jthgPanIPyTfHEPAKIe/R4u9/UzLB432lIOfCYI/J1UeLbdyOcoz1S12', 'teacher'),
  (3, 'sarah.johnson@college.edu', 's+ar6k43jthgPanIPyTfHEPAKIe/R4u9/UzLB432lIOfCYI/J1UeLbdyOcoz1S12', 'teacher'),
  (4, 'michael.brown@college.edu', 's+ar6k43jthgPanIPyTfHEPAKIe/R4u9/UzLB432lIOfCYI/J1UeLbdyOcoz1S12', 'teacher');

-- Student users
INSERT OR IGNORE INTO users (id, email, password_hash, role) VALUES 
  (5, 'alice.brown@student.edu', 's+ar6k43jthgPanIPyTfHEPAKIe/R4u9/UzLB432lIOfCYI/J1UeLbdyOcoz1S12', 'student'),
  (6, 'bob.davis@student.edu', 's+ar6k43jthgPanIPyTfHEPAKIe/R4u9/UzLB432lIOfCYI/J1UeLbdyOcoz1S12', 'student'),
  (7, 'charlie.wilson@student.edu', 's+ar6k43jthgPanIPyTfHEPAKIe/R4u9/UzLB432lIOfCYI/J1UeLbdyOcoz1S12', 'student'),
  (8, 'diana.martinez@student.edu', 's+ar6k43jthgPanIPyTfHEPAKIe/R4u9/UzLB432lIOfCYI/J1UeLbdyOcoz1S12', 'student'),
  (9, 'eva.garcia@student.edu', 's+ar6k43jthgPanIPyTfHEPAKIe/R4u9/UzLB432lIOfCYI/J1UeLbdyOcoz1S12', 'student'),
  (10, 'frank.miller@student.edu', 's+ar6k43jthgPanIPyTfHEPAKIe/R4u9/UzLB432lIOfCYI/J1UeLbdyOcoz1S12', 'student'),
  (11, 'grace.lee@student.edu', 's+ar6k43jthgPanIPyTfHEPAKIe/R4u9/UzLB432lIOfCYI/J1UeLbdyOcoz1S12', 'student'),
  (12, 'henry.taylor@student.edu', 's+ar6k43jthgPanIPyTfHEPAKIe/R4u9/UzLB432lIOfCYI/J1UeLbdyOcoz1S12', 'student');

-- Link teachers to user accounts
UPDATE teachers SET user_id = 2 WHERE id = 't1';
UPDATE teachers SET user_id = 3 WHERE id = 't2';
UPDATE teachers SET user_id = 4 WHERE id = 't3';

-- Link students to user accounts
UPDATE students SET user_id = 5 WHERE id = 's1';
UPDATE students SET user_id = 6 WHERE id = 's2';
UPDATE students SET user_id = 7 WHERE id = 's3';
UPDATE students SET user_id = 8 WHERE id = 's4';
UPDATE students SET user_id = 9 WHERE id = 's5';
UPDATE students SET user_id = 10 WHERE id = 's6';
UPDATE students SET user_id = 11 WHERE id = 's7';
UPDATE students SET user_id = 12 WHERE id = 's8';
