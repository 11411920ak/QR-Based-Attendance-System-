-- Insert demo teachers
INSERT OR IGNORE INTO teachers (id, name, email, password, department) VALUES 
  ('t1', 'Dr. John Smith', 'john.smith@college.edu', 'password123', 'Computer Science'),
  ('t2', 'Dr. Sarah Johnson', 'sarah.johnson@college.edu', 'password123', 'Mathematics'),
  ('t3', 'Prof. Michael Brown', 'michael.brown@college.edu', 'password123', 'Physics');

-- Insert demo students
INSERT OR IGNORE INTO students (id, name, email, password, enrollment_number) VALUES 
  ('s1', 'Alice Brown', 'alice.brown@student.edu', 'student123', 'CS2024001'),
  ('s2', 'Bob Davis', 'bob.davis@student.edu', 'student123', 'CS2024002'),
  ('s3', 'Charlie Wilson', 'charlie.wilson@student.edu', 'student123', 'CS2024003'),
  ('s4', 'Diana Martinez', 'diana.martinez@student.edu', 'student123', 'CS2024004'),
  ('s5', 'Eva Garcia', 'eva.garcia@student.edu', 'student123', 'CS2024005'),
  ('s6', 'Frank Miller', 'frank.miller@student.edu', 'student123', 'CS2024006'),
  ('s7', 'Grace Lee', 'grace.lee@student.edu', 'student123', 'CS2024007'),
  ('s8', 'Henry Taylor', 'henry.taylor@student.edu', 'student123', 'CS2024008');

-- Insert demo classes
INSERT OR IGNORE INTO classes (id, name, code, teacher_id, schedule, room) VALUES 
  ('c1', 'Data Structures and Algorithms', 'CS301', 't1', 'Mon/Wed/Fri 9:00-10:00 AM', 'Room 101'),
  ('c2', 'Database Management Systems', 'CS302', 't1', 'Tue/Thu 10:00-11:30 AM', 'Room 102'),
  ('c3', 'Web Development', 'CS303', 't1', 'Mon/Wed 2:00-3:30 PM', 'Lab 1'),
  ('c4', 'Advanced Mathematics', 'MATH401', 't2', 'Mon/Wed/Fri 11:00-12:00 PM', 'Room 201'),
  ('c5', 'Quantum Physics', 'PHY501', 't3', 'Tue/Thu 2:00-3:30 PM', 'Room 301');

-- Enroll students in classes
INSERT OR IGNORE INTO enrollments (student_id, class_id) VALUES 
  -- All students in Data Structures
  ('s1', 'c1'), ('s2', 'c1'), ('s3', 'c1'), ('s4', 'c1'), ('s5', 'c1'),
  ('s6', 'c1'), ('s7', 'c1'), ('s8', 'c1'),
  
  -- Most students in Database Management
  ('s1', 'c2'), ('s2', 'c2'), ('s3', 'c2'), ('s4', 'c2'), ('s5', 'c2'),
  
  -- Some students in Web Development
  ('s1', 'c3'), ('s2', 'c3'), ('s6', 'c3'), ('s7', 'c3'),
  
  -- Some students in Advanced Math
  ('s3', 'c4'), ('s4', 'c4'), ('s8', 'c4'),
  
  -- Some students in Quantum Physics
  ('s5', 'c5'), ('s6', 'c5'), ('s7', 'c5'), ('s8', 'c5');
