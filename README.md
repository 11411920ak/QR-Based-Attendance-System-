# Smart College Attendance System

## Project Overview
- **Name**: Smart College Attendance System
- **Goal**: Create an intelligent QR code-based attendance tracking system for colleges with location validation and anti-fraud measures
- **Features**: 
  - QR code generation with 5-minute time limit
  - 80-meter radius geolocation validation
  - One-time scan per device/student protection
  - Real-time attendance monitoring
  - Teacher and student dashboards

## URLs
- **Local Development**: https://3000-ifcxiotwstypq3ttd2pvp-c81df28e.sandbox.novita.ai
- **Teacher Dashboard**: https://3000-ifcxiotwstypq3ttd2pvp-c81df28e.sandbox.novita.ai/teacher
- **Student Dashboard**: https://3000-ifcxiotwstypq3ttd2pvp-c81df28e.sandbox.novita.ai/student
- **Production**: (To be deployed to Cloudflare Pages as `attendance-system`)

## System Features

### ✅ Currently Completed Features
1. **QR Code Generation**
   - Teachers can generate QR codes for specific classes
   - QR codes expire automatically after 5 minutes
   - Real-time countdown timer display

2. **Geolocation Validation**
   - 80-meter radius restriction from QR generation point
   - Accurate distance calculation using Haversine formula
   - Location-based attendance verification

3. **Device & Student Protection**
   - One-time scan per QR session per device
   - Device fingerprinting to prevent sharing
   - Student enrollment verification

4. **Teacher Dashboard**
   - Class selection and management
   - Live attendance monitoring
   - Attendance history and reports
   - Session management (start/stop)

5. **Student Dashboard** 
   - Camera-based QR code scanner
   - Real-time scanning feedback
   - Personal attendance history

6. **Database Architecture**
   - Teachers, students, classes, and enrollment management
   - QR sessions with expiry tracking
   - Attendance records with device tracking
   - Comprehensive indexing for performance

### 🔄 Functional Entry URIs

#### Teacher APIs
- `GET /api/teacher/classes` - Get teacher's classes
  - Query params: `teacherId` (default: t1)
  - Returns: List of classes assigned to the teacher

- `POST /api/generate-qr` - Generate QR code for attendance
  - Body: `{ classId, latitude, longitude, teacherId }`
  - Returns: Session details with QR data and expiration time

- `GET /api/session/{sessionId}/attendance` - Get live attendance
  - Path param: `sessionId`
  - Returns: List of students who marked attendance for this session

- `POST /api/session/{sessionId}/stop` - Stop QR session
  - Path param: `sessionId`
  - Returns: Success confirmation

- `GET /api/teacher/attendance-history` - Get attendance history
  - Query params: `teacherId` (default: t1)
  - Returns: Recent sessions with attendance counts

#### Student APIs  
- `POST /api/scan-qr` - Scan QR and mark attendance
  - Body: `{ qrData, latitude, longitude, studentId }`
  - Validates: Time limit, location, enrollment, device, duplicate scan
  - Returns: Success message with class info and distance

- `GET /api/student/attendance` - Get student's attendance history
  - Query params: `studentId` (default: s1)
  - Returns: Student's attendance records with class details

#### Web Pages
- `GET /` - Home page with system overview and navigation
- `GET /teacher` - Teacher dashboard for QR generation and monitoring
- `GET /student` - Student dashboard for QR scanning and history

### 🚧 Features Not Yet Implemented
1. **Authentication System**
   - JWT-based login for teachers and students
   - Role-based access control
   - Session management

2. **Enhanced Security**
   - Password hashing (currently using placeholder)
   - API rate limiting
   - CSRF protection

3. **Advanced Reporting**
   - Detailed analytics dashboard
   - Export functionality (CSV/PDF)
   - Attendance statistics and trends

4. **Mobile Optimization**
   - Progressive Web App (PWA) features
   - Offline capability
   - Push notifications

5. **Class Management**
   - Bulk student enrollment
   - Schedule management
   - Room allocation

## Data Architecture

### Data Models
- **Teachers**: User management for faculty (id, name, email, password, department)
- **Students**: Student profiles with enrollment data (id, name, email, password, enrollment_number)
- **Classes**: Course information with scheduling (id, name, code, teacher_id, schedule, room)
- **Enrollments**: Many-to-many relationship between students and classes
- **QR Sessions**: Temporary sessions with location and expiry (id, class_id, teacher_id, latitude, longitude, radius_meters, expires_at, is_active)
- **Attendance Records**: Timestamped attendance with validation (id, session_id, student_id, class_id, latitude, longitude, distance_meters, device_fingerprint, marked_at)
- **Device Scans**: Anti-fraud device tracking (id, session_id, device_fingerprint, student_id, scanned_at)

### Storage Services
- **Cloudflare D1**: SQLite-based database for all relational data
- **Local Development**: Uses `--local` flag for offline SQLite database in `.wrangler/state/v3/d1`

### Data Flow
1. Teacher generates QR → Creates session with location/time in `qr_sessions` table
2. Student scans QR → Validates location, time, enrollment, device
3. System records attendance → Inserts into `attendance` and `device_scans` tables
4. Session expires → QR becomes invalid after 5 minutes (checked on scan)

## User Guide

### For Teachers
1. **Access Teacher Dashboard**: Go to `/teacher` (https://3000-ifcxiotwstypq3ttd2pvp-c81df28e.sandbox.novita.ai/teacher)
2. **Select Class**: Choose from your assigned classes (CS301, CS302, CS303)
3. **Generate QR Code**: Click "Generate QR Code" - allow location access when prompted
4. **Display QR**: Show the generated QR code on smart board/projector for students to scan
5. **Monitor Attendance**: Watch live attendance updates in real-time
6. **Stop Session**: Click "Stop Session" when class ends (or wait 5 minutes for auto-expiry)

### For Students
1. **Access Student Dashboard**: Go to `/student` (https://3000-ifcxiotwstypq3ttd2pvp-c81df28e.sandbox.novita.ai/student)
2. **Select Student**: Choose your profile from dropdown (demo mode)
3. **Start Scanner**: Click "Start QR Scanner" - allow camera and location access
4. **Scan QR Code**: Point camera at the QR code displayed in classroom
5. **Verify Location**: Must be within 80 meters of where QR was generated
6. **Confirmation**: Receive success message and see updated attendance history

### Demo Accounts
- **Teacher**: ID `t1` (Dr. John Smith) - Computer Science Department
  - Classes: Data Structures (CS301), Database Systems (CS302), Web Development (CS303)
- **Students**: IDs `s1-s8`
  - s1: Alice Brown (CS2024001)
  - s2: Bob Davis (CS2024002)
  - s3: Charlie Wilson (CS2024003)
  - s4: Diana Martinez (CS2024004)
  - s5: Eva Garcia (CS2024005)
  - s6: Frank Miller (CS2024006)
  - s7: Grace Lee (CS2024007)
  - s8: Henry Taylor (CS2024008)

## Deployment

### Current Status
- **Platform**: Cloudflare Pages
- **Development Status**: ✅ Fully functional locally
- **Production Status**: ⏳ Ready for deployment (requires Cloudflare API key setup)
- **Database**: Cloudflare D1 (local SQLite for development)
- **Tech Stack**: Hono + TypeScript + TailwindCSS + D1 Database
- **Project Name**: `attendance-system` (stored in meta_info)

### Local Development
```bash
# Install dependencies
npm install

# Build project
npm run build

# Apply database migrations
npm run db:migrate:local

# Seed database with demo data  
npm run db:seed

# Start development server with PM2
pm2 start ecosystem.config.cjs

# Check service status
pm2 list

# View logs (non-blocking)
pm2 logs attendance-system --nostream

# Test application
curl http://localhost:3000
```

### Database Management
```bash
# Reset database (clean slate)
npm run db:reset

# Apply migrations only
npm run db:migrate:local

# Seed data only
npm run db:seed

# Query database
npm run db:console:local
# Then run SQL: SELECT * FROM students;
```

### Deployment to Cloudflare Pages

**IMPORTANT: Before deployment, you must set up your Cloudflare API key in the Deploy tab.**

```bash
# 1. Setup Cloudflare API key (REQUIRED FIRST)
# Go to Deploy tab and configure your API key

# 2. Create production D1 database
npx wrangler d1 create attendance-db

# 3. Update wrangler.jsonc with the database_id from step 2

# 4. Apply migrations to production database
npm run db:migrate:prod

# 5. (Optional) Seed production database
wrangler d1 execute attendance-db --file=./seed.sql

# 6. Create Cloudflare Pages project
npx wrangler pages project create attendance-system \
  --production-branch main \
  --compatibility-date 2025-11-18

# 7. Deploy to production
npm run deploy:prod

# 8. Verify deployment
curl https://attendance-system.pages.dev
```

## Security Features
- **Time-based Validation**: QR codes expire after exactly 5 minutes
- **Location Validation**: 80-meter radius enforcement using GPS coordinates (Haversine formula)
- **Device Tracking**: Unique device fingerprinting prevents QR sharing between devices
- **Enrollment Verification**: Students can only mark attendance for enrolled classes
- **One-time Scanning**: Each device can scan only once per QR session
- **Duplicate Prevention**: Database constraints prevent duplicate attendance records

## Technical Implementation

### Distance Calculation
Uses Haversine formula for accurate GPS distance measurement:
```typescript
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371e3; // Earth's radius in meters
  const φ1 = lat1 * Math.PI / 180;
  const φ2 = lat2 * Math.PI / 180;
  const Δφ = (lat2 - lat1) * Math.PI / 180;
  const Δλ = (lon2 - lon1) * Math.PI / 180;

  const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
    Math.cos(φ1) * Math.cos(φ2) *
    Math.sin(Δλ/2) * Math.sin(Δλ/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

  return R * c; // Distance in meters
}
```

### QR Code Generation
- Client-side QR code creation using QRCode.js library
- Session data encoded in QR (session ID)
- Automatic expiration timer with visual countdown

### Real-time Updates
- Polling-based live attendance monitoring (3-second intervals)
- Automatic UI updates when new students mark attendance

### Camera Integration
- Web API camera access using html5-qrcode library
- Real-time QR code scanning with instant feedback
- Error handling for camera and location permissions

### Responsive Design
- Mobile-first UI with TailwindCSS
- Responsive grid layouts for all screen sizes
- Touch-friendly buttons and controls

## Recommended Next Steps
1. **Deploy to Production**
   - Set up Cloudflare API key in Deploy tab
   - Create production D1 database
   - Deploy to Cloudflare Pages

2. **Implement Authentication**
   - Add JWT-based login system
   - Implement password hashing with bcrypt
   - Add session management

3. **Mobile App**
   - Convert to Progressive Web App (PWA)
   - Add offline capability with service workers
   - Implement push notifications

4. **Enhanced Analytics**
   - Add detailed reporting dashboard
   - Implement CSV/PDF export functionality
   - Create attendance trend charts

5. **Bulk Management**
   - Implement bulk student enrollment
   - Add class schedule management
   - Create admin panel for system configuration

## Project Structure
```
webapp/
├── src/
│   ├── index.tsx           # Main Hono application with all routes
│   └── renderer.tsx        # SSR renderer (unused in current implementation)
├── migrations/
│   └── 0001_initial_schema.sql  # Database schema with all tables
├── seed.sql                # Demo data for testing
├── ecosystem.config.cjs    # PM2 configuration for local development
├── wrangler.jsonc          # Cloudflare configuration with D1 binding
├── package.json            # Dependencies and npm scripts
├── vite.config.ts          # Vite build configuration
├── tsconfig.json           # TypeScript configuration
└── README.md               # This file

.wrangler/                  # Local development files (not committed)
└── state/v3/d1/            # Local SQLite database storage
```

## Last Updated
November 18, 2025 - Complete system implementation with all core features
- ✅ Full CRUD operations for attendance tracking
- ✅ QR code generation and scanning
- ✅ Geolocation validation
- ✅ Device fingerprinting
- ✅ Real-time monitoring dashboards
- ✅ Local development with PM2 and D1 local mode
- ⏳ Ready for Cloudflare Pages deployment
