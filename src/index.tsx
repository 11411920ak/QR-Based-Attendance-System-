import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'
import { setCookie, deleteCookie, getCookie } from 'hono/cookie'
import {
    hashPassword,
    verifyPassword,
    generateToken,
    createSession,
    deleteSession,
    getUserByEmail,
    getUserByUsername,
    getTeacherIdByUserId,
    getStudentIdByUserId,
    verifyToken,
    verifySession
} from './auth'
import { authMiddleware, requireRole, AuthContext } from './middleware'

type Bindings = {
    DB: D1Database;
}

const app = new Hono<{ Bindings: Bindings }>()

// Enable CORS for API routes
app.use('/api/*', cors())

// Serve static files
app.use('/static/*', serveStatic({ root: './' }))

// Helper function to calculate distance between two coordinates (Haversine formula)
function calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371e3; // Earth's radius in meters
    const phi1 = lat1 * Math.PI / 180;
    const phi2 = lat2 * Math.PI / 180;
    const dPhi = (lat2 - lat1) * Math.PI / 180;
    const dLambda = (lon2 - lon1) * Math.PI / 180;

    const a = Math.sin(dPhi / 2) * Math.sin(dPhi / 2) +
        Math.cos(phi1) * Math.cos(phi2) *
        Math.sin(dLambda / 2) * Math.sin(dLambda / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    return R * c; // Distance in meters
}

// Generate a unique session ID
function generateSessionId(): string {
    return 'qr_' + Date.now() + '_' + Math.random().toString(36).substring(7);
}

// Generate device fingerprint
// clientId MUST be first so it always influences the hash output â€”
// all phone User-Agents share the same long prefix, so appending
// clientId after them made btoa().substring(0,32) identical across devices.
function generateDeviceFingerprint(clientId: string, userAgent: string, ip: string): string {
    // Use clientId as primary uniqueness source; UA+IP as secondary context
    const raw = clientId + '|' + ip + '|' + userAgent;
    return btoa(raw).substring(0, 48); // 48 chars to reduce collision risk
}

// ==================== AUTHENTICATION APIs ====================

// Register new user
app.post('/api/auth/register', async (c) => {
    const { DB } = c.env;
    let body: any;
    try {
        body = await c.req.json();
    } catch {
        return c.json({ success: false, error: 'Invalid JSON body' }, 400);
    }
    const { email, password, role, name, enrollmentNumber, department } = body;

    if (!email || !password || !role) {
        return c.json({ success: false, error: 'Email, password, and role are required' }, 400);
    }

    if (!['admin', 'teacher', 'student'].includes(role)) {
        return c.json({ success: false, error: 'Invalid role' }, 400);
    }

    if (password.length < 8) {
        return c.json({ success: false, error: 'Password must be at least 8 characters' }, 400);
    }

    const existingUser = await getUserByEmail(DB, email);
    if (existingUser) {
        return c.json({ success: false, error: 'Email already registered' }, 400);
    }

    const passwordHash = await hashPassword(password);

    const userResult = await DB.prepare(`
    INSERT INTO users (email, password_hash, role)
    VALUES (?, ?, ?)
  `).bind(email, passwordHash, role).run();

    const userId = userResult.meta.last_row_id as number;

    if (role === 'teacher') {
        if (!name || !department) {
            return c.json({ success: false, error: 'Name and department required for teachers' }, 400);
        }
        const teacherId = 't' + userId;
        await DB.prepare(`
      INSERT INTO teachers (id, name, email, password, department, user_id)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(teacherId, name, email, 'linked_to_user', department, userId).run();
    } else if (role === 'student') {
        if (!name || !enrollmentNumber) {
            return c.json({ success: false, error: 'Name and enrollment number required for students' }, 400);
        }
        const studentId = 's' + userId;
        await DB.prepare(`
      INSERT INTO students (id, name, email, password, enrollment_number, user_id)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(studentId, name, email, 'linked_to_user', enrollmentNumber, userId).run();
    }

    return c.json({
        success: true,
        message: 'Registration successful',
        userId
    });
});

// Login
app.post('/api/auth/login', async (c) => {
    const { DB } = c.env;
    let body: any;
    try {
        body = await c.req.json();
    } catch {
        return c.json({ success: false, error: 'Invalid JSON body' }, 400);
    }
    const { email, password } = body;

    if (!email || !password) {
        return c.json({ success: false, error: 'Email and password are required' }, 400);
    }

    const user = await getUserByEmail(DB, email);
    if (!user) {
        return c.json({ success: false, error: 'Invalid email or password' }, 401);
    }

    const isValid = await verifyPassword(password, user.password_hash);
    if (!isValid) {
        return c.json({ success: false, error: 'Invalid email or password' }, 401);
    }

    if (!user.isActive) {
        return c.json({ success: false, error: 'Account is inactive' }, 401);
    }

    const token = await generateToken({
        userId: user.id,
        email: user.email,
        role: user.role
    });

    await createSession(DB, user.id, token);

    setCookie(c, 'auth_token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
        maxAge: 7 * 24 * 60 * 60,
        path: '/'
    });

    let roleId = null;
    if (user.role === 'teacher') {
        roleId = await getTeacherIdByUserId(DB, user.id);
    } else if (user.role === 'student') {
        roleId = await getStudentIdByUserId(DB, user.id);
    }

    return c.json({
        success: true,
        token,
        user: {
            id: user.id,
            email: user.email,
            role: user.role,
            roleId
        }
    });
});

// Logout
app.post('/api/auth/logout', async (c) => {
    const { DB } = c.env;
    const authHeader = c.req.header('Authorization');
    const cookieToken = getCookie(c, 'auth_token');
    const token = authHeader?.split(' ')[1] || cookieToken;

    if (token) {
        try {
            await deleteSession(DB, token);
        } catch (e) {
            // ignore session deletion errors
        }
    }

    deleteCookie(c, 'auth_token');

    return c.json({ success: true, message: 'Logged out successfully' });
});

// Get current user
app.get('/api/auth/me', authMiddleware as any, async (c: AuthContext) => {
    const { DB } = c.env;
    const user = c.get('user');

    let roleId = null;
    let roleDetails = null;

    if (user.role === 'teacher') {
        roleId = await getTeacherIdByUserId(DB, user.id);
        const teacher = await DB.prepare(`
      SELECT id, name, department FROM teachers WHERE user_id = ?
    `).bind(user.id).first();
        roleDetails = teacher;
    } else if (user.role === 'student') {
        roleId = await getStudentIdByUserId(DB, user.id);
        const student = await DB.prepare(`
      SELECT id, name, enrollment_number FROM students WHERE user_id = ?
    `).bind(user.id).first();
        roleDetails = student;
    }

    return c.json({
        success: true,
        user: {
            ...user,
            roleId,
            roleDetails
        }
    });
});

// ==================== TEACHER APIs ====================

// Teacher Signup
app.post('/api/teacher/signup', async (c) => {
    const { DB } = c.env;
    const { name, phone, gender, username, password } = await c.req.json();

    if (!name || !username || !password || password.length < 6) {
        return c.json({ success: false, error: 'Invalid input. Ensure all fields are filled and password is >= 6 chars.' }, 400);
    }

    try {
        // Check if username exists
        const existing = await getUserByUsername(DB, username);
        if (existing) {
            return c.json({ success: false, error: 'Username already taken' }, 400);
        }

        const passHash = await hashPassword(password);
        
        // Insert into users
        const userInsert = await DB.prepare(`
            INSERT INTO users (email, username, password_hash, role)
            VALUES (?, ?, ?, 'teacher')
            RETURNING id
        `).bind(username + '@placeholder.com', username, passHash).first();
        const userId = userInsert?.id;

        // Insert into teachers
        const tId = 't_' + Date.now();
        await DB.prepare(`
            INSERT INTO teachers (id, name, email, password, department, user_id, phone, gender)
            VALUES (?, ?, ?, ?, 'General', ?, ?, ?)
        `).bind(tId, name, username + '@placeholder.com', 'x', userId, phone || null, gender || null).run();

        return c.json({ success: true });
    } catch (e) {
        console.error(e);
        return c.json({ success: false, error: 'Signup failed' }, 500);
    }
});

// Teacher Login
app.post('/api/teacher/login', async (c) => {
    const { DB } = c.env;
    const { username, password } = await c.req.json();

    const user = await getUserByUsername(DB, username);
    if (!user || user.role !== 'teacher') {
        return c.json({ success: false, error: 'Invalid username or password' }, 401);
    }

    const isValid = await verifyPassword(password, user.password_hash);
    if (!isValid) {
        return c.json({ success: false, error: 'Invalid username or password' }, 401);
    }

    const token = await generateToken({
        userId: user.id,
        email: user.email,
        role: user.role
    });

    await createSession(DB, user.id, token);
    setCookie(c, 'teacher_token', token, {
        path: '/',
        secure: true,
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60,
        sameSite: 'Lax'
    });

    return c.json({ success: true });
});

// Teacher Logout
app.post('/api/teacher/logout', async (c) => {
    const { DB } = c.env;
    const token = getCookie(c, 'teacher_token');
    if (token) {
        await deleteSession(DB, token);
        deleteCookie(c, 'teacher_token', { path: '/' });
    }
    return c.json({ success: true });
});

// Teacher Me (Check Auth)
app.get('/api/teacher/me', async (c) => {
    const { DB } = c.env;
    const token = getCookie(c, 'teacher_token');
    if (!token) return c.json({ success: false }, 401);

    const payload = await verifyToken(token);
    if (!payload || payload.role !== 'teacher') {
        return c.json({ success: false }, 401);
    }
    const isValidSession = await verifySession(DB, token);
    if (!isValidSession) return c.json({ success: false }, 401);

    const teacher = await DB.prepare(`
        SELECT t.id, t.name, u.username
        FROM teachers t
        JOIN users u ON t.user_id = u.id
        WHERE u.id = ?
    `).bind(payload.userId).first();

    return c.json({ success: true, teacher });
});

// Create Subject
app.post('/api/teacher/create-subject', async (c) => {
    const { DB } = c.env;
    const { name, code, schedule, room } = await c.req.json();
    
    const token = getCookie(c, 'teacher_token');
    if (!token) return c.json({ success: false, error: 'Unauthorized' }, 401);
    const payload = await verifyToken(token);
    if (!payload || payload.role !== 'teacher') return c.json({ success: false, error: 'Unauthorized' }, 401);
    
    const teacherId = await getTeacherIdByUserId(DB, payload.userId);
    if (!teacherId) return c.json({ success: false, error: 'Teacher profile not found' }, 404);

    if (!name || !code) return c.json({ success: false, error: 'Name and Code are required' }, 400);

    const cId = 'c_' + Date.now();
    try {
        await DB.prepare(`
            INSERT INTO classes (id, name, code, teacher_id, schedule, room)
            VALUES (?, ?, ?, ?, ?, ?)
        `).bind(cId, name, code, teacherId, schedule || null, room || null).run();
        return c.json({ success: true, classId: cId });
    } catch (e: any) {
        if (e.message?.includes('UNIQUE constraint failed')) {
            return c.json({ success: false, error: 'Subject code must be unique' }, 400);
        }
        return c.json({ success: false, error: 'Failed to create subject' }, 500);
    }
});
// Get teacher's classes
app.get('/api/teacher/classes', async (c) => {
    const { DB } = c.env;
    let teacherId: string | null = c.req.query('teacherId') || null;

    // Prefer session-derived teacherId over query param
    const classToken = getCookie(c, 'teacher_token');
    if (classToken) {
        const classPayload = await verifyToken(classToken);
        if (classPayload) {
            const sid = await getTeacherIdByUserId(DB, classPayload.userId);
            if (sid) teacherId = sid;
        }
    }
    if (!teacherId) teacherId = 't1'; // demo fallback

    const classes = await DB.prepare(`
    SELECT id, name, code, schedule, room, created_at
    FROM classes
    WHERE teacher_id = ?
    ORDER BY name
  `).bind(teacherId).all();

    return c.json({ success: true, classes: classes.results });
});

// Generate QR code for attendance
app.post('/api/generate-qr', async (c) => {
    const { DB } = c.env;
    const body = await c.req.json();
    const { classId, latitude, longitude } = body;
    let teacherId: string = body.teacherId || 't1';

    // Session overrides body teacherId (prevents spoofing)
    const qrToken = getCookie(c, 'teacher_token');
    if (qrToken) {
        const qrPayload = await verifyToken(qrToken);
        if (qrPayload) {
            const sessionTeacherId = await getTeacherIdByUserId(DB, qrPayload.userId);
            if (sessionTeacherId) teacherId = sessionTeacherId;
        }
    }

    if (!classId || latitude === undefined || latitude === null || longitude === undefined || longitude === null) {
        return c.json({ success: false, error: 'Missing required fields' }, 400);
    }

    const sessionId = generateSessionId();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes from now

    await DB.prepare(`
    INSERT INTO qr_sessions (id, class_id, teacher_id, latitude, longitude, expires_at, is_active)
    VALUES (?, ?, ?, ?, ?, ?, 1)
  `).bind(sessionId, classId, teacherId || 't1', latitude, longitude, expiresAt.toISOString()).run();

    // Get class information
    const classInfo = await DB.prepare(`
    SELECT c.name, c.code, t.name as teacher_name
    FROM classes c
    JOIN teachers t ON c.teacher_id = t.id
    WHERE c.id = ?
  `).bind(classId).first();

    return c.json({
        success: true,
        session: {
            id: sessionId,
            classId,
            className: classInfo?.name,
            classCode: classInfo?.code,
            teacherName: classInfo?.teacher_name,
            expiresAt: expiresAt.toISOString(),
            latitude,
            longitude
        }
    });
});

// Get live attendance for a session
app.get('/api/session/:sessionId/attendance', async (c) => {
    const { DB } = c.env;
    const sessionId = c.req.param('sessionId');

    const attendance = await DB.prepare(`
    SELECT 
      a.id,
      a.student_id,
      s.name as student_name,
      s.enrollment_number,
      a.latitude,
      a.longitude,
      a.distance_meters,
      strftime('%Y-%m-%dT%H:%M:%SZ', a.marked_at) as marked_at
    FROM attendance a
    JOIN students s ON a.student_id = s.id
    WHERE a.session_id = ?
    ORDER BY a.marked_at DESC
  `).bind(sessionId).all();

    return c.json({ success: true, attendance: attendance.results });
});

// Stop QR session
app.post('/api/session/:sessionId/stop', async (c) => {
    const { DB } = c.env;
    const sessionId = c.req.param('sessionId');

    await DB.prepare(`
    UPDATE qr_sessions
    SET is_active = 0
    WHERE id = ?
  `).bind(sessionId).run();

    return c.json({ success: true, message: 'Session stopped successfully' });
});

// Get attendance history for teacher
app.get('/api/teacher/attendance-history', async (c) => {
    const { DB } = c.env;
    const teacherId = c.req.query('teacherId') || 't1';

    const history = await DB.prepare(`
    SELECT 
      qs.id as session_id,
      c.name as class_name,
      c.code as class_code,
      qs.created_at,
      qs.expires_at,
      qs.is_active,
      COUNT(a.id) as attendance_count
    FROM qr_sessions qs
    JOIN classes c ON qs.class_id = c.id
    LEFT JOIN attendance a ON qs.id = a.session_id
    WHERE qs.teacher_id = ?
    GROUP BY qs.id
    ORDER BY qs.created_at DESC
    LIMIT 50
  `).bind(teacherId).all();

    return c.json({ success: true, history: history.results });
});

// Get active session for a teacher or class (recovery endpoint)
app.get('/api/active-session', async (c) => {
    const { DB } = c.env;
    const teacherId = c.req.query('teacherId');
    const classId = c.req.query('classId');

    if (!teacherId && !classId) {
        return c.json({ success: false, error: 'teacherId or classId is required' }, 400);
    }

    const nowStr = new Date().toISOString();
    let query = `
        SELECT id, class_id, teacher_id, latitude, longitude, expires_at, is_active
        FROM qr_sessions
        WHERE is_active = 1 AND expires_at > ?
    `;
    const params: any[] = [nowStr];

    if (classId) {
        query += ` AND class_id = ?`;
        params.push(classId);
    } else if (teacherId) {
        query += ` AND teacher_id = ?`;
        params.push(teacherId);
    }

    query += ` ORDER BY created_at DESC LIMIT 1`;

    const session = await DB.prepare(query).bind(...params).first();

    if (!session) {
        return c.json({ success: true, session: null });
    }

    // Get class information
    const classInfo = await DB.prepare(`
        SELECT c.name, c.code, t.name as teacher_name
        FROM classes c
        JOIN teachers t ON c.teacher_id = t.id
        WHERE c.id = ?
    `).bind(session.class_id).first();

    return c.json({
        success: true,
        session: {
            id: session.id,
            classId: session.class_id,
            className: classInfo?.name,
            classCode: classInfo?.code,
            teacherName: classInfo?.teacher_name,
            expiresAt: session.expires_at,
            latitude: session.latitude,
            longitude: session.longitude
        }
    });
});

// ==================== STUDENT APIs ====================

// Student Signup
app.post('/api/student/signup', async (c) => {
    const { DB } = c.env;
    const { name, branch, roll_no, section, gender, year, password } = await c.req.json();

    if (!name || !roll_no || !password || password.length < 6) {
        return c.json({ success: false, error: 'Name, Roll No and a password (min 6 chars) are required.' }, 400);
    }

    try {
        // Roll no must be unique across students
        const existing = await DB.prepare(`SELECT id FROM students WHERE roll_no = ?`).bind(roll_no).first();
        if (existing) {
            return c.json({ success: false, error: 'A student with this Roll No already exists.' }, 400);
        }

        const passHash = await hashPassword(password);

        // Create user record (roll_no is the username)
        const userInsert = await DB.prepare(`
            INSERT INTO users (email, username, password_hash, role)
            VALUES (?, ?, ?, 'student')
            RETURNING id
        `).bind(roll_no + '@student.local', roll_no, passHash).first();
        const userId = userInsert?.id;

        // Create student profile
        const sId = 's_' + Date.now();
        await DB.prepare(`
            INSERT INTO students (id, name, email, password, enrollment_number, user_id, branch, roll_no, section, gender, year)
            VALUES (?, ?, ?, 'x', ?, ?, ?, ?, ?, ?, ?)
        `).bind(sId, name, roll_no + '@student.local', roll_no, userId, branch || null, roll_no, section || null, gender || null, year || null).run();

        return c.json({ success: true });
    } catch (e: any) {
        console.error('Student signup error:', e);
        if (e?.message?.includes('UNIQUE')) {
            return c.json({ success: false, error: 'Roll No already registered.' }, 400);
        }
        return c.json({ success: false, error: 'Signup failed. Please try again.' }, 500);
    }
});

// Student Login (using roll_no as username)
app.post('/api/student/login', async (c) => {
    const { DB } = c.env;
    const { roll_no, password } = await c.req.json();

    if (!roll_no || !password) {
        return c.json({ success: false, error: 'Roll No and password are required.' }, 400);
    }

    const user = await getUserByUsername(DB, roll_no);
    if (!user || user.role !== 'student') {
        return c.json({ success: false, error: 'Invalid Roll No or password.' }, 401);
    }

    const isValid = await verifyPassword(password, user.password_hash);
    if (!isValid) {
        return c.json({ success: false, error: 'Invalid Roll No or password.' }, 401);
    }

    const token = await generateToken({ userId: user.id, email: user.email, role: user.role });
    await createSession(DB, user.id, token);

    setCookie(c, 'student_token', token, {
        path: '/',
        secure: true,
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60,
        sameSite: 'Lax'
    });

    return c.json({ success: true });
});

// Student Logout
app.post('/api/student/logout', async (c) => {
    const { DB } = c.env;
    const token = getCookie(c, 'student_token');
    if (token) {
        await deleteSession(DB, token);
        deleteCookie(c, 'student_token', { path: '/' });
    }
    return c.json({ success: true });
});

// Student Me (session check)
app.get('/api/student/me', async (c) => {
    const { DB } = c.env;
    const token = getCookie(c, 'student_token');
    if (!token) return c.json({ success: false }, 401);

    const payload = await verifyToken(token);
    if (!payload || payload.role !== 'student') return c.json({ success: false }, 401);

    const isValidSession = await verifySession(DB, token);
    if (!isValidSession) return c.json({ success: false }, 401);

    const student = await DB.prepare(`
        SELECT s.id, s.name, s.roll_no, s.branch, s.section, s.year, s.gender
        FROM students s
        JOIN users u ON s.user_id = u.id
        WHERE u.id = ?
    `).bind(payload.userId).first();

    return c.json({ success: true, student });
});

// Student Attendance History (session-aware)
app.get('/api/student/attendance', async (c) => {
    const { DB } = c.env;
    let studentId = c.req.query('studentId') || 's1';

    // Prefer session
    const sToken = getCookie(c, 'student_token');
    if (sToken) {
        const sPay = await verifyToken(sToken);
        if (sPay) {
            const sid = await getStudentIdByUserId(DB, sPay.userId);
            if (sid) studentId = sid;
        }
    }

    const attendance = await DB.prepare(`
        SELECT
          a.id,
          c.name as class_name,
          c.code as class_code,
          t.name as teacher_name,
          strftime('%Y-%m-%dT%H:%M:%SZ', a.marked_at) as marked_at,
          a.distance_meters
        FROM attendance a
        JOIN classes c ON a.class_id = c.id
        JOIN teachers t ON c.teacher_id = t.id
        WHERE a.student_id = ?
        ORDER BY a.marked_at DESC
        LIMIT 50
    `).bind(studentId).all();

    return c.json({ success: true, attendance: attendance.results });
});

// Scan QR code and mark attendance
app.post('/api/scan-qr', async (c) => {
    const { DB } = c.env;
    const body = await c.req.json();
    const { qrData, latitude, longitude, clientId } = body;

    // Derive studentId from session cookie (secure) â€” fallback to body for legacy/demo
    let studentId = body.studentId || null;
    const scanToken = getCookie(c, 'student_token');
    if (scanToken) {
        const scanPayload = await verifyToken(scanToken);
        if (scanPayload && scanPayload.role === 'student') {
            const sid = await getStudentIdByUserId(DB, scanPayload.userId);
            if (sid) studentId = sid;
        }
    }

    if (!qrData || latitude === undefined || latitude === null || longitude === undefined || longitude === null || !studentId) {
        return c.json({ success: false, error: 'Missing required fields' }, 400);
    }

    // Parse QR data (should be the session ID)
    const sessionId = qrData;

    // Get session details
    const session = await DB.prepare(`
    SELECT id, class_id, latitude, longitude, radius_meters, expires_at, is_active
    FROM qr_sessions
    WHERE id = ?
  `).bind(sessionId).first();

    if (!session) {
        return c.json({ success: false, error: 'Invalid QR code' }, 404);
    }

    // Check if session is active
    if (!session.is_active) {
        return c.json({ success: false, error: 'This QR session has been stopped' }, 400);
    }

    // Check if session has expired
    const now = new Date();
    const expiresAt = new Date(session.expires_at as string);
    if (now > expiresAt) {
        return c.json({ success: false, error: 'QR code has expired' }, 400);
    }

    // Auto-enroll student in the class if not already enrolled.
    // This removes the friction of manual enrollment â€” scanning the QR
    // is the student's implicit confirmation they belong to this class.
    const enrollment = await DB.prepare(`
        SELECT id FROM enrollments
        WHERE student_id = ? AND class_id = ?
    `).bind(studentId, session.class_id).first();

    if (!enrollment) {
        await DB.prepare(`
            INSERT OR IGNORE INTO enrollments (student_id, class_id)
            VALUES (?, ?)
        `).bind(studentId, session.class_id).run();
    }

    // Calculate distance
    const distance = calculateDistance(
        session.latitude as number,
        session.longitude as number,
        latitude,
        longitude
    );

    // Check if within radius
    const radiusMeters = (session.radius_meters as number) || 80;
    if (distance > radiusMeters) {
        return c.json({
            success: false,
            error: `You must be within ${radiusMeters} meters of the classroom. Current distance: ${Math.round(distance)} meters`,
            distance: Math.round(distance)
        }, 400);
    }

    // Generate device fingerprint.
    // clientId is a persistent random token generated in the browser's localStorage,
    // unique per physical device regardless of shared NAT/WiFi IP.
    const userAgent = c.req.header('User-Agent') || '';
    const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || '';
    const safeClientId = (clientId || '').substring(0, 64);
    const deviceFingerprint = generateDeviceFingerprint(safeClientId, userAgent, ip);

    // Check if this physical device has already scanned this session.
    // Scoped to (session + device fingerprint) â€” one device per session.
    // Now that clientId is included in the fingerprint, different physical
    // devices on the same WiFi get unique fingerprints, so this check
    // correctly blocks only the same device from scanning twice.
    const existingScan = await DB.prepare(`
    SELECT id FROM device_scans
    WHERE session_id = ? AND device_fingerprint = ?
  `).bind(sessionId, deviceFingerprint).first();

    if (existingScan) {
        return c.json({ success: false, error: 'This device has already marked attendance for this session' }, 400);
    }

    // Check if student has already marked attendance for this session
    const existingAttendance = await DB.prepare(`
    SELECT id FROM attendance
    WHERE session_id = ? AND student_id = ?
  `).bind(sessionId, studentId).first();

    if (existingAttendance) {
        return c.json({ success: false, error: 'You have already marked your attendance' }, 400);
    }

    // ── Face Token Validation (hard gate) ────────────────────────────────────
    // A valid face_token is strictly required. It verifies the HMAC signature and expiry.
    // Valid token = /api/face/verify already confirmed a server-side face match.
    let verifiedByFace = 0;
    const faceToken = body.face_token;
    if (!faceToken) {
        return c.json({ success: false, error: 'Face verification is strictly required to mark attendance.' }, 400);
    }
    try {
        const parts = faceToken.split('.');
        if (parts.length === 2) {
            const payloadB64 = parts[0];
            const sigB64 = parts[1];
            const encoder = new TextEncoder();
            const jwtSecret = (c.env && c.env.JWT_SECRET) ||
                'your-secret-key-change-in-production-min-32-chars-attendance-system-2025';
            const key = await crypto.subtle.importKey(
                'raw',
                encoder.encode(jwtSecret),
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            const expectedSig = await crypto.subtle.sign('HMAC', key, encoder.encode(payloadB64));
            const expectedB64 = btoa(String.fromCharCode(...new Uint8Array(expectedSig)))
                .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            if (expectedB64 === sigB64) {
                const tokenPayload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
                if (tokenPayload.studentId === studentId && tokenPayload.exp > Date.now()) {
                    verifiedByFace = 1;
                }
            }
        }
    } catch (_) {
        // signature validation or parsing failed
    }

    if (verifiedByFace !== 1) {
        return c.json({ success: false, error: 'Face verification is invalid or has expired. Please verify your face again.' }, 400);
    }

    // Mark attendance (includes verified_by_face audit flag)
    await DB.prepare(`
    INSERT INTO attendance (session_id, student_id, class_id, latitude, longitude, distance_meters, device_fingerprint, verified_by_face)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(sessionId, studentId, session.class_id, latitude, longitude, distance, deviceFingerprint, verifiedByFace).run();

    // Record device scan
    await DB.prepare(`
    INSERT INTO device_scans (session_id, device_fingerprint, student_id)
    VALUES (?, ?, ?)
  `).bind(sessionId, deviceFingerprint, studentId).run();

    // Get class information
    const classInfo = await DB.prepare(`
    SELECT name, code FROM classes WHERE id = ?
  `).bind(session.class_id).first();

    return c.json({
        success: true,
        message: 'Attendance marked successfully',
        class: classInfo,
        distance: Math.round(distance)
    });
});

// Get student's attendance history
app.get('/api/student/attendance', async (c) => {
    const { DB } = c.env;
    const studentId = c.req.query('studentId') || 's1';

    const attendance = await DB.prepare(`
    SELECT 
      a.id,
      c.name as class_name,
      c.code as class_code,
      t.name as teacher_name,
      strftime('%Y-%m-%dT%H:%M:%SZ', a.marked_at) as marked_at,
      a.distance_meters
    FROM attendance a
    JOIN classes c ON a.class_id = c.id
    JOIN teachers t ON c.teacher_id = t.id
    WHERE a.student_id = ?
    ORDER BY a.marked_at DESC
    LIMIT 50
  `).bind(studentId).all();

    return c.json({ success: true, attendance: attendance.results });
});

// ==================== FACE VERIFICATION APIs ====================

// Check if student has enrolled their face
app.get('/api/face/status', async (c) => {
    const { DB } = c.env;
    const token = getCookie(c, 'student_token');
    if (!token) return c.json({ success: false, error: 'Unauthorized' }, 401);
    const payload = await verifyToken(token);
    if (!payload || payload.role !== 'student') return c.json({ success: false, error: 'Unauthorized' }, 401);
    const isValidSession = await verifySession(DB, token);
    if (!isValidSession) return c.json({ success: false, error: 'Unauthorized' }, 401);

    const studentId = await getStudentIdByUserId(DB, payload.userId);
    if (!studentId) return c.json({ success: false, error: 'Student not found' }, 404);

    const student = await DB.prepare(`
        SELECT face_descriptor FROM students WHERE id = ?
    `).bind(studentId).first();

    return c.json({
        success: true,
        enrolled: !!(student && student.face_descriptor)
    });
});

// Enroll a student's face
app.post('/api/face/enroll', async (c) => {
    const { DB } = c.env;
    const token = getCookie(c, 'student_token');
    if (!token) return c.json({ success: false, error: 'Unauthorized' }, 401);
    const payload = await verifyToken(token);
    if (!payload || payload.role !== 'student') return c.json({ success: false, error: 'Unauthorized' }, 401);
    const isValidSession = await verifySession(DB, token);
    if (!isValidSession) return c.json({ success: false, error: 'Unauthorized' }, 401);

    const studentId = await getStudentIdByUserId(DB, payload.userId);
    if (!studentId) return c.json({ success: false, error: 'Student not found' }, 404);

    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ success: false, error: 'Invalid JSON' }, 400); }

    const { descriptor } = body;

    // Validate descriptor: must be exactly 128 finite floats
    if (!Array.isArray(descriptor) || descriptor.length !== 128 ||
        !descriptor.every((v) => typeof v === 'number' && isFinite(v))) {
        return c.json({ success: false, error: 'Invalid face descriptor — must be 128 finite floats' }, 400);
    }

    // Rate-limit check: block re-enrollment within 60 seconds
    const existing = await DB.prepare(`
        SELECT face_enrolled_at FROM students WHERE id = ?
    `).bind(studentId).first();

    if (existing && existing.face_enrolled_at) {
        const lastEnrolled = new Date(existing.face_enrolled_at as string).getTime();
        if (Date.now() - lastEnrolled < 60_000) {
            return c.json({ success: false, error: 'Please wait 60 seconds before re-enrolling your face.' }, 429);
        }
    }

    const descriptorJson = JSON.stringify(descriptor);
    const enrolledAt = new Date().toISOString();

    await DB.prepare(`
        UPDATE students SET face_descriptor = ?, face_enrolled_at = ? WHERE id = ?
    `).bind(descriptorJson, enrolledAt, studentId).run();

    return c.json({ success: true, message: 'Face enrolled successfully.' });
});

// Verify a student's face and return a HMAC face_token
app.post('/api/face/verify', async (c) => {
    const { DB } = c.env;
    const token = getCookie(c, 'student_token');
    if (!token) return c.json({ success: false, error: 'Unauthorized' }, 401);
    const payload = await verifyToken(token);
    if (!payload || payload.role !== 'student') return c.json({ success: false, error: 'Unauthorized' }, 401);
    const isValidSession = await verifySession(DB, token);
    if (!isValidSession) return c.json({ success: false, error: 'Unauthorized' }, 401);

    const studentId = await getStudentIdByUserId(DB, payload.userId);
    if (!studentId) return c.json({ success: false, error: 'Student not found' }, 404);

    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ success: false, error: 'Invalid JSON' }, 400); }

    const { descriptor } = body;

    // Validate descriptor: must be exactly 128 finite floats
    if (!Array.isArray(descriptor) || descriptor.length !== 128 ||
        !descriptor.every((v) => typeof v === 'number' && isFinite(v))) {
        return c.json({ success: false, error: 'Invalid face descriptor — must be 128 finite floats' }, 400);
    }

    // Retrieve enrolled face descriptor
    const student = await DB.prepare(`
        SELECT face_descriptor FROM students WHERE id = ?
    `).bind(studentId).first();

    if (!student || !student.face_descriptor) {
        return c.json({ success: false, error: 'Face not enrolled. Please enroll your face first.' }, 400);
    }

    let enrolledDescriptor: number[];
    try {
        enrolledDescriptor = JSON.parse(student.face_descriptor as string);
    } catch (e) {
        return c.json({ success: false, error: 'Enrolled face data is corrupt.' }, 500);
    }

    if (!Array.isArray(enrolledDescriptor) || enrolledDescriptor.length !== 128) {
        return c.json({ success: false, error: 'Enrolled face data is invalid.' }, 500);
    }

    // Euclidean distance calculation
    let sumSquares = 0;
    for (let i = 0; i < 128; i++) {
        const diff = descriptor[i] - enrolledDescriptor[i];
        sumSquares += diff * diff;
    }
    const distance = Math.sqrt(sumSquares);

    // Threshold of 0.40 is standard/strict for face-api.js TinyFaceDetector + FaceLandmark68 + FaceRecognition
    if (distance > 0.40) {
        return c.json({ success: false, error: 'Face not recognized. Keep still and ensure proper lighting.' }, 400);
    }

    // Generate signed face_token
    const exp = Date.now() + 5 * 60 * 1000; // 5 min expiry
    const tokenPayload = { studentId, exp };
    const payloadB64 = btoa(JSON.stringify(tokenPayload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const jwtSecret = (c.env && c.env.JWT_SECRET) ||
        'your-secret-key-change-in-production-min-32-chars-attendance-system-2025';

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(jwtSecret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payloadB64));
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    const faceToken = `${payloadB64}.${sigB64}`;

    return c.json({
        success: true,
        face_token: faceToken
    });
});

// ==================== WEB PAGES ====================

// Teacher Login Page
app.get('/teacher/login', (c) => {
    return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Teacher Sign In — AttendX</title>
        <meta name="description" content="Sign in to the AttendX teacher portal to manage classes and attendance.">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"><\/script>
        <style>
            *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
            body{font-family:'Inter',sans-serif;background:#080b14;color:#e2e8f0;min-height:100vh;overflow-x:hidden}
            .mesh-bg{position:fixed;inset:0;z-index:0;background:radial-gradient(ellipse 80% 60% at 20% 10%,rgba(99,102,241,.15) 0%,transparent 60%),radial-gradient(ellipse 60% 50% at 80% 80%,rgba(139,92,246,.1) 0%,transparent 55%),#080b14}
            .orb{position:fixed;border-radius:50%;filter:blur(100px);pointer-events:none;z-index:0;animation:orbF 25s ease-in-out infinite}
            .orb-1{width:450px;height:450px;top:-120px;left:-100px;background:radial-gradient(circle,rgba(99,102,241,.3),transparent 70%)}
            .orb-2{width:350px;height:350px;bottom:-80px;right:-60px;background:radial-gradient(circle,rgba(139,92,246,.25),transparent 70%);animation-delay:-10s}
            .orb-3{width:200px;height:200px;top:40%;left:60%;background:radial-gradient(circle,rgba(99,102,241,.12),transparent 70%);animation-delay:-5s}
            @keyframes orbF{0%,100%{transform:translate(0,0) scale(1)}25%{transform:translate(40px,-30px) scale(1.05)}50%{transform:translate(-20px,20px) scale(.95)}75%{transform:translate(30px,40px) scale(1.08)}}
            .auth-wrap{position:relative;z-index:1;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
            .auth-card{display:grid;grid-template-columns:1fr 1fr;max-width:920px;width:100%;border-radius:28px;overflow:hidden;border:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.025);backdrop-filter:blur(40px);box-shadow:0 30px 100px -20px rgba(0,0,0,.5);animation:cardIn .8s cubic-bezier(.16,1,.3,1)}
            @keyframes cardIn{from{opacity:0;transform:translateY(30px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}
            @media(max-width:768px){.auth-card{grid-template-columns:1fr;max-width:480px}}
            .brand{padding:52px 44px;display:flex;flex-direction:column;justify-content:center;position:relative;overflow:hidden;background:linear-gradient(145deg,rgba(99,102,241,.08),rgba(139,92,246,.03));border-right:1px solid rgba(255,255,255,.05)}
            .brand::before{content:'';position:absolute;top:0;left:10%;right:10%;height:1px;background:linear-gradient(90deg,transparent,rgba(99,102,241,.4),transparent)}
            .brand::after{content:'';position:absolute;bottom:30px;right:-30px;width:120px;height:120px;border-radius:50%;background:radial-gradient(circle,rgba(99,102,241,.1),transparent 70%);filter:blur(30px)}
            @media(max-width:768px){.brand{padding:36px 28px;border-right:none;border-bottom:1px solid rgba(255,255,255,.05)}}
            .b-logo{display:flex;align-items:center;gap:12px;margin-bottom:40px}
            .b-logo-i{width:42px;height:42px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border-radius:13px;display:flex;align-items:center;justify-content:center;font-size:16px;color:#fff;box-shadow:0 0 20px rgba(99,102,241,.35)}
            .b-logo-t{font-size:21px;font-weight:800;color:#fff;letter-spacing:-.5px}
            .b-logo-t span{color:#818cf8}
            .b-icon{width:76px;height:76px;border-radius:22px;background:linear-gradient(135deg,rgba(99,102,241,.18),rgba(139,92,246,.12));display:flex;align-items:center;justify-content:center;font-size:30px;color:#818cf8;margin-bottom:28px;box-shadow:0 0 40px rgba(99,102,241,.12);animation:glow 4s ease-in-out infinite}
            @keyframes glow{0%,100%{box-shadow:0 0 40px rgba(99,102,241,.12)}50%{box-shadow:0 0 60px rgba(99,102,241,.22)}}
            .b-h{font-size:25px;font-weight:800;color:#f1f5f9;margin-bottom:10px;letter-spacing:-.5px;line-height:1.25}
            .b-p{font-size:14px;color:#64748b;line-height:1.75;margin-bottom:32px}
            .chips{display:flex;flex-wrap:wrap;gap:8px}
            .chip{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:999px;font-size:11px;font-weight:600;background:rgba(99,102,241,.08);border:1px solid rgba(99,102,241,.18);color:#a5b4fc;transition:all .3s}
            .chip:hover{background:rgba(99,102,241,.15);border-color:rgba(99,102,241,.3);transform:translateY(-1px)}
            .chip i{font-size:9px}
            .fpanel{padding:52px 44px;display:flex;flex-direction:column;justify-content:center}
            @media(max-width:768px){.fpanel{padding:36px 28px}}
            .f-h{font-size:26px;font-weight:800;color:#f1f5f9;margin-bottom:6px;letter-spacing:-.5px}
            .f-sub{font-size:13px;color:#64748b;margin-bottom:32px}
            .err{background:rgba(244,63,94,.08);border:1px solid rgba(244,63,94,.18);color:#fb7185;padding:12px 16px;border-radius:12px;font-size:13px;font-weight:500;text-align:center;margin-bottom:20px;display:none}
            .err.show{display:block;animation:shake .4s ease}
            @keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-8px)}40%{transform:translateX(8px)}60%{transform:translateX(-4px)}80%{transform:translateX(4px)}}
            .fld{margin-bottom:22px}
            .fld-l{display:block;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px}
            .iw{position:relative}
            .ii{position:absolute;top:50%;left:16px;transform:translateY(-50%);color:#3f4a5c;font-size:14px;pointer-events:none;transition:color .3s}
            .fi{width:100%;padding:14px 16px 14px 46px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:14px;color:#e2e8f0;font-size:14px;font-family:'Inter',sans-serif;outline:none;transition:all .3s}
            .fi:focus{border-color:rgba(99,102,241,.45);box-shadow:0 0 0 3px rgba(99,102,241,.08),0 0 24px rgba(99,102,241,.06);background:rgba(255,255,255,.06)}
            .fi:focus~.ii{color:#818cf8}
            .fi::placeholder{color:#3f4a5c}
            .pw-t{position:absolute;top:50%;right:16px;transform:translateY(-50%);background:none;border:none;color:#3f4a5c;cursor:pointer;font-size:14px;padding:4px;transition:color .2s}
            .pw-t:hover{color:#818cf8}
            .sbtn{width:100%;padding:15px;margin-top:4px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none;border-radius:14px;font-size:14px;font-weight:700;font-family:'Inter',sans-serif;cursor:pointer;letter-spacing:.3px;transition:all .3s cubic-bezier(.23,1,.32,1);box-shadow:0 4px 24px rgba(99,102,241,.25);position:relative;overflow:hidden}
            .sbtn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,transparent 30%,rgba(255,255,255,.1) 50%,transparent 70%);transform:translateX(-100%);transition:transform .6s}
            .sbtn:hover::after{transform:translateX(100%)}
            .sbtn:hover:not(:disabled){box-shadow:0 8px 40px rgba(99,102,241,.4);transform:translateY(-2px)}
            .sbtn:active:not(:disabled){transform:translateY(0)}
            .sbtn:disabled{opacity:.6;cursor:not-allowed}
            .alt{text-align:center;margin-top:28px;font-size:13px;color:#64748b}
            .alt a{color:#818cf8;font-weight:600;text-decoration:none;transition:color .2s}
            .alt a:hover{color:#a5b4fc}
            .bk{position:fixed;top:28px;left:28px;z-index:10;display:inline-flex;align-items:center;gap:8px;color:#475569;font-size:13px;font-weight:500;text-decoration:none;transition:all .2s;padding:8px 16px;border-radius:12px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}
            .bk:hover{color:#818cf8;background:rgba(99,102,241,.06);border-color:rgba(99,102,241,.15)}
        </style>
    </head>
    <body>
        <div class="mesh-bg"></div>
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
        <div class="orb orb-3"></div>
        <a href="/" class="bk"><i class="fas fa-arrow-left"></i> Home</a>
        <div class="auth-wrap">
            <div class="auth-card">
                <div class="brand">
                    <div class="b-logo"><div class="b-logo-i"><i class="fas fa-qrcode"></i></div><div class="b-logo-t">Attend<span>X</span></div></div>
                    <div class="b-icon"><i class="fas fa-chalkboard-teacher"></i></div>
                    <div class="b-h">Instructor Portal</div>
                    <div class="b-p">Manage your classes, generate secure QR codes, and monitor student attendance in real-time.</div>
                    <div class="chips">
                        <div class="chip"><i class="fas fa-plus-circle"></i> Create Subjects</div>
                        <div class="chip"><i class="fas fa-qrcode"></i> Generate QR</div>
                        <div class="chip"><i class="fas fa-chart-line"></i> Live Monitoring</div>
                        <div class="chip"><i class="fas fa-shield-alt"></i> Anti-Fraud</div>
                    </div>
                </div>
                <div class="fpanel">
                    <div class="f-h">Welcome Back</div>
                    <div class="f-sub">Sign in to your instructor account</div>
                    <form id="loginForm">
                        <div id="errorMsg" class="err"></div>
                        <div class="fld">
                            <label class="fld-l">Username</label>
                            <div class="iw">
                                <input type="text" id="username" class="fi" placeholder="Enter your username" required>
                                <i class="fas fa-user ii"></i>
                            </div>
                        </div>
                        <div class="fld">
                            <label class="fld-l">Password</label>
                            <div class="iw">
                                <input type="password" id="password" class="fi" placeholder="Enter your password" required>
                                <i class="fas fa-lock ii"></i>
                                <button type="button" class="pw-t" onclick="togglePw(this)"><i class="fas fa-eye"></i></button>
                            </div>
                        </div>
                        <button type="submit" id="submitBtn" class="sbtn">Sign In</button>
                    </form>
                    <div class="alt">Don't have an account? <a href="/teacher/signup">Create one</a></div>
                </div>
            </div>
        </div>
        <script>
            function togglePw(b){var i=b.parentElement.querySelector('input'),c=b.querySelector('i');if(i.type==='password'){i.type='text';c.className='fas fa-eye-slash'}else{i.type='password';c.className='fas fa-eye'}}
            document.getElementById('loginForm').addEventListener('submit',async function(e){
                e.preventDefault();
                var btn=document.getElementById('submitBtn');
                var err=document.getElementById('errorMsg');
                btn.disabled=true;
                btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Signing in...';
                err.classList.remove('show');
                try{
                    var res=await axios.post('/api/teacher/login',{username:document.getElementById('username').value,password:document.getElementById('password').value});
                    if(res.data.success){btn.innerHTML='<i class="fas fa-check"></i> Success!';window.location.href='/teacher';}
                }catch(error){
                    err.textContent=error.response?.data?.error||'Login failed. Please try again.';
                    err.classList.add('show');
                    btn.disabled=false;
                    btn.innerHTML='Sign In';
                }
            });
        <\/script>
    </body>
    </html>
    `);
});


// Teacher Signup Page
// Teacher Signup Page
app.get('/teacher/signup', (c) => {
    return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Teacher Sign Up — AttendX</title>
        <meta name="description" content="Create an instructor account on AttendX to manage attendance.">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"><\/script>
        <style>
            *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
            body{font-family:'Inter',sans-serif;background:#080b14;color:#e2e8f0;min-height:100vh;overflow-x:hidden}
            .mesh-bg{position:fixed;inset:0;z-index:0;background:radial-gradient(ellipse 80% 60% at 20% 10%,rgba(99,102,241,.15) 0%,transparent 60%),radial-gradient(ellipse 60% 50% at 80% 80%,rgba(139,92,246,.1) 0%,transparent 55%),#080b14}
            .orb{position:fixed;border-radius:50%;filter:blur(100px);pointer-events:none;z-index:0;animation:orbF 25s ease-in-out infinite}
            .orb-1{width:450px;height:450px;top:-120px;left:-100px;background:radial-gradient(circle,rgba(99,102,241,.3),transparent 70%)}
            .orb-2{width:350px;height:350px;bottom:-80px;right:-60px;background:radial-gradient(circle,rgba(139,92,246,.25),transparent 70%);animation-delay:-10s}
            .orb-3{width:200px;height:200px;top:40%;left:60%;background:radial-gradient(circle,rgba(99,102,241,.12),transparent 70%);animation-delay:-5s}
            @keyframes orbF{0%,100%{transform:translate(0,0) scale(1)}25%{transform:translate(40px,-30px) scale(1.05)}50%{transform:translate(-20px,20px) scale(.95)}75%{transform:translate(30px,40px) scale(1.08)}}
            .auth-wrap{position:relative;z-index:1;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
            .auth-card{display:grid;grid-template-columns:1fr 1.2fr;max-width:960px;width:100%;border-radius:28px;overflow:hidden;border:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.025);backdrop-filter:blur(40px);box-shadow:0 30px 100px -20px rgba(0,0,0,.5);animation:cardIn .8s cubic-bezier(.16,1,.3,1)}
            @keyframes cardIn{from{opacity:0;transform:translateY(30px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}
            @media(max-width:768px){.auth-card{grid-template-columns:1fr;max-width:500px}}
            .brand{padding:52px 44px;display:flex;flex-direction:column;justify-content:center;position:relative;overflow:hidden;background:linear-gradient(145deg,rgba(99,102,241,.08),rgba(139,92,246,.03));border-right:1px solid rgba(255,255,255,.05)}
            .brand::before{content:'';position:absolute;top:0;left:10%;right:10%;height:1px;background:linear-gradient(90deg,transparent,rgba(99,102,241,.4),transparent)}
            .brand::after{content:'';position:absolute;bottom:30px;right:-30px;width:120px;height:120px;border-radius:50%;background:radial-gradient(circle,rgba(99,102,241,.1),transparent 70%);filter:blur(30px)}
            @media(max-width:768px){.brand{padding:36px 28px;border-right:none;border-bottom:1px solid rgba(255,255,255,.05)}}
            .b-logo{display:flex;align-items:center;gap:12px;margin-bottom:40px}
            .b-logo-i{width:42px;height:42px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border-radius:13px;display:flex;align-items:center;justify-content:center;font-size:16px;color:#fff;box-shadow:0 0 20px rgba(99,102,241,.35)}
            .b-logo-t{font-size:21px;font-weight:800;color:#fff;letter-spacing:-.5px}
            .b-logo-t span{color:#818cf8}
            .b-icon{width:76px;height:76px;border-radius:22px;background:linear-gradient(135deg,rgba(99,102,241,.18),rgba(139,92,246,.12));display:flex;align-items:center;justify-content:center;font-size:30px;color:#818cf8;margin-bottom:28px;box-shadow:0 0 40px rgba(99,102,241,.12);animation:glow 4s ease-in-out infinite}
            @keyframes glow{0%,100%{box-shadow:0 0 40px rgba(99,102,241,.12)}50%{box-shadow:0 0 60px rgba(99,102,241,.22)}}
            .b-h{font-size:25px;font-weight:800;color:#f1f5f9;margin-bottom:10px;letter-spacing:-.5px;line-height:1.25}
            .b-p{font-size:14px;color:#64748b;line-height:1.75;margin-bottom:32px}
            .chips{display:flex;flex-wrap:wrap;gap:8px}
            .chip{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:999px;font-size:11px;font-weight:600;background:rgba(99,102,241,.08);border:1px solid rgba(99,102,241,.18);color:#a5b4fc;transition:all .3s}
            .chip:hover{background:rgba(99,102,241,.15);border-color:rgba(99,102,241,.3);transform:translateY(-1px)}
            .chip i{font-size:9px}
            .fpanel{padding:44px 40px;display:flex;flex-direction:column;justify-content:center}
            @media(max-width:768px){.fpanel{padding:32px 24px}}
            .f-h{font-size:24px;font-weight:800;color:#f1f5f9;margin-bottom:6px;letter-spacing:-.5px}
            .f-sub{font-size:13px;color:#64748b;margin-bottom:28px}
            .err{background:rgba(244,63,94,.08);border:1px solid rgba(244,63,94,.18);color:#fb7185;padding:12px 16px;border-radius:12px;font-size:13px;font-weight:500;text-align:center;margin-bottom:20px;display:none}
            .err.show{display:block;animation:shake .4s ease}
            @keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-8px)}40%{transform:translateX(8px)}60%{transform:translateX(-4px)}80%{transform:translateX(4px)}}
            .fld{margin-bottom:18px}
            .fld-l{display:block;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px}
            .fgrid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
            @media(max-width:480px){.fgrid{grid-template-columns:1fr}}
            .iw{position:relative}
            .fi{width:100%;padding:13px 16px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:14px;color:#e2e8f0;font-size:14px;font-family:'Inter',sans-serif;outline:none;transition:all .3s}
            .fi:focus{border-color:rgba(99,102,241,.45);box-shadow:0 0 0 3px rgba(99,102,241,.08),0 0 24px rgba(99,102,241,.06);background:rgba(255,255,255,.06)}
            .fi::placeholder{color:#3f4a5c}
            .fsel{width:100%;padding:13px 16px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:14px;color:#e2e8f0;font-size:14px;font-family:'Inter',sans-serif;outline:none;transition:all .3s;appearance:none;cursor:pointer}
            .fsel:focus{border-color:rgba(99,102,241,.45);box-shadow:0 0 0 3px rgba(99,102,241,.08);background:rgba(255,255,255,.06)}
            .fsel option{background:#1e293b;color:#e2e8f0}
            .pw-t{position:absolute;top:50%;right:16px;transform:translateY(-50%);background:none;border:none;color:#3f4a5c;cursor:pointer;font-size:14px;padding:4px;transition:color .2s}
            .pw-t:hover{color:#818cf8}
            .sbtn{width:100%;padding:15px;margin-top:6px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none;border-radius:14px;font-size:14px;font-weight:700;font-family:'Inter',sans-serif;cursor:pointer;letter-spacing:.3px;transition:all .3s cubic-bezier(.23,1,.32,1);box-shadow:0 4px 24px rgba(99,102,241,.25);position:relative;overflow:hidden}
            .sbtn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,transparent 30%,rgba(255,255,255,.1) 50%,transparent 70%);transform:translateX(-100%);transition:transform .6s}
            .sbtn:hover::after{transform:translateX(100%)}
            .sbtn:hover:not(:disabled){box-shadow:0 8px 40px rgba(99,102,241,.4);transform:translateY(-2px)}
            .sbtn:disabled{opacity:.6;cursor:not-allowed}
            .alt{text-align:center;margin-top:24px;font-size:13px;color:#64748b}
            .alt a{color:#818cf8;font-weight:600;text-decoration:none;transition:color .2s}
            .alt a:hover{color:#a5b4fc}
            .bk{position:fixed;top:28px;left:28px;z-index:10;display:inline-flex;align-items:center;gap:8px;color:#475569;font-size:13px;font-weight:500;text-decoration:none;transition:all .2s;padding:8px 16px;border-radius:12px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}
            .bk:hover{color:#818cf8;background:rgba(99,102,241,.06);border-color:rgba(99,102,241,.15)}
        </style>
    </head>
    <body>
        <div class="mesh-bg"></div>
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
        <div class="orb orb-3"></div>
        <a href="/" class="bk"><i class="fas fa-arrow-left"></i> Home</a>
        <div class="auth-wrap">
            <div class="auth-card">
                <div class="brand">
                    <div class="b-logo"><div class="b-logo-i"><i class="fas fa-qrcode"></i></div><div class="b-logo-t">Attend<span>X</span></div></div>
                    <div class="b-icon"><i class="fas fa-user-plus"></i></div>
                    <div class="b-h">Join as Instructor</div>
                    <div class="b-p">Create your instructor account to start managing classes and tracking attendance with GPS-verified QR codes.</div>
                    <div class="chips">
                        <div class="chip"><i class="fas fa-plus-circle"></i> Create Subjects</div>
                        <div class="chip"><i class="fas fa-qrcode"></i> Generate QR</div>
                        <div class="chip"><i class="fas fa-chart-line"></i> Live Monitoring</div>
                        <div class="chip"><i class="fas fa-download"></i> Export Data</div>
                    </div>
                </div>
                <div class="fpanel">
                    <div class="f-h">Create Account</div>
                    <div class="f-sub">Register as an instructor to get started</div>
                    <form id="signupForm">
                        <div id="errorMsg" class="err"></div>
                        <div class="fgrid">
                            <div class="fld">
                                <label class="fld-l">Full Name *</label>
                                <input type="text" id="name" class="fi" placeholder="John Doe" required>
                            </div>
                            <div class="fld">
                                <label class="fld-l">Phone</label>
                                <input type="tel" id="phone" class="fi" placeholder="+91 98765 43210">
                            </div>
                        </div>
                        <div class="fgrid">
                            <div class="fld">
                                <label class="fld-l">Username *</label>
                                <input type="text" id="username" class="fi" placeholder="Unique ID" required>
                            </div>
                            <div class="fld">
                                <label class="fld-l">Gender</label>
                                <select id="gender" class="fsel">
                                    <option value="">Prefer not to say</option>
                                    <option value="Male">Male</option>
                                    <option value="Female">Female</option>
                                    <option value="Other">Other</option>
                                </select>
                            </div>
                        </div>
                        <div class="fld">
                            <label class="fld-l">Password *</label>
                            <div class="iw">
                                <input type="password" id="password" minlength="6" class="fi" placeholder="At least 6 characters" required>
                                <button type="button" class="pw-t" onclick="togglePw(this)"><i class="fas fa-eye"></i></button>
                            </div>
                        </div>
                        <div class="fld">
                            <label class="fld-l">Confirm Password *</label>
                            <div class="iw">
                                <input type="password" id="confirmPassword" minlength="6" class="fi" placeholder="Must match password" required>
                            </div>
                        </div>
                        <button type="submit" id="submitBtn" class="sbtn">Create Account</button>
                    </form>
                    <div class="alt">Already have an account? <a href="/teacher/login">Sign in</a></div>
                </div>
            </div>
        </div>
        <script>
            function togglePw(b){var i=b.parentElement.querySelector('input'),c=b.querySelector('i');if(i.type==='password'){i.type='text';c.className='fas fa-eye-slash'}else{i.type='password';c.className='fas fa-eye'}}
            document.getElementById('signupForm').addEventListener('submit',async function(e){
                e.preventDefault();
                var btn=document.getElementById('submitBtn');
                var err=document.getElementById('errorMsg');
                var pwd=document.getElementById('password').value;
                var confirmPwd=document.getElementById('confirmPassword').value;
                if(pwd!==confirmPwd){err.textContent='Passwords do not match';err.classList.add('show');return;}
                btn.disabled=true;
                btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Creating...';
                err.classList.remove('show');
                try{
                    var res=await axios.post('/api/teacher/signup',{
                        name:document.getElementById('name').value,
                        phone:document.getElementById('phone').value,
                        username:document.getElementById('username').value,
                        gender:document.getElementById('gender').value,
                        password:pwd
                    });
                    if(res.data.success){
                        btn.innerHTML='<i class="fas fa-check"></i> Account Created!';
                        btn.style.background='linear-gradient(135deg,#10b981,#06b6d4)';
                        setTimeout(function(){window.location.href='/teacher/login';},1200);
                    }
                }catch(error){
                    err.textContent=error.response?.data?.error||'Signup failed. Please try again.';
                    err.classList.add('show');
                    btn.disabled=false;
                    btn.innerHTML='Create Account';
                }
            });
        <\/script>
    </body>
    </html>
    `);
});


// â”€â”€ Student Login Page â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ── Student Login Page ───────────────────────────────────────────────
app.get('/student/login', (c) => {
    return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Student Sign In — AttendX</title>
        <meta name="description" content="Sign in to the AttendX student portal to mark attendance.">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"><\/script>
        <style>
            *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
            body{font-family:'Inter',sans-serif;background:#080b14;color:#e2e8f0;min-height:100vh;overflow-x:hidden}
            .mesh-bg{position:fixed;inset:0;z-index:0;background:radial-gradient(ellipse 80% 60% at 20% 10%,rgba(16,185,129,.15) 0%,transparent 60%),radial-gradient(ellipse 60% 50% at 80% 80%,rgba(6,182,212,.1) 0%,transparent 55%),#080b14}
            .orb{position:fixed;border-radius:50%;filter:blur(100px);pointer-events:none;z-index:0;animation:orbF 25s ease-in-out infinite}
            .orb-1{width:450px;height:450px;top:-120px;left:-100px;background:radial-gradient(circle,rgba(16,185,129,.3),transparent 70%)}
            .orb-2{width:350px;height:350px;bottom:-80px;right:-60px;background:radial-gradient(circle,rgba(6,182,212,.25),transparent 70%);animation-delay:-10s}
            .orb-3{width:200px;height:200px;top:40%;left:60%;background:radial-gradient(circle,rgba(16,185,129,.12),transparent 70%);animation-delay:-5s}
            @keyframes orbF{0%,100%{transform:translate(0,0) scale(1)}25%{transform:translate(40px,-30px) scale(1.05)}50%{transform:translate(-20px,20px) scale(.95)}75%{transform:translate(30px,40px) scale(1.08)}}
            .auth-wrap{position:relative;z-index:1;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
            .auth-card{display:grid;grid-template-columns:1fr 1fr;max-width:920px;width:100%;border-radius:28px;overflow:hidden;border:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.025);backdrop-filter:blur(40px);box-shadow:0 30px 100px -20px rgba(0,0,0,.5);animation:cardIn .8s cubic-bezier(.16,1,.3,1)}
            @keyframes cardIn{from{opacity:0;transform:translateY(30px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}
            @media(max-width:768px){.auth-card{grid-template-columns:1fr;max-width:480px}}
            .brand{padding:52px 44px;display:flex;flex-direction:column;justify-content:center;position:relative;overflow:hidden;background:linear-gradient(145deg,rgba(16,185,129,.08),rgba(6,182,212,.03));border-right:1px solid rgba(255,255,255,.05)}
            .brand::before{content:'';position:absolute;top:0;left:10%;right:10%;height:1px;background:linear-gradient(90deg,transparent,rgba(16,185,129,.4),transparent)}
            .brand::after{content:'';position:absolute;bottom:30px;right:-30px;width:120px;height:120px;border-radius:50%;background:radial-gradient(circle,rgba(16,185,129,.1),transparent 70%);filter:blur(30px)}
            @media(max-width:768px){.brand{padding:36px 28px;border-right:none;border-bottom:1px solid rgba(255,255,255,.05)}}
            .b-logo{display:flex;align-items:center;gap:12px;margin-bottom:40px}
            .b-logo-i{width:42px;height:42px;background:linear-gradient(135deg,#10b981,#06b6d4);border-radius:13px;display:flex;align-items:center;justify-content:center;font-size:16px;color:#fff;box-shadow:0 0 20px rgba(16,185,129,.35)}
            .b-logo-t{font-size:21px;font-weight:800;color:#fff;letter-spacing:-.5px}
            .b-logo-t span{color:#34d399}
            .b-icon{width:76px;height:76px;border-radius:22px;background:linear-gradient(135deg,rgba(16,185,129,.18),rgba(6,182,212,.12));display:flex;align-items:center;justify-content:center;font-size:30px;color:#34d399;margin-bottom:28px;box-shadow:0 0 40px rgba(16,185,129,.12);animation:glow 4s ease-in-out infinite}
            @keyframes glow{0%,100%{box-shadow:0 0 40px rgba(16,185,129,.12)}50%{box-shadow:0 0 60px rgba(16,185,129,.22)}}
            .b-h{font-size:25px;font-weight:800;color:#f1f5f9;margin-bottom:10px;letter-spacing:-.5px;line-height:1.25}
            .b-p{font-size:14px;color:#64748b;line-height:1.75;margin-bottom:32px}
            .chips{display:flex;flex-wrap:wrap;gap:8px}
            .chip{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:999px;font-size:11px;font-weight:600;background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.18);color:#6ee7b7;transition:all .3s}
            .chip:hover{background:rgba(16,185,129,.15);border-color:rgba(16,185,129,.3);transform:translateY(-1px)}
            .chip i{font-size:9px}
            .fpanel{padding:52px 44px;display:flex;flex-direction:column;justify-content:center}
            @media(max-width:768px){.fpanel{padding:36px 28px}}
            .f-h{font-size:26px;font-weight:800;color:#f1f5f9;margin-bottom:6px;letter-spacing:-.5px}
            .f-sub{font-size:13px;color:#64748b;margin-bottom:32px}
            .err{background:rgba(244,63,94,.08);border:1px solid rgba(244,63,94,.18);color:#fb7185;padding:12px 16px;border-radius:12px;font-size:13px;font-weight:500;text-align:center;margin-bottom:20px;display:none}
            .err.show{display:block;animation:shake .4s ease}
            @keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-8px)}40%{transform:translateX(8px)}60%{transform:translateX(-4px)}80%{transform:translateX(4px)}}
            .fld{margin-bottom:22px}
            .fld-l{display:block;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px}
            .iw{position:relative}
            .ii{position:absolute;top:50%;left:16px;transform:translateY(-50%);color:#3f4a5c;font-size:14px;pointer-events:none;transition:color .3s}
            .fi{width:100%;padding:14px 16px 14px 46px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:14px;color:#e2e8f0;font-size:14px;font-family:'Inter',sans-serif;outline:none;transition:all .3s}
            .fi:focus{border-color:rgba(16,185,129,.45);box-shadow:0 0 0 3px rgba(16,185,129,.08),0 0 24px rgba(16,185,129,.06);background:rgba(255,255,255,.06)}
            .fi:focus~.ii{color:#34d399}
            .fi::placeholder{color:#3f4a5c}
            .pw-t{position:absolute;top:50%;right:16px;transform:translateY(-50%);background:none;border:none;color:#3f4a5c;cursor:pointer;font-size:14px;padding:4px;transition:color .2s}
            .pw-t:hover{color:#34d399}
            .sbtn{width:100%;padding:15px;margin-top:4px;background:linear-gradient(135deg,#10b981,#06b6d4);color:#fff;border:none;border-radius:14px;font-size:14px;font-weight:700;font-family:'Inter',sans-serif;cursor:pointer;letter-spacing:.3px;transition:all .3s cubic-bezier(.23,1,.32,1);box-shadow:0 4px 24px rgba(16,185,129,.25);position:relative;overflow:hidden}
            .sbtn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,transparent 30%,rgba(255,255,255,.1) 50%,transparent 70%);transform:translateX(-100%);transition:transform .6s}
            .sbtn:hover::after{transform:translateX(100%)}
            .sbtn:hover:not(:disabled){box-shadow:0 8px 40px rgba(16,185,129,.4);transform:translateY(-2px)}
            .sbtn:active:not(:disabled){transform:translateY(0)}
            .sbtn:disabled{opacity:.6;cursor:not-allowed}
            .alt{text-align:center;margin-top:28px;font-size:13px;color:#64748b}
            .alt a{color:#34d399;font-weight:600;text-decoration:none;transition:color .2s}
            .alt a:hover{color:#6ee7b7}
            .bk{position:fixed;top:28px;left:28px;z-index:10;display:inline-flex;align-items:center;gap:8px;color:#475569;font-size:13px;font-weight:500;text-decoration:none;transition:all .2s;padding:8px 16px;border-radius:12px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}
            .bk:hover{color:#34d399;background:rgba(16,185,129,.06);border-color:rgba(16,185,129,.15)}
        </style>
    </head>
    <body>
        <div class="mesh-bg"></div>
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
        <div class="orb orb-3"></div>
        <a href="/" class="bk"><i class="fas fa-arrow-left"></i> Home</a>
        <div class="auth-wrap">
            <div class="auth-card">
                <div class="brand">
                    <div class="b-logo"><div class="b-logo-i"><i class="fas fa-qrcode"></i></div><div class="b-logo-t">Attend<span>X</span></div></div>
                    <div class="b-icon"><i class="fas fa-user-graduate"></i></div>
                    <div class="b-h">Student Portal</div>
                    <div class="b-p">Sign in with your Roll Number to scan QR codes, mark attendance, and track your attendance history.</div>
                    <div class="chips">
                        <div class="chip"><i class="fas fa-qrcode"></i> Scan QR Code</div>
                        <div class="chip"><i class="fas fa-map-marker-alt"></i> GPS Verified</div>
                        <div class="chip"><i class="fas fa-history"></i> Track History</div>
                        <div class="chip"><i class="fas fa-bolt"></i> Instant Marking</div>
                    </div>
                </div>
                <div class="fpanel">
                    <div class="f-h">Welcome Back</div>
                    <div class="f-sub">Sign in with your Roll No to mark attendance</div>
                    <form id="loginForm">
                        <div id="errorMsg" class="err"></div>
                        <div class="fld">
                            <label class="fld-l">Roll Number</label>
                            <div class="iw">
                                <input type="text" id="roll_no" class="fi" placeholder="e.g. CS2101001" required>
                                <i class="fas fa-id-card ii"></i>
                            </div>
                        </div>
                        <div class="fld">
                            <label class="fld-l">Password</label>
                            <div class="iw">
                                <input type="password" id="password" class="fi" placeholder="Enter your password" required>
                                <i class="fas fa-lock ii"></i>
                                <button type="button" class="pw-t" onclick="togglePw(this)"><i class="fas fa-eye"></i></button>
                            </div>
                        </div>
                        <button type="submit" id="submitBtn" class="sbtn">Sign In</button>
                    </form>
                    <div class="alt">New student? <a href="/student/signup">Create account</a></div>
                </div>
            </div>
        </div>
        <script>
            function togglePw(b){var i=b.parentElement.querySelector('input'),c=b.querySelector('i');if(i.type==='password'){i.type='text';c.className='fas fa-eye-slash'}else{i.type='password';c.className='fas fa-eye'}}
            document.getElementById('loginForm').addEventListener('submit',async function(e){
                e.preventDefault();
                var btn=document.getElementById('submitBtn');
                var err=document.getElementById('errorMsg');
                btn.disabled=true;
                btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Signing in...';
                err.classList.remove('show');
                try{
                    var res=await axios.post('/api/student/login',{roll_no:document.getElementById('roll_no').value.trim(),password:document.getElementById('password').value});
                    if(res.data.success){btn.innerHTML='<i class="fas fa-check"></i> Success!';window.location.href='/student';}
                }catch(error){
                    err.textContent=error.response?.data?.error||'Login failed. Please try again.';
                    err.classList.add('show');
                    btn.disabled=false;
                    btn.innerHTML='Sign In';
                }
            });
        <\/script>
    </body>
    </html>
    `);
});


// â”€â”€ Student Signup Page â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ── Student Signup Page ──────────────────────────────────────────────
app.get('/student/signup', (c) => {
    return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Student Sign Up — AttendX</title>
        <meta name="description" content="Create a student account on AttendX to mark attendance.">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"><\/script>
        <style>
            *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
            body{font-family:'Inter',sans-serif;background:#080b14;color:#e2e8f0;min-height:100vh;overflow-x:hidden}
            .mesh-bg{position:fixed;inset:0;z-index:0;background:radial-gradient(ellipse 80% 60% at 20% 10%,rgba(16,185,129,.15) 0%,transparent 60%),radial-gradient(ellipse 60% 50% at 80% 80%,rgba(6,182,212,.1) 0%,transparent 55%),#080b14}
            .orb{position:fixed;border-radius:50%;filter:blur(100px);pointer-events:none;z-index:0;animation:orbF 25s ease-in-out infinite}
            .orb-1{width:450px;height:450px;top:-120px;left:-100px;background:radial-gradient(circle,rgba(16,185,129,.3),transparent 70%)}
            .orb-2{width:350px;height:350px;bottom:-80px;right:-60px;background:radial-gradient(circle,rgba(6,182,212,.25),transparent 70%);animation-delay:-10s}
            .orb-3{width:200px;height:200px;top:40%;left:60%;background:radial-gradient(circle,rgba(16,185,129,.12),transparent 70%);animation-delay:-5s}
            @keyframes orbF{0%,100%{transform:translate(0,0) scale(1)}25%{transform:translate(40px,-30px) scale(1.05)}50%{transform:translate(-20px,20px) scale(.95)}75%{transform:translate(30px,40px) scale(1.08)}}
            .auth-wrap{position:relative;z-index:1;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
            .auth-card{display:grid;grid-template-columns:1fr 1.2fr;max-width:980px;width:100%;border-radius:28px;overflow:hidden;border:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.025);backdrop-filter:blur(40px);box-shadow:0 30px 100px -20px rgba(0,0,0,.5);animation:cardIn .8s cubic-bezier(.16,1,.3,1)}
            @keyframes cardIn{from{opacity:0;transform:translateY(30px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}
            @media(max-width:768px){.auth-card{grid-template-columns:1fr;max-width:500px}}
            .brand{padding:52px 44px;display:flex;flex-direction:column;justify-content:center;position:relative;overflow:hidden;background:linear-gradient(145deg,rgba(16,185,129,.08),rgba(6,182,212,.03));border-right:1px solid rgba(255,255,255,.05)}
            .brand::before{content:'';position:absolute;top:0;left:10%;right:10%;height:1px;background:linear-gradient(90deg,transparent,rgba(16,185,129,.4),transparent)}
            .brand::after{content:'';position:absolute;bottom:30px;right:-30px;width:120px;height:120px;border-radius:50%;background:radial-gradient(circle,rgba(16,185,129,.1),transparent 70%);filter:blur(30px)}
            @media(max-width:768px){.brand{padding:36px 28px;border-right:none;border-bottom:1px solid rgba(255,255,255,.05)}}
            .b-logo{display:flex;align-items:center;gap:12px;margin-bottom:40px}
            .b-logo-i{width:42px;height:42px;background:linear-gradient(135deg,#10b981,#06b6d4);border-radius:13px;display:flex;align-items:center;justify-content:center;font-size:16px;color:#fff;box-shadow:0 0 20px rgba(16,185,129,.35)}
            .b-logo-t{font-size:21px;font-weight:800;color:#fff;letter-spacing:-.5px}
            .b-logo-t span{color:#34d399}
            .b-icon{width:76px;height:76px;border-radius:22px;background:linear-gradient(135deg,rgba(16,185,129,.18),rgba(6,182,212,.12));display:flex;align-items:center;justify-content:center;font-size:30px;color:#34d399;margin-bottom:28px;box-shadow:0 0 40px rgba(16,185,129,.12);animation:glow 4s ease-in-out infinite}
            @keyframes glow{0%,100%{box-shadow:0 0 40px rgba(16,185,129,.12)}50%{box-shadow:0 0 60px rgba(16,185,129,.22)}}
            .b-h{font-size:25px;font-weight:800;color:#f1f5f9;margin-bottom:10px;letter-spacing:-.5px;line-height:1.25}
            .b-p{font-size:14px;color:#64748b;line-height:1.75;margin-bottom:32px}
            .chips{display:flex;flex-wrap:wrap;gap:8px}
            .chip{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:999px;font-size:11px;font-weight:600;background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.18);color:#6ee7b7;transition:all .3s}
            .chip:hover{background:rgba(16,185,129,.15);border-color:rgba(16,185,129,.3);transform:translateY(-1px)}
            .chip i{font-size:9px}
            .fpanel{padding:44px 40px;display:flex;flex-direction:column;justify-content:center}
            @media(max-width:768px){.fpanel{padding:32px 24px}}
            .f-h{font-size:24px;font-weight:800;color:#f1f5f9;margin-bottom:6px;letter-spacing:-.5px}
            .f-sub{font-size:13px;color:#64748b;margin-bottom:28px}
            .err{background:rgba(244,63,94,.08);border:1px solid rgba(244,63,94,.18);color:#fb7185;padding:12px 16px;border-radius:12px;font-size:13px;font-weight:500;text-align:center;margin-bottom:18px;display:none}
            .err.show{display:block;animation:shake .4s ease}
            @keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-8px)}40%{transform:translateX(8px)}60%{transform:translateX(-4px)}80%{transform:translateX(4px)}}
            .fld{margin-bottom:16px}
            .fld-l{display:block;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px}
            .fgrid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
            @media(max-width:480px){.fgrid{grid-template-columns:1fr}}
            .iw{position:relative}
            .fi{width:100%;padding:12px 16px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:14px;color:#e2e8f0;font-size:14px;font-family:'Inter',sans-serif;outline:none;transition:all .3s}
            .fi:focus{border-color:rgba(16,185,129,.45);box-shadow:0 0 0 3px rgba(16,185,129,.08),0 0 24px rgba(16,185,129,.06);background:rgba(255,255,255,.06)}
            .fi::placeholder{color:#3f4a5c}
            .fsel{width:100%;padding:12px 16px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:14px;color:#e2e8f0;font-size:14px;font-family:'Inter',sans-serif;outline:none;transition:all .3s;appearance:none;cursor:pointer}
            .fsel:focus{border-color:rgba(16,185,129,.45);box-shadow:0 0 0 3px rgba(16,185,129,.08);background:rgba(255,255,255,.06)}
            .fsel option{background:#1e293b;color:#e2e8f0}
            .pw-t{position:absolute;top:50%;right:16px;transform:translateY(-50%);background:none;border:none;color:#3f4a5c;cursor:pointer;font-size:14px;padding:4px;transition:color .2s}
            .pw-t:hover{color:#34d399}
            .sbtn{width:100%;padding:15px;margin-top:6px;background:linear-gradient(135deg,#10b981,#06b6d4);color:#fff;border:none;border-radius:14px;font-size:14px;font-weight:700;font-family:'Inter',sans-serif;cursor:pointer;letter-spacing:.3px;transition:all .3s cubic-bezier(.23,1,.32,1);box-shadow:0 4px 24px rgba(16,185,129,.25);position:relative;overflow:hidden}
            .sbtn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,transparent 30%,rgba(255,255,255,.1) 50%,transparent 70%);transform:translateX(-100%);transition:transform .6s}
            .sbtn:hover::after{transform:translateX(100%)}
            .sbtn:hover:not(:disabled){box-shadow:0 8px 40px rgba(16,185,129,.4);transform:translateY(-2px)}
            .sbtn:disabled{opacity:.6;cursor:not-allowed}
            .alt{text-align:center;margin-top:22px;font-size:13px;color:#64748b}
            .alt a{color:#34d399;font-weight:600;text-decoration:none;transition:color .2s}
            .alt a:hover{color:#6ee7b7}
            .bk{position:fixed;top:28px;left:28px;z-index:10;display:inline-flex;align-items:center;gap:8px;color:#475569;font-size:13px;font-weight:500;text-decoration:none;transition:all .2s;padding:8px 16px;border-radius:12px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}
            .bk:hover{color:#34d399;background:rgba(16,185,129,.06);border-color:rgba(16,185,129,.15)}
        </style>
    </head>
    <body>
        <div class="mesh-bg"></div>
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
        <div class="orb orb-3"></div>
        <a href="/" class="bk"><i class="fas fa-arrow-left"></i> Home</a>
        <div class="auth-wrap">
            <div class="auth-card">
                <div class="brand">
                    <div class="b-logo"><div class="b-logo-i"><i class="fas fa-qrcode"></i></div><div class="b-logo-t">Attend<span>X</span></div></div>
                    <div class="b-icon"><i class="fas fa-user-plus"></i></div>
                    <div class="b-h">Join as Student</div>
                    <div class="b-p">Create your student account and start marking attendance with a single QR scan. Quick, secure, and GPS-verified.</div>
                    <div class="chips">
                        <div class="chip"><i class="fas fa-qrcode"></i> Scan QR</div>
                        <div class="chip"><i class="fas fa-map-marker-alt"></i> GPS Verified</div>
                        <div class="chip"><i class="fas fa-history"></i> View History</div>
                        <div class="chip"><i class="fas fa-mobile-alt"></i> Mobile Friendly</div>
                    </div>
                </div>
                <div class="fpanel">
                    <div class="f-h">Create Student Account</div>
                    <div class="f-sub">Fill in your details to register</div>
                    <form id="signupForm">
                        <div id="errorMsg" class="err"></div>
                        <div class="fgrid">
                            <div class="fld">
                                <label class="fld-l">Full Name *</label>
                                <input type="text" id="name" class="fi" placeholder="Ankit Kumar" required>
                            </div>
                            <div class="fld">
                                <label class="fld-l">Roll No *</label>
                                <input type="text" id="roll_no" class="fi" placeholder="CS2101001" required>
                            </div>
                        </div>
                        <div class="fgrid">
                            <div class="fld">
                                <label class="fld-l">Branch</label>
                                <input type="text" id="branch" class="fi" placeholder="Computer Science">
                            </div>
                            <div class="fld">
                                <label class="fld-l">Section</label>
                                <input type="text" id="section" class="fi" placeholder="A">
                            </div>
                        </div>
                        <div class="fgrid">
                            <div class="fld">
                                <label class="fld-l">Year</label>
                                <select id="year" class="fsel">
                                    <option value="">Select Year</option>
                                    <option value="1st Year">1st Year</option>
                                    <option value="2nd Year">2nd Year</option>
                                    <option value="3rd Year">3rd Year</option>
                                    <option value="4th Year">4th Year</option>
                                </select>
                            </div>
                            <div class="fld">
                                <label class="fld-l">Gender</label>
                                <select id="gender" class="fsel">
                                    <option value="">Prefer not to say</option>
                                    <option value="Male">Male</option>
                                    <option value="Female">Female</option>
                                    <option value="Other">Other</option>
                                </select>
                            </div>
                        </div>
                        <div class="fld">
                            <label class="fld-l">Password * <span style="text-transform:none;font-weight:400;color:#475569">(min 6 chars)</span></label>
                            <div class="iw">
                                <input type="password" id="password" minlength="6" class="fi" placeholder="Create a strong password" required>
                                <button type="button" class="pw-t" onclick="togglePw(this)"><i class="fas fa-eye"></i></button>
                            </div>
                        </div>
                        <div class="fld">
                            <label class="fld-l">Confirm Password *</label>
                            <input type="password" id="confirmPassword" minlength="6" class="fi" placeholder="Re-enter password" required>
                        </div>
                        <button type="submit" id="submitBtn" class="sbtn">Create Account</button>
                    </form>
                    <div class="alt">Already registered? <a href="/student/login">Sign in</a></div>
                </div>
            </div>
        </div>
        <script>
            function togglePw(b){var i=b.parentElement.querySelector('input'),c=b.querySelector('i');if(i.type==='password'){i.type='text';c.className='fas fa-eye-slash'}else{i.type='password';c.className='fas fa-eye'}}
            document.getElementById('signupForm').addEventListener('submit',async function(e){
                e.preventDefault();
                var btn=document.getElementById('submitBtn');
                var err=document.getElementById('errorMsg');
                var pwd=document.getElementById('password').value;
                var confirmPwd=document.getElementById('confirmPassword').value;
                if(pwd!==confirmPwd){err.textContent='Passwords do not match';err.classList.add('show');return;}
                btn.disabled=true;
                btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Creating...';
                err.classList.remove('show');
                try{
                    var res=await axios.post('/api/student/signup',{
                        name:document.getElementById('name').value.trim(),
                        roll_no:document.getElementById('roll_no').value.trim(),
                        branch:document.getElementById('branch').value.trim(),
                        section:document.getElementById('section').value.trim(),
                        year:document.getElementById('year').value,
                        gender:document.getElementById('gender').value,
                        password:pwd
                    });
                    if(res.data.success){
                        btn.innerHTML='<i class="fas fa-check"></i> Account Created!';
                        btn.style.background='linear-gradient(135deg,#10b981,#06b6d4)';
                        setTimeout(function(){window.location.href='/student/login?registered=1';},1200);
                    }
                }catch(error){
                    err.textContent=error.response?.data?.error||'Signup failed. Please try again.';
                    err.classList.add('show');
                    btn.disabled=false;
                    btn.innerHTML='Create Account';
                }
            });
        <\/script>
    </body>
    </html>
    `);
});


// â”€â”€ Student Dashboard (Scanner + History) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/student', (c) => {
    return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Student Dashboard - Attendance</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"><\/script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <!-- jsQR: reads QR from camera frames -->
        <script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js"><\/script>
        <!-- face-api.js for face detection, landmark, and recognition (runs entirely in-browser) -->
        <script src="https://cdn.jsdelivr.net/npm/face-api.js@0.22.2/dist/face-api.min.js"><\/script>
        <style>
            body {
                font-family: 'Inter', sans-serif;
            }
            .glass-effect {
                backdrop-filter: blur(16px);
                background-color: rgba(255, 255, 255, 0.04);
                border: 1px solid rgba(255, 255, 255, 0.08);
                box-shadow: 0 10px 30px -10px rgba(16, 185, 129, 0.06);
            }
            .pulse-button {
                position: relative;
                z-index: 1;
            }
            .pulse-button::after {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                border-radius: inherit;
                background: inherit;
                z-index: -1;
                opacity: 0.4;
                animation: pulse-ring 2s cubic-bezier(0.4, 0, 0.2, 1) infinite;
            }
            @keyframes pulse-ring {
                0% { transform: scale(1); opacity: 0.4; }
                100% { transform: scale(1.15); opacity: 0; }
            }
            .dot-pulse {
                position: relative;
            }
            .dot-pulse::after {
                content: '';
                position: absolute;
                width: 100%;
                height: 100%;
                top: 0;
                left: 0;
                border-radius: 50%;
                background-color: inherit;
                animation: dot-ping 1.5s cubic-bezier(0, 0, 0.2, 1) infinite;
            }
            @keyframes dot-ping {
                0% { transform: scale(1); opacity: 1; }
                100% { transform: scale(2.5); opacity: 0; }
            }
            #scannerVideo { width:100%; border-radius:16px; object-fit:cover; max-height:280px; background:#0f172a; }
            .scan-overlay { position:relative; }
            .scan-overlay::after { content:''; position:absolute; inset:0; border-radius:16px; border:3px solid rgba(16,185,129,0.6); pointer-events:none; box-shadow:inset 0 0 20px rgba(16,185,129,0.1); }
            .tag { display:inline-flex;align-items:center;gap:4px;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:600; }
            /* Face verification gate */
            #faceVideo { width:100%;max-height:220px;object-fit:cover;border-radius:14px;background:#0f172a; }
            #faceCanvas { display:none; }
            #enrollVideo { width:100%;max-height:220px;object-fit:cover;border-radius:14px;background:#0f172a; }
            #enrollCanvas { display:none; }
            .face-overlay { position:relative; }
            .face-overlay::after { content:''; position:absolute;inset:0;border-radius:14px;border:2.5px solid rgba(16,185,129,0.5);pointer-events:none; }
            .blink-ring { animation: blinkPulse 0.6s ease-out; }
            @keyframes blinkPulse { 0%{border-color:rgba(251,191,36,0.9)} 100%{border-color:rgba(16,185,129,0.5)} }
            /* Enrollment modal */
            #enrollModal { position:fixed;inset:0;z-index:999;background:rgba(0,0,0,0.8);backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center; }
            #enrollModal.hidden { display:none; }
        </style>
    </head>
    <body class="min-h-screen text-slate-100" style="background:#080b14;font-family:'Inter',sans-serif;">
        <!-- Dark background orbs -->
        <div style="position:fixed;inset:0;z-index:0;background:radial-gradient(ellipse 70% 50% at 10% 0%, rgba(16,185,129,0.15) 0%, transparent 60%),radial-gradient(ellipse 50% 40% at 90% 90%, rgba(6,182,212,0.10) 0%, transparent 55%),#080b14;pointer-events:none;"></div>
        <div style="position:relative;z-index:1;">
        <div class="container mx-auto px-4 py-8 max-w-5xl">
            <!-- Header -->
            <div class="flex flex-col md:flex-row justify-between items-center gap-4 mb-8 p-5 rounded-2xl glass-effect">
                <div class="flex items-center space-x-4">
                    <div class="w-12 h-12 rounded-2xl flex items-center justify-center text-white text-xl" style="background:linear-gradient(135deg,#10b981,#06b6d4);box-shadow:0 0 24px rgba(16,185,129,0.4);">
                        <i class="fas fa-user-graduate"></i>
                    </div>
                    <div>
                        <h1 class="text-2xl font-bold text-white tracking-tight">Student Dashboard</h1>
                        <p class="text-xs" style="color:#64748b;">Welcome, <span id="studentName" class="font-semibold" style="color:#34d399;">Loading...</span></p>
                    </div>
                </div>
                <div class="flex items-center space-x-3">
                    <span id="studentRollTag" class="text-xs font-bold px-3 py-1.5 rounded-full" style="background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.3);color:#34d399;">Roll: â€”</span>
                    <a href="/" class="text-sm transition flex items-center px-3 py-1.5 rounded-xl" style="color:#64748b;" title="Home">
                        <i class="fas fa-home"></i>
                    </a>
                    <button id="logoutBtn" class="flex items-center space-x-1.5 text-sm font-semibold px-3 py-1.5 rounded-xl transition" style="color:#f87171;background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.2);">
                        <i class="fas fa-right-from-bracket text-xs"></i>
                        <span>Sign Out</span>
                    </button>
                </div>
            </div>

            <!-- Profile and Scanner Layout -->
            <div class="grid md:grid-cols-3 gap-8 mb-8">
                <!-- Profile Card -->
                <div class="rounded-2xl p-6 md:col-span-1 flex flex-col glass-effect" id="profileCard">
                    <h2 class="text-lg font-bold mb-4 flex items-center space-x-2" style="color:#f1f5f9;">
                        <i class="fas fa-id-card" style="color:#34d399;"></i>
                        <span>Profile</span>
                    </h2>
                    <div class="space-y-4">
                        <div><span class="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">Branch</span><p id="pBranch" class="font-semibold text-slate-200">â€”</p></div>
                        <div><span class="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">Section</span><p id="pSection" class="font-semibold text-slate-200">â€”</p></div>
                        <div><span class="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">Year</span><p id="pYear" class="font-semibold text-slate-200">â€”</p></div>
                        <div><span class="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">Gender</span><p id="pGender" class="font-semibold text-slate-200">â€”</p></div>
                    </div>
                </div>

                <!-- Face Verification Gate + QR Scanner -->
                <div class="rounded-2xl p-6 md:col-span-2 flex flex-col justify-between glass-effect">
                    <div>
                        <h2 class="text-lg font-bold mb-3 flex items-center space-x-2" style="color:#f1f5f9;">
                            <i class="fas fa-user-shield" style="color:#34d399;"></i>
                            <span>Verify Identity & Scan QR</span>
                        </h2>
                        <p class="text-sm mb-4 leading-relaxed" style="color:#64748b;">
                            First verify your identity with your face, then scan the teacher's QR code to mark attendance.
                        </p>
                    </div>

                    <!-- ── Step 1: Face Verification Gate ── -->
                    <div id="faceGate">
                        <!-- Loading face-api models -->
                        <div id="faceLoading" class="text-center py-6 text-sm" style="color:#64748b;background:rgba(255,255,255,0.02);border:1px dashed rgba(255,255,255,0.1);border-radius:14px;">
                            <i class="fas fa-spinner fa-spin text-2xl mb-2 block"></i>
                            Loading face recognition models...
                        </div>
                        <!-- Camera view for face verification -->
                        <div id="faceView" class="hidden">
                           <div class="face-overlay mb-3" id="faceOverlay">
                               <video id="faceVideo" autoplay playsinline muted></video>
                               <canvas id="faceCanvas"></canvas>
                           </div>
                           <div id="faceStatus" class="text-center text-xs mb-3 font-semibold" style="color:#94a3b8;">
                               <i class="fas fa-eye mr-1"></i> Look at the camera and blink once...
                           </div>
                           <div id="faceProgress" class="w-full h-1.5 rounded-full mb-3" style="background:rgba(255,255,255,0.08);">
                               <div id="faceProgressBar" class="h-full rounded-full transition-all" style="width:0%;background:linear-gradient(90deg,#10b981,#06b6d4);"></div>
                           </div>
                        </div>
                        <!-- Not enrolled prompt -->
                        <div id="faceNotEnrolled" class="hidden text-center py-5" style="background:rgba(251,191,36,0.07);border:1px solid rgba(251,191,36,0.2);border-radius:14px;">
                            <i class="fas fa-face-smile-beam text-3xl mb-2" style="color:#fbbf24;"></i>
                            <p class="text-sm font-bold mb-1" style="color:#fbbf24;">Face Not Enrolled</p>
                            <p class="text-xs mb-3" style="color:#94a3b8;">Enroll your face once so we can verify it's really you before each attendance.</p>
                            <button id="openEnrollBtn" class="text-xs font-bold px-4 py-2 rounded-xl transition" style="background:rgba(251,191,36,0.15);border:1px solid rgba(251,191,36,0.3);color:#fbbf24;">
                                <i class="fas fa-camera mr-1"></i> Enroll My Face
                            </button>
                        </div>
                        <!-- Face verified badge -->
                        <div id="faceVerifiedBadge" class="hidden text-center py-3 mb-3 rounded-xl" style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);">
                            <i class="fas fa-circle-check text-2xl mb-1" style="color:#34d399;"></i>
                            <p class="text-sm font-bold" style="color:#34d399;">Identity Verified!</p>
                            <p class="text-xs mt-0.5" style="color:#64748b;">Face matched — QR scanner is now active below.</p>
                        </div>
                    </div>

                    <!-- ── Step 2: QR Scanner (shown after face verified) ── -->
                    <div id="qrGate" class="hidden mt-4">
                        <div class="border-t mb-4" style="border-color:rgba(255,255,255,0.08);"></div>
                        <h3 class="text-sm font-bold mb-3 flex items-center gap-2" style="color:#f1f5f9;">
                            <i class="fas fa-qrcode" style="color:#34d399;"></i> Scan QR Code
                        </h3>
                        <div id="cameraStatus" class="text-center py-6 text-sm text-slate-500" style="background:rgba(255,255,255,0.02);border:1px dashed rgba(255,255,255,0.1);border-radius:16px;">
                            <i class="fas fa-camera text-3xl mb-3 block opacity-30"></i>
                            Camera not started
                        </div>
                        <div id="scannerWrap" class="scan-overlay hidden mb-4">
                            <video id="scannerVideo" autoplay playsinline muted></video>
                            <canvas id="scanCanvas" class="hidden"></canvas>
                        </div>
                        <div id="scanResult" class="hidden rounded-xl p-4 text-sm font-medium text-center mb-4"></div>
                        <div class="flex gap-3 mt-4">
                            <button id="startCameraBtn" class="pulse-button flex-1 bg-gradient-to-r from-emerald-500 to-teal-600 text-white py-3.5 rounded-xl font-bold text-sm shadow-lg shadow-emerald-500/20 hover:-translate-y-0.5 transition-all flex items-center justify-center gap-2">
                                <i class="fas fa-camera"></i> Start Camera
                            </button>
                            <button id="stopCameraBtn" class="hidden flex-1 border border-rose-500/50 text-rose-400 py-3 rounded-xl font-bold text-sm hover:bg-rose-500/10 transition flex items-center justify-center gap-2">
                                <i class="fas fa-stop"></i> Stop
                            </button>
                        </div>
                        <p class="text-center text-xs mt-4 flex items-center justify-center gap-1.5" style="color:#64748b;">
                            <i class="fas fa-map-marker-alt text-rose-400"></i>
                            Location is required to verify you're within 80m of the classroom.
                        </p>
                    </div>
                </div>
            </div>

            <!-- Face Enrollment Modal -->
            <div id="enrollModal" class="hidden">
                <div class="rounded-2xl p-6 w-full max-w-md mx-4" style="background:#0f172a;border:1px solid rgba(255,255,255,0.1);">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-lg font-bold text-white flex items-center gap-2">
                            <i class="fas fa-camera-retro" style="color:#34d399;"></i> Enroll Your Face
                        </h3>
                        <button id="closeEnrollModal" class="text-slate-400 hover:text-white transition">
                            <i class="fas fa-times text-lg"></i>
                        </button>
                    </div>
                    <p class="text-sm mb-4" style="color:#64748b;">
                        Face enrollment is a one-time step. Your face descriptor (128 numbers) is stored securely — never a photo.
                    </p>
                    <div class="face-overlay mb-3">
                        <video id="enrollVideo" autoplay playsinline muted></video>
                        <canvas id="enrollCanvas"></canvas>
                    </div>
                    <div id="enrollStatus" class="text-center text-xs mb-3 font-semibold" style="color:#94a3b8;">
                       <i class="fas fa-spinner fa-spin mr-1"></i> Position your face clearly in the frame...
                    </div>
                    <div id="enrollProgress" class="w-full h-2 rounded-full mb-4" style="background:rgba(255,255,255,0.08);">
                        <div id="enrollProgressBar" class="h-full rounded-full transition-all" style="width:0%;background:linear-gradient(90deg,#10b981,#06b6d4);"></div>
                    </div>
                    <button id="enrollCaptureBtn" class="w-full py-3 rounded-xl font-bold text-sm text-white transition" style="background:linear-gradient(135deg,#10b981,#06b6d4);opacity:0.5;cursor:not-allowed;" disabled>
                        <i class="fas fa-check-circle mr-1"></i> Capture & Enroll Face
                    </button>
                </div>
            </div>

            <!-- Attendance History -->
            <div class="rounded-2xl p-6 glass-effect">
                <h2 class="text-lg font-bold mb-6 flex items-center space-x-2" style="color:#f1f5f9;">
                    <i class="fas fa-history" style="color:#34d399;"></i>
                    <span>Attendance History</span>
                </h2>
                <div id="historyList">
                    <div class="text-center text-sm py-8" style="color:#64748b;">
                        <i class="fas fa-spinner fa-spin text-2xl mb-2 block"></i> Loading...
                    </div>
                </div>
            </div>
        </div>
        </div>

        <script>
            // ── Global State ─────────────────────────────────────────────────────
            let studentData = null;
            let stream = null;
            let scanInterval = null;
            let scanning = false;
            let scanCooldown = false;

            // face-api state
            let faceModelsLoaded = false;
            let faceStream = null;
            let faceToken = null;          // short-lived HMAC token from /api/face/verify
            let blinkDetected = false;
            let faceVerified = false;
            let prevEAR = 1.0;             // previous eye aspect ratio (for blink detection)
            let faceCheckInterval = null;

            // enrollment state
            let enrollStream = null;
            let enrollDescriptors = [];    // collected descriptors for averaging

            // Persistent client ID for device fingerprinting
            if (!localStorage.getItem('clientId')) {
                localStorage.setItem('clientId', crypto.randomUUID ? crypto.randomUUID() : (Math.random().toString(36).slice(2) + Date.now()));
            }
            const clientId = localStorage.getItem('clientId');

            // ── Face API Helpers ──────────────────────────────────────────────────
            // Eye Aspect Ratio (EAR): low value = eye closed = blink
            function eyeAspectRatio(eye) {
                // eye = array of 6 landmark points {x,y}
                const A = Math.hypot(eye[1].x - eye[5].x, eye[1].y - eye[5].y);
                const B = Math.hypot(eye[2].x - eye[4].x, eye[2].y - eye[4].y);
                const C = Math.hypot(eye[0].x - eye[3].x, eye[0].y - eye[3].y);
                return (A + B) / (2.0 * C);
            }

            // Load face-api models from CDN
            async function loadFaceModels() {
                const MODEL_URL = 'https://cdn.jsdelivr.net/gh/justadudewhohacks/face-api.js@0.22.2/weights';
                try {
                    await Promise.all([
                        faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
                        faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
                        faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL),
                    ]);
                    faceModelsLoaded = true;
                    return true;
                } catch (err) {
                    console.error('Failed to load face-api models:', err);
                    return false;
                }
            }

            // ── Face Verification Gate ────────────────────────────────────────────
            async function startFaceGate() {
                // Stop any existing stream and interval to avoid duplication/overlapping
                stopFaceCamera();

                document.getElementById('faceLoading').classList.remove('hidden');
                document.getElementById('faceView').classList.add('hidden');
                document.getElementById('faceNotEnrolled').classList.add('hidden');

                // Check face enrollment status
                let enrolled = false;
                try {
                    const statusRes = await axios.get('/api/face/status');
                    enrolled = statusRes.data.enrolled;
                } catch (e) { enrolled = false; }

                if (!enrolled) {
                    document.getElementById('faceLoading').classList.add('hidden');
                    document.getElementById('faceNotEnrolled').classList.remove('hidden');
                    return;
                }

                // Load models if not yet loaded
                if (!faceModelsLoaded) {
                    const ok = await loadFaceModels();
                    if (!ok) {
                        document.getElementById('faceLoading').innerHTML =
                            '<i class="fas fa-exclamation-triangle text-rose-400 text-2xl mb-2 block"></i>' +
                            '<p class="text-xs text-rose-400">Failed to load face models. Face verification is strictly required.</p>';
                        return;
                    }
                }

                // Start face camera
                try {
                    faceStream = await navigator.mediaDevices.getUserMedia({
                        video: { facingMode: 'user', width: 320, height: 240 },
                        audio: false
                    });
                    const vid = document.getElementById('faceVideo');
                    vid.srcObject = faceStream;
                    await vid.play();
                } catch (err) {
                    document.getElementById('faceLoading').innerHTML =
                        '<i class="fas fa-camera-slash text-rose-400 text-2xl mb-2 block"></i>' +
                        '<p class="text-xs text-rose-400">Camera permission denied. Face verification is strictly required.</p>';
                    return;
                }

                document.getElementById('faceLoading').classList.add('hidden');
                document.getElementById('faceView').classList.remove('hidden');

                // Start detection loop
                blinkDetected = false;
                prevEAR = 1.0;
                let detectCount = 0;
                const BLINK_EAR_THRESHOLD = 0.22;
                const BLINK_EAR_CONSEC = 1; // 1 frame at 150ms is highly responsive and catches normal blinks
                let earBelowCount = 0;
                let bestDescriptor = null;
                let progressFrames = 0;

                function runFaceDetection() {
                    if (faceCheckInterval) clearInterval(faceCheckInterval);
                    faceCheckInterval = setInterval(async () => {
                        if (faceVerified) { clearInterval(faceCheckInterval); return; }
                        const vid = document.getElementById('faceVideo');
                        if (!vid || vid.readyState < 2) return;

                        const detection = await faceapi
                            .detectSingleFace(vid, new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.15 }))
                            .withFaceLandmarks()
                            .withFaceDescriptor();

                        if (!detection) {
                            document.getElementById('faceStatus').innerHTML =
                                '<i class="fas fa-face-meh mr-1 text-amber-400"></i> No face detected. Move closer.';
                            return;
                        }

                        // Update progress
                        progressFrames = Math.min(progressFrames + 1, 10);
                        document.getElementById('faceProgressBar').style.width = (progressFrames * 10) + '%';

                        if (progressFrames < 10) {
                            document.getElementById('faceStatus').innerHTML =
                                '<i class="fas fa-smile mr-1 text-emerald-400"></i> Face detected! Keeping still... (' + (progressFrames * 10) + '%)';
                        } else if (!blinkDetected) {
                            document.getElementById('faceStatus').innerHTML =
                                '<i class="fas fa-eye mr-1 text-emerald-400"></i> Face detected! Blink your eyes once to verify.';
                        }

                        // Blink detection via eye landmarks
                        const lm = detection.landmarks;
                        const leftEye = lm.getLeftEye();
                        const rightEye = lm.getRightEye();
                        const ear = (eyeAspectRatio(leftEye) + eyeAspectRatio(rightEye)) / 2;

                        if (ear < BLINK_EAR_THRESHOLD) {
                            earBelowCount++;
                        } else if (earBelowCount >= BLINK_EAR_CONSEC) {
                            // Blink completed
                            blinkDetected = true;
                            earBelowCount = 0;
                            document.getElementById('faceOverlay').classList.add('blink-ring');
                            setTimeout(() => document.getElementById('faceOverlay').classList.remove('blink-ring'), 600);
                            document.getElementById('faceStatus').innerHTML =
                                '<i class="fas fa-eye mr-1 text-emerald-400"></i> Blink detected! Verifying face...';
                        } else {
                            earBelowCount = 0;
                        }

                        bestDescriptor = Array.from(detection.descriptor);

                        // Trigger verification ONLY on blink (liveness check is mandatory)
                        if (blinkDetected && bestDescriptor) {
                            clearInterval(faceCheckInterval);
                            document.getElementById('faceStatus').innerHTML =
                                '<i class="fas fa-spinner fa-spin mr-1"></i> Verifying with server...';
                            document.getElementById('faceProgressBar').style.width = '100%';
                            await serverVerifyFace(bestDescriptor, runFaceDetection);
                        }
                    }, 150); // Checks every 150ms to ensure normal human blinks are captured reliably
                }

                runFaceDetection();
            }

            async function serverVerifyFace(descriptor, retryCallback) {
                try {
                    const res = await axios.post('/api/face/verify', { descriptor });
                    if (res.data.success && res.data.face_token) {
                        faceToken = res.data.face_token;
                        faceVerified = true;
                        stopFaceCamera();
                        document.getElementById('faceView').classList.add('hidden');
                        document.getElementById('faceVerifiedBadge').classList.remove('hidden');
                        document.getElementById('qrGate').classList.remove('hidden');
                    } else {
                        document.getElementById('faceStatus').innerHTML =
                            '<i class="fas fa-circle-xmark mr-1 text-rose-400"></i> ' + (res.data.error || 'Face not matched') + ' — try again.';
                        
                        // Reset liveness tracking variables
                        blinkDetected = false;
                        progressFrames = 0;
                        earBelowCount = 0;
                        document.getElementById('faceProgressBar').style.width = '0%';

                        // Wait 2.5s to let user read error message before restarting detection loop
                        setTimeout(() => {
                            if (!faceVerified && typeof retryCallback === 'function') {
                                retryCallback();
                            }
                        }, 2500);
                    }
                } catch (e) {
                    document.getElementById('faceStatus').innerHTML =
                        '<i class="fas fa-wifi-slash mr-1 text-rose-400"></i> Verification failed. Face verification is strictly required.';
                    stopFaceCamera();
                }
            }

            function stopFaceCamera() {
                if (faceCheckInterval) { clearInterval(faceCheckInterval); faceCheckInterval = null; }
                if (faceStream) { faceStream.getTracks().forEach(t => t.stop()); faceStream = null; }
            }

            // ── Face Enrollment Modal ─────────────────────────────────────────────
            document.getElementById('openEnrollBtn').addEventListener('click', openEnrollModal);
            document.getElementById('closeEnrollModal').addEventListener('click', closeEnrollModal);

            async function openEnrollModal() {
                document.getElementById('enrollModal').classList.remove('hidden');
                enrollDescriptors = [];
                document.getElementById('enrollProgressBar').style.width = '0%';
                document.getElementById('enrollStatus').innerHTML =
                    '<i class="fas fa-spinner fa-spin mr-1"></i> Starting camera...';
                document.getElementById('enrollCaptureBtn').disabled = true;
                document.getElementById('enrollCaptureBtn').style.opacity = '0.5';
                document.getElementById('enrollCaptureBtn').style.cursor = 'not-allowed';

                if (!faceModelsLoaded) {
                    document.getElementById('enrollStatus').innerHTML =
                        '<i class="fas fa-spinner fa-spin mr-1"></i> Loading face models (first time only)...';
                    await loadFaceModels();
                }

                try {
                    enrollStream = await navigator.mediaDevices.getUserMedia({
                        video: { facingMode: 'user', width: 320, height: 240 },
                        audio: false
                    });
                    const vid = document.getElementById('enrollVideo');
                    vid.srcObject = enrollStream;
                    await vid.play();
                    startEnrollDetection();
                } catch (err) {
                    document.getElementById('enrollStatus').innerHTML =
                        '<i class="fas fa-camera-slash text-rose-400 mr-1"></i> Camera access denied.';
                }
            }

            function closeEnrollModal() {
                stopEnrollCamera();
                document.getElementById('enrollModal').classList.add('hidden');
            }

            function stopEnrollCamera() {
                if (enrollStream) { enrollStream.getTracks().forEach(t => t.stop()); enrollStream = null; }
            }

            let enrollDetectInterval = null;

            function startEnrollDetection() {
                enrollDescriptors = [];
                const TARGET = 5; // capture 5 frames and average
                enrollDetectInterval = setInterval(async () => {
                    const vid = document.getElementById('enrollVideo');
                    if (!vid || vid.readyState < 2) return;
                    const detection = await faceapi
                        .detectSingleFace(vid, new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.15 }))
                        .withFaceLandmarks()
                        .withFaceDescriptor();
                    if (!detection) {
                        document.getElementById('enrollStatus').innerHTML =
                            '<i class="fas fa-face-meh mr-1 text-amber-400"></i> No face detected. Move closer.';
                        return;
                    }
                    enrollDescriptors.push(Array.from(detection.descriptor));
                    const pct = Math.round((enrollDescriptors.length / TARGET) * 100);
                    document.getElementById('enrollProgressBar').style.width = pct + '%';
                    document.getElementById('enrollStatus').innerHTML =
                        '<i class="fas fa-circle-notch fa-spin mr-1 text-emerald-400"></i> Capturing face (' + enrollDescriptors.length + '/' + TARGET + ')...';

                    if (enrollDescriptors.length >= TARGET) {
                        clearInterval(enrollDetectInterval);
                        // Average descriptors for robustness
                        const avgDesc = enrollDescriptors[0].map((_, i) =>
                            enrollDescriptors.reduce((sum, d) => sum + d[i], 0) / enrollDescriptors.length
                        );
                        document.getElementById('enrollStatus').innerHTML =
                            '<i class="fas fa-check-circle text-emerald-400 mr-1"></i> Face captured! Click to enroll.';
                        const btn = document.getElementById('enrollCaptureBtn');
                        btn.disabled = false;
                        btn.style.opacity = '1';
                        btn.style.cursor = 'pointer';
                        btn.onclick = () => submitEnrollment(avgDesc);
                    }
                }, 400);
            }

            async function submitEnrollment(descriptor) {
                document.getElementById('enrollStatus').innerHTML =
                    '<i class="fas fa-spinner fa-spin mr-1"></i> Enrolling...';
                try {
                    const res = await axios.post('/api/face/enroll', { descriptor });
                    if (res.data.success) {
                        document.getElementById('enrollStatus').innerHTML =
                            '<i class="fas fa-circle-check text-emerald-400 mr-1"></i> Face enrolled successfully!';
                        setTimeout(() => {
                            closeEnrollModal();
                            // Restart face gate now that student is enrolled
                            document.getElementById('faceNotEnrolled').classList.add('hidden');
                            startFaceGate();
                        }, 1500);
                    } else {
                        document.getElementById('enrollStatus').innerHTML =
                            '<i class="fas fa-circle-xmark text-rose-400 mr-1"></i> ' + (res.data.error || 'Enrollment failed');
                    }
                } catch (e) {
                    document.getElementById('enrollStatus').innerHTML =
                        '<i class="fas fa-circle-xmark text-rose-400 mr-1"></i> ' +
                        (e.response?.data?.error || 'Enrollment failed. Try again.');
                }
            }

            // ── Auth check ────────────────────────────────────────────────────────
            async function checkAuth() {
                try {
                    const res = await axios.get('/api/student/me');
                    if (res.data.success && res.data.student) {
                        studentData = res.data.student;
                        document.getElementById('studentName').textContent = studentData.name;
                        document.getElementById('studentRollTag').textContent = 'Roll: ' + (studentData.roll_no || '—');
                        document.getElementById('pBranch').textContent = studentData.branch || '—';
                        document.getElementById('pSection').textContent = studentData.section || '—';
                        document.getElementById('pYear').textContent = studentData.year || '—';
                        document.getElementById('pGender').textContent = studentData.gender || '—';
                        loadHistory();
                    } else {
                        window.location.href = '/student/login';
                    }
                } catch (e) {
                    window.location.href = '/student/login';
                }
            }

            // ── Logout ────────────────────────────────────────────────────────────
            document.getElementById('logoutBtn').addEventListener('click', async () => {
                stopCamera();
                try { await axios.post('/api/student/logout'); } catch(e) {}
                window.location.href = '/student/login';
            });

            // ── Camera / QR Scan ──────────────────────────────────────────────────
            document.getElementById('startCameraBtn').addEventListener('click', startCamera);
            document.getElementById('stopCameraBtn').addEventListener('click', stopCamera);

            async function startCamera() {
                document.getElementById('cameraStatus').classList.add('hidden');
                document.getElementById('scannerWrap').classList.remove('hidden');
                document.getElementById('startCameraBtn').classList.add('hidden');
                document.getElementById('stopCameraBtn').classList.remove('hidden');
                document.getElementById('stopCameraBtn').classList.add('flex');
                try {
                    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
                    const video = document.getElementById('scannerVideo');
                    video.srcObject = stream;
                    await video.play();
                    scanning = true;
                    scanInterval = setInterval(scanFrame, 300);
                } catch(err) {
                    showResult('Camera access denied. Please allow camera permissions.', false);
                    stopCamera();
                }
            }

            function stopCamera() {
                scanning = false;
                if (scanInterval) { clearInterval(scanInterval); scanInterval = null; }
                if (stream) { stream.getTracks().forEach(t => t.stop()); stream = null; }
                document.getElementById('scannerWrap').classList.add('hidden');
                document.getElementById('cameraStatus').classList.remove('hidden');
                document.getElementById('cameraStatus').innerHTML = '<i class="fas fa-camera text-3xl mb-3 block opacity-30"></i>Camera stopped';
                document.getElementById('startCameraBtn').classList.remove('hidden');
                document.getElementById('stopCameraBtn').classList.add('hidden');
                document.getElementById('stopCameraBtn').classList.remove('flex');
            }

            function scanFrame() {
                if (!scanning || scanCooldown) return;
                const video = document.getElementById('scannerVideo');
                const canvas = document.getElementById('scanCanvas');
                if (video.readyState !== video.HAVE_ENOUGH_DATA) return;
                canvas.width = video.videoWidth;
                canvas.height = video.videoHeight;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'dontInvert' });
                if (code && code.data) {
                    handleQRCode(code.data);
                }
            }

            async function handleQRCode(qrData) {
                if (scanCooldown) return;
                scanCooldown = true;
                showResult('<i class="fas fa-spinner fa-spin mr-2"></i>Verifying QR code...', null);

                if (!navigator.geolocation) {
                    showResult('Geolocation is not supported by your browser.', false);
                    setTimeout(() => { scanCooldown = false; }, 4000);
                    return;
                }

                navigator.geolocation.getCurrentPosition(async (pos) => {
                    try {
                        const res = await axios.post('/api/scan-qr', {
                            qrData,
                            latitude: pos.coords.latitude,
                            longitude: pos.coords.longitude,
                            clientId,
                            face_token: faceToken  // HMAC-signed token from /api/face/verify
                        });
                        if (res.data.success) {
                            showResult('<i class="fas fa-check-circle mr-2"></i>Attendance marked! ' + (res.data.class?.name || ''), true);
                            stopCamera();
                            loadHistory();
                        } else {
                            showResult('<i class="fas fa-times-circle mr-2"></i>' + (res.data.error || 'Failed'), false);
                            setTimeout(() => { scanCooldown = false; }, 5000);
                        }
                    } catch (err) {
                        const msg = err.response?.data?.error || 'Server error. Try again.';
                        showResult('<i class="fas fa-times-circle mr-2"></i>' + msg, false);
                        setTimeout(() => { scanCooldown = false; }, 5000);
                    }
                }, (err) => {
                    showResult('Location access denied. Enable GPS to mark attendance.', false);
                    setTimeout(() => { scanCooldown = false; }, 5000);
                }, { enableHighAccuracy: true, timeout: 10000 });
            }

            function showResult(msg, success) {
                const el = document.getElementById('scanResult');
                el.classList.remove('hidden');
                if (success === true) { el.style.background='rgba(16,185,129,0.1)'; el.style.color='#34d399'; el.style.border='1px solid rgba(16,185,129,0.2)'; }
                else if (success === false) { el.style.background='rgba(244,63,94,0.1)'; el.style.color='#fb7185'; el.style.border='1px solid rgba(244,63,94,0.2)'; }
                else { el.style.background='rgba(59,130,246,0.1)'; el.style.color='#60a5fa'; el.style.border='1px solid rgba(59,130,246,0.2)'; }
                el.innerHTML = msg;
            }

            // ── Attendance History ────────────────────────────────────────────────
            async function loadHistory() {
                try {
                    const res = await axios.get('/api/student/attendance');
                    const list = document.getElementById('historyList');
                    if (!res.data.attendance || res.data.attendance.length === 0) {
                        list.innerHTML = '<div class="text-center text-sm py-8" style="color:#64748b;"><i class="fas fa-clipboard-list text-3xl mb-3 block opacity-30"></i>No attendance records yet.</div>';
                        return;
                    }
                    list.innerHTML = res.data.attendance.map(a => {
                        const date = new Date(a.marked_at);
                        const dateStr = date.toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' });
                        const timeStr = date.toLocaleTimeString('en-IN', { hour:'2-digit', minute:'2-digit' });
                        return \`<div class="flex items-center justify-between py-4 border-b last:border-0" style="border-color:rgba(255,255,255,0.05);">
                            <div>
                                <p class="text-sm font-bold text-slate-200">\${a.class_name}</p>
                                <p class="text-xs" style="color:#64748b;">\${a.teacher_name} &bull; \${a.class_code}</p>
                            </div>
                            <div class="text-right flex-shrink-0 ml-4">
                                <p class="text-xs font-bold text-slate-300">\${dateStr}</p>
                                <p class="text-xs mb-1" style="color:#64748b;">\${timeStr}</p>
                                <span class="tag" style="background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.3);color:#34d399;"><i class="fas fa-check-circle mr-0.5"></i>\${Math.round(a.distance_meters)}m</span>
                            </div>
                        </div>\`;
                    }).join('');
                } catch (e) {
                    document.getElementById('historyList').innerHTML = '<div class="text-center text-sm py-4" style="color:#fb7185;">Failed to load history.</div>';
                }
            }

            // ── Init ──────────────────────────────────────────────────────────────
            checkAuth().then(() => {
                // Start face verification gate after auth confirms student identity
                startFaceGate();
            });
        <\/script>
    </body>
    </html>
    `);
});


// Home page
app.get('/', (c) => {
    return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AttendX — Smart QR Attendance System</title>
        <meta name="description" content="Secure QR-based college attendance with GPS verification, device fingerprinting, and real-time monitoring.">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
            :root { --indigo: #6366f1; --purple: #8b5cf6; --emerald: #10b981; --teal: #06b6d4; }
            body { font-family: 'Inter', sans-serif; background: #080b14; color: #e2e8f0; min-height: 100vh; overflow-x: hidden; }
            .mesh-bg { position: fixed; inset: 0; z-index: 0;
                background: radial-gradient(ellipse 80% 60% at 20% 10%, rgba(99,102,241,0.18) 0%, transparent 60%),
                            radial-gradient(ellipse 60% 50% at 80% 80%, rgba(16,185,129,0.12) 0%, transparent 55%),
                            #080b14; }
            .orb { position: fixed; border-radius: 50%; filter: blur(90px); pointer-events: none; z-index: 0; animation: orbFloat 20s ease-in-out infinite; }
            .orb-1 { width: 500px; height: 500px; top: -150px; left: -150px; background: radial-gradient(circle, rgba(99,102,241,0.4), transparent 70%); animation-delay: 0s; }
            .orb-2 { width: 400px; height: 400px; bottom: -100px; right: -100px; background: radial-gradient(circle, rgba(16,185,129,0.35), transparent 70%); animation-delay: -8s; }
            @keyframes orbFloat { 0%,100% { transform: translate(0,0) scale(1); } 33% { transform: translate(30px,-40px) scale(1.08); } 66% { transform: translate(-20px,30px) scale(0.95); } }
            .page { position: relative; z-index: 1; }
            .container { max-width: 1100px; margin: 0 auto; padding: 0 24px; }
            nav { display: flex; justify-content: center; align-items: center; padding: 28px 0 0; }
            .logo { display: flex; align-items: center; gap: 12px; text-decoration: none; }
            .logo-icon { width: 42px; height: 42px; background: linear-gradient(135deg, var(--indigo), var(--purple)); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 18px; color: #fff; box-shadow: 0 0 24px rgba(99,102,241,0.4); }
            .logo-text { font-size: 22px; font-weight: 800; color: #fff; letter-spacing: -0.5px; }
            .logo-text span { color: var(--indigo); }
            .badge { display: inline-flex; align-items: center; gap: 8px; background: rgba(99,102,241,0.12); border: 1px solid rgba(99,102,241,0.3); color: #a5b4fc; font-size: 12px; font-weight: 600; padding: 6px 14px; border-radius: 999px; letter-spacing: 0.5px; margin-bottom: 28px; }
            .badge-dot { width: 6px; height: 6px; background: var(--indigo); border-radius: 50%; box-shadow: 0 0 8px var(--indigo); animation: pulse 2s infinite; }
            @keyframes pulse { 0%,100% { opacity:1; transform:scale(1); } 50% { opacity:0.5; transform:scale(1.5); } }
            .hero { text-align: center; padding: 80px 0 70px; }
            .hero h1 { font-size: clamp(40px, 7vw, 72px); font-weight: 900; line-height: 1.08; letter-spacing: -2px; color: #fff; margin-bottom: 20px; }
            .hero h1 .grad { background: linear-gradient(135deg, #818cf8 0%, #c084fc 50%, #38bdf8 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
            .hero p { font-size: 17px; color: #94a3b8; max-width: 560px; margin: 0 auto 48px; line-height: 1.7; }
            .stats { display: flex; justify-content: center; gap: 48px; flex-wrap: wrap; margin-bottom: 80px; }
            .stat { text-align: center; }
            .stat-num { font-size: 36px; font-weight: 800; background: linear-gradient(135deg, #818cf8, #c084fc); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
            .stat-label { font-size: 12px; color: #64748b; font-weight: 500; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }
            .pills { display: flex; justify-content: center; flex-wrap: wrap; gap: 10px; margin-bottom: 80px; }
            .pill { display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 999px; padding: 10px 20px; font-size: 13px; font-weight: 500; color: #cbd5e1; transition: all 0.3s ease; cursor: default; }
            .pill:hover { background: rgba(99,102,241,0.12); border-color: rgba(99,102,241,0.3); color: #a5b4fc; transform: translateY(-2px); }
            .pill-indigo i { color: #818cf8; } .pill-emerald i { color: #34d399; } .pill-rose i { color: #fb7185; } .pill-sky i { color: #38bdf8; }
            .portals { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 24px; margin-bottom: 80px; }
            .portal { position: relative; border-radius: 28px; padding: 40px 36px; display: flex; flex-direction: column; align-items: center; text-align: center; overflow: hidden; transition: transform 0.4s cubic-bezier(.23,1,.32,1), box-shadow 0.4s ease; }
            .portal-teacher { background: linear-gradient(145deg, rgba(99,102,241,0.15) 0%, rgba(139,92,246,0.08) 100%); border: 1px solid rgba(99,102,241,0.25); }
            .portal-teacher:hover { transform: translateY(-10px) scale(1.02); box-shadow: 0 30px 80px -20px rgba(99,102,241,0.35); border-color: rgba(99,102,241,0.5); }
            .portal-student { background: linear-gradient(145deg, rgba(16,185,129,0.15) 0%, rgba(6,182,212,0.08) 100%); border: 1px solid rgba(16,185,129,0.25); }
            .portal-student:hover { transform: translateY(-10px) scale(1.02); box-shadow: 0 30px 80px -20px rgba(16,185,129,0.35); border-color: rgba(16,185,129,0.5); }
            .portal::before { content: ''; position: absolute; top: 0; left: 10%; right: 10%; height: 1px; border-radius: 999px; transition: opacity 0.4s; opacity: 0; }
            .portal-teacher::before { background: linear-gradient(90deg, transparent, #818cf8, transparent); }
            .portal-student::before { background: linear-gradient(90deg, transparent, #34d399, transparent); }
            .portal:hover::before { opacity: 1; }
            .portal-icon { width: 72px; height: 72px; border-radius: 22px; display: flex; align-items: center; justify-content: center; font-size: 28px; margin-bottom: 28px; }
            .portal-teacher .portal-icon { background: linear-gradient(135deg, rgba(99,102,241,0.25), rgba(139,92,246,0.2)); color: #818cf8; box-shadow: 0 0 30px rgba(99,102,241,0.2); }
            .portal-student .portal-icon { background: linear-gradient(135deg, rgba(16,185,129,0.25), rgba(6,182,212,0.2)); color: #34d399; box-shadow: 0 0 30px rgba(16,185,129,0.2); }
            .portal h2 { font-size: 24px; font-weight: 800; color: #f1f5f9; margin-bottom: 12px; letter-spacing: -0.5px; }
            .portal p { font-size: 14px; color: #64748b; line-height: 1.7; margin-bottom: 32px; }
            .btn { display: inline-flex; align-items: center; gap: 8px; padding: 13px 28px; border-radius: 14px; font-size: 14px; font-weight: 700; text-decoration: none; transition: all 0.3s cubic-bezier(.23,1,.32,1); }
            .btn-teacher { background: linear-gradient(135deg, #6366f1, #8b5cf6); color: #fff; box-shadow: 0 4px 24px rgba(99,102,241,0.3); }
            .btn-teacher:hover { box-shadow: 0 8px 40px rgba(99,102,241,0.5); transform: translateY(-2px); }
            .btn-student { background: linear-gradient(135deg, #10b981, #06b6d4); color: #fff; box-shadow: 0 4px 24px rgba(16,185,129,0.3); }
            .btn-student:hover { box-shadow: 0 8px 40px rgba(16,185,129,0.5); transform: translateY(-2px); }
            .signup-row { margin-top: 16px; font-size: 12px; color: #475569; }
            .signup-row a { color: #818cf8; text-decoration: none; font-weight: 600; }
            .signup-row a:hover { color: #c084fc; }
            .portal-student .signup-row a { color: #34d399; }
            .section-label { text-align: center; font-size: 11px; font-weight: 700; letter-spacing: 3px; text-transform: uppercase; color: #6366f1; margin-bottom: 16px; }
            .section-title { text-align: center; font-size: 34px; font-weight: 800; color: #f1f5f9; margin-bottom: 12px; letter-spacing: -1px; }
            .section-sub { text-align: center; font-size: 15px; color: #64748b; margin-bottom: 56px; }
            .steps { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 100px; }
            .step { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); border-radius: 20px; padding: 28px 24px; position: relative; overflow: hidden; transition: all 0.3s ease; }
            .step:hover { background: rgba(99,102,241,0.07); border-color: rgba(99,102,241,0.2); transform: translateY(-4px); }
            .step-num { font-size: 48px; font-weight: 900; background: linear-gradient(135deg, rgba(99,102,241,0.15), rgba(139,92,246,0.08)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; position: absolute; top: 16px; right: 20px; }
            .step-icon { font-size: 22px; margin-bottom: 16px; }
            .step h4 { font-size: 15px; font-weight: 700; color: #e2e8f0; margin-bottom: 8px; }
            .step p { font-size: 13px; color: #64748b; line-height: 1.6; }
            .step-teacher .step-icon { color: #818cf8; } .step-student .step-icon { color: #34d399; }
            footer { border-top: 1px solid rgba(255,255,255,0.05); padding: 32px 0; text-align: center; font-size: 13px; color: #334155; }
        </style>
    </head>
    <body>
        <div class="mesh-bg"></div>
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
        <div class="page">
            <nav>
                <a href="/" class="logo">
                    <div class="logo-icon"><i class="fas fa-qrcode"></i></div>
                    <span class="logo-text">Attend<span>X</span></span>
                </a>
            </nav>
            <div class="container">
                <div class="hero">
                    <div class="badge"><div class="badge-dot"></div>QR &middot; GPS &middot; Anti-Fraud &middot; Real-Time</div>
                    <h1>Attendance,<br><span class="grad">Reimagined.</span></h1>
                    <p>Smart QR-based attendance for colleges — verified with GPS location, device fingerprinting, and live monitoring. No paper. No proxies.</p>
                </div>
                <div class="stats">
                    <div class="stat"><div class="stat-num">80m</div><div class="stat-label">GPS Radius</div></div>
                    <div class="stat"><div class="stat-num">5 min</div><div class="stat-label">QR Expiry</div></div>
                    <div class="stat"><div class="stat-num">1&times;</div><div class="stat-label">Per Device</div></div>
                    <div class="stat"><div class="stat-num">Live</div><div class="stat-label">Monitoring</div></div>
                </div>
                <div class="pills">
                    <div class="pill pill-indigo"><i class="fas fa-clock"></i> Auto-expiring QR codes</div>
                    <div class="pill pill-emerald"><i class="fas fa-map-marker-alt"></i> Haversine GPS check</div>
                    <div class="pill pill-rose"><i class="fas fa-shield-alt"></i> Device fingerprinting</div>
                    <div class="pill pill-sky"><i class="fas fa-bolt"></i> Real-time attendance feed</div>
                    <div class="pill pill-indigo"><i class="fas fa-camera"></i> Built-in QR scanner</div>
                    <div class="pill pill-emerald"><i class="fas fa-lock"></i> Secure JWT sessions</div>
                </div>
                <div class="portals">
                    <div class="portal portal-teacher">
                        <div class="portal-icon"><i class="fas fa-chalkboard-teacher"></i></div>
                        <h2>Teacher Portal</h2>
                        <p>Create subjects, generate GPS-anchored QR codes, monitor live attendance, and manage sessions — all from one dashboard.</p>
                        <a href="/teacher/login" class="btn btn-teacher"><i class="fas fa-sign-in-alt"></i> Teacher Sign In</a>
                        <div class="signup-row">New? <a href="/teacher/signup">Create an account</a></div>
                    </div>
                    <div class="portal portal-student">
                        <div class="portal-icon"><i class="fas fa-user-graduate"></i></div>
                        <h2>Student Portal</h2>
                        <p>Sign in with your Roll No, open the scanner, point at the class QR code and instantly mark your attendance.</p>
                        <a href="/student/login" class="btn btn-student"><i class="fas fa-sign-in-alt"></i> Student Sign In</a>
                        <div class="signup-row">New? <a href="/student/signup">Create an account</a></div>
                    </div>
                </div>
                <div class="section-label">How It Works</div>
                <div class="section-title">Simple for everyone.</div>
                <div class="section-sub">Two roles. Four steps. Zero hassle.</div>
                <div class="steps">
                    <div class="step step-teacher"><div class="step-num">01</div><div class="step-icon"><i class="fas fa-user-plus"></i></div><h4>Teacher Signs Up</h4><p>Create an account, add your subjects, and you're ready to take attendance.</p></div>
                    <div class="step step-teacher"><div class="step-num">02</div><div class="step-icon"><i class="fas fa-qrcode"></i></div><h4>Generate QR</h4><p>Select a class and tap Generate — a live QR code appears, locked to your GPS location.</p></div>
                    <div class="step step-student"><div class="step-num">03</div><div class="step-icon"><i class="fas fa-mobile-alt"></i></div><h4>Student Scans</h4><p>Student opens the app, taps Start Camera and scans the code from within the classroom.</p></div>
                    <div class="step step-student"><div class="step-num">04</div><div class="step-icon"><i class="fas fa-check-circle"></i></div><h4>Attendance Marked</h4><p>GPS, device and session are verified instantly. Attendance is recorded with distance proof.</p></div>
                </div>
            </div>
            <footer><span>AttendX &copy; 2025 &nbsp;&middot;&nbsp; Built with Cloudflare Workers + D1</span></footer>
        </div>
    </body>
    </html>
    `);
});
// Teacher dashboard
app.get('/teacher', (c) => {
    return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Teacher Dashboard - Attendance System</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <style>
            body {
                font-family: 'Inter', sans-serif;
            }
            .glass-effect {
                backdrop-filter: blur(16px);
                background-color: rgba(255, 255, 255, 0.8);
                border: 1px solid rgba(255, 255, 255, 0.4);
                box-shadow: 0 10px 30px -10px rgba(79, 70, 229, 0.06);
            }
            .pulse-button {
                position: relative;
                z-index: 1;
            }
            .pulse-button::after {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                border-radius: inherit;
                background: inherit;
                z-index: -1;
                opacity: 0.4;
                animation: pulse-ring 2s cubic-bezier(0.4, 0, 0.2, 1) infinite;
            }
            @keyframes pulse-ring {
                0% { transform: scale(1); opacity: 0.4; }
                100% { transform: scale(1.15); opacity: 0; }
            }
            .dot-pulse {
                position: relative;
            }
            .dot-pulse::after {
                content: '';
                position: absolute;
                width: 100%;
                height: 100%;
                top: 0;
                left: 0;
                border-radius: 50%;
                background-color: inherit;
                animation: dot-ping 1.5s cubic-bezier(0, 0, 0.2, 1) infinite;
            }
            @keyframes dot-ping {
                0% { transform: scale(1); opacity: 1; }
                100% { transform: scale(2.5); opacity: 0; }
            }
        </style>
    </head>
    <body class="min-h-screen text-slate-100" style="background:#080b14;font-family:'Inter',sans-serif;">
        <!-- Dark background orbs -->
        <div style="position:fixed;inset:0;z-index:0;background:radial-gradient(ellipse 70% 50% at 10% 0%, rgba(99,102,241,0.15) 0%, transparent 60%),radial-gradient(ellipse 50% 40% at 90% 90%, rgba(16,185,129,0.10) 0%, transparent 55%),#080b14;pointer-events:none;"></div>
        <div style="position:relative;z-index:1;">
        <div class="container mx-auto px-4 py-8 max-w-5xl">
            <!-- Header -->
            <div class="flex flex-col md:flex-row justify-between items-center gap-4 mb-8 p-5 rounded-2xl" style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);backdrop-filter:blur(16px);">
                <div class="flex items-center space-x-4">
                    <div class="w-12 h-12 rounded-2xl flex items-center justify-center text-white text-xl" style="background:linear-gradient(135deg,#6366f1,#8b5cf6);box-shadow:0 0 24px rgba(99,102,241,0.4);">
                        <i class="fas fa-chalkboard-teacher"></i>
                    </div>
                    <div>
                        <h1 class="text-2xl font-bold text-white tracking-tight">Teacher Dashboard</h1>
                        <p class="text-xs" style="color:#64748b;">Welcome, <span id="teacherDisplayName" class="font-semibold" style="color:#a5b4fc;">Loading...</span></p>
                    </div>
                </div>
                <div class="flex items-center space-x-3">
                    <span id="teacherUsernameTag" class="text-xs font-bold px-3 py-1.5 rounded-full" style="background:rgba(99,102,241,0.15);border:1px solid rgba(99,102,241,0.3);color:#a5b4fc;">Teacher</span>
                    <a href="/" class="text-sm transition flex items-center px-3 py-1.5 rounded-xl" style="color:#64748b;" title="Home">
                        <i class="fas fa-home"></i>
                    </a>
                    <button id="logoutBtn" class="flex items-center space-x-1.5 text-sm font-semibold px-3 py-1.5 rounded-xl transition" style="color:#f87171;background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.2);">
                        <i class="fas fa-right-from-bracket text-xs"></i>
                        <span>Sign Out</span>
                    </button>
                </div>
            </div>

            <!-- Class Selection & QR Gen Layout -->
            <div class="grid md:grid-cols-3 gap-8 mb-8">
                <!-- Class Selection -->
                <div class="rounded-2xl p-6 md:col-span-1 flex flex-col justify-between" style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);">
                    <div>
                        <h2 class="text-lg font-bold mb-4 flex items-center space-x-2" style="color:#f1f5f9;">
                            <i class="fas fa-book" style="color:#818cf8;"></i>
                            <span>Select Class</span>
                        </h2>
                        <p class="text-xs mb-4" style="color:#64748b;">Choose a class to activate or restore attendance sessions.</p>
                        <select id="classSelect" class="w-full px-4 py-3 rounded-xl text-sm transition" style="background:rgba(15,20,40,0.8);border:1px solid rgba(255,255,255,0.1);color:#e2e8f0;outline:none;">
                            <option value="">Loading classes...</option>
                        </select>
                        <button id="createSubjectBtn" class="mt-3 w-full flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-bold rounded-xl transition uppercase tracking-wide" style="border:2px dashed rgba(99,102,241,0.3);color:#818cf8;background:transparent;" onmouseover="this.style.background='rgba(99,102,241,0.1)'" onmouseout="this.style.background='transparent'">
                            <i class="fas fa-plus-circle"></i> Add New Subject
                        </button>
                    </div>
                </div>

                <!-- QR Generation Trigger (shown when class selected and no active session) -->
                <div id="qrSection" class="rounded-2xl p-6 md:col-span-2 hidden flex flex-col justify-between" style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);">
                    <div>
                        <h2 class="text-lg font-bold mb-3 flex items-center space-x-2" style="color:#f1f5f9;">
                            <i class="fas fa-qrcode" style="color:#818cf8;"></i>
                            <span>Generate QR Code</span>
                        </h2>
                        <p class="text-sm mb-6 leading-relaxed" style="color:#64748b;">
                            Generate a temporary attendance QR code locked to your current physical coordinates. Students must scan this within 80 meters.
                        </p>
                    </div>
                    <div>
                        <button id="generateBtn" class="pulse-button w-full md:w-auto bg-gradient-to-r from-indigo-600 to-purple-600 text-white px-6 py-3.5 rounded-xl font-bold hover:shadow-lg hover:shadow-indigo-500/20 transition flex items-center justify-center space-x-2 text-sm">
                            <i class="fas fa-plus-circle"></i>
                            <span>Activate Attendance QR</span>
                        </button>
                    </div>
                </div>

                <!-- Active Session (Shown when session runs) -->
                <div id="activeSession" class="rounded-2xl p-6 md:col-span-2 hidden flex flex-col justify-between" style="background:rgba(16,185,129,0.05);border:1px solid rgba(16,185,129,0.25);">
                    <div class="flex justify-between items-start mb-6">
                        <div class="flex items-center space-x-3">
                            <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 dot-pulse"></span>
                            <div>
                                <h2 class="text-lg font-bold text-white">Session Active</h2>
                                <p class="text-xs" id="sessionClass" style="color:#64748b;"></p>
                            </div>
                        </div>
                        <button id="stopBtn" class="bg-rose-50 hover:bg-rose-100 border border-rose-200 text-rose-600 px-4 py-2 rounded-xl text-xs font-semibold transition flex items-center space-x-1">
                            <i class="fas fa-stop-circle"></i>
                            <span>Terminate Session</span>
                        </button>
                    </div>
                    
                    <div class="grid md:grid-cols-2 gap-6 items-center">
                        <!-- QR Code -->
                        <div class="flex flex-col items-center p-4 rounded-2xl" style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);">
                            <div id="qrcode" class="bg-white p-3 rounded-xl shadow-md border border-slate-200/50"></div>
                            <div class="mt-4 text-center">
                                <div class="text-3xl font-extrabold tracking-tight" id="timer" style="color:#818cf8;">5:00</div>
                                <div class="text-[10px] uppercase font-semibold mt-0.5 tracking-wider" style="color:#475569;">Remaining Time</div>
                            </div>
                        </div>
                        
                        <!-- Attendance Stats -->
                        <div class="h-full flex flex-col justify-between">
                            <div class="p-4 rounded-xl text-center mb-4" style="background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.2);">
                                <div class="text-4xl font-extrabold" id="attendanceCount" style="color:#818cf8;">0</div>
                                <div class="text-xs font-medium mt-1" style="color:#818cf8;">Students Signed In</div>
                            </div>
                            <div class="text-xs leading-relaxed p-3 rounded-xl" style="color:#64748b;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);">
                                <i class="fas fa-info-circle text-indigo-500 mr-1"></i> Live feed is updating automatically every 3 seconds.
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Attendance Panels -->
            <div class="grid md:grid-cols-3 gap-8">
                <!-- Live Scan Feed -->
                <div class="rounded-2xl p-6 md:col-span-2 flex flex-col h-[400px]" style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);">
                    <h3 class="text-lg font-bold mb-4 flex items-center space-x-2" style="color:#f1f5f9;">
                        <i class="fas fa-users" style="color:#818cf8;"></i>
                        <span>Live Attendance Stream</span>
                    </h3>
                    <div id="attendanceList" class="space-y-3 overflow-y-auto pr-1 flex-1">
                        <p class="text-sm italic" style="color:#475569;">No entries yet. Select a class and start a session...</p>
                    </div>
                </div>

                <!-- History -->
                <div class="rounded-2xl p-6 md:col-span-1 flex flex-col h-[400px]" style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);">
                    <h3 class="text-lg font-bold mb-4 flex items-center space-x-2" style="color:#f1f5f9;">
                        <i class="fas fa-history" style="color:#818cf8;"></i>
                        <span>Session History</span>
                    </h3>
                    <div id="historyList" class="space-y-3 overflow-y-auto pr-1 flex-1">
                        <p class="text-sm italic" style="color:#475569;">Loading history records...</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Create Subject Modal -->
        <div id="createSubjectModal" style="display:none;position:fixed;inset:0;z-index:50;align-items:center;justify-content:center;padding:16px;background:rgba(0,0,0,0.75);backdrop-filter:blur(8px);">
            <div class="rounded-2xl p-8 w-full" style="max-width:440px;background:rgba(15,20,40,0.95);border:1px solid rgba(255,255,255,0.12);backdrop-filter:blur(24px);">
                <div class="flex justify-between items-center mb-6">
                    <h3 class="text-lg font-bold text-white"><i class="fas fa-book-open mr-2" style="color:#818cf8;"></i>Add New Subject</h3>
                    <button id="closeSubjectModal" class="w-8 h-8 rounded-full flex items-center justify-center transition" style="color:#64748b;background:rgba(255,255,255,0.05);" onmouseover="this.style.background='rgba(255,255,255,0.1)'" onmouseout="this.style.background='rgba(255,255,255,0.05)'">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <form id="createSubjectForm" class="space-y-4">
                    <div>
                        <label class="block text-xs font-semibold uppercase tracking-wider mb-1.5" style="color:#64748b;">Subject Name *</label>
                        <input id="subjectName" type="text" placeholder="e.g. Advanced Mathematics" class="w-full px-4 py-2.5 rounded-xl text-sm" style="background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.1);color:#e2e8f0;outline:none;" required>
                    </div>
                    <div>
                        <label class="block text-xs font-semibold uppercase tracking-wider mb-1.5" style="color:#64748b;">Subject Code *</label>
                        <input id="subjectCode" type="text" placeholder="e.g. MATH401" class="w-full px-4 py-2.5 rounded-xl text-sm" style="background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.1);color:#e2e8f0;outline:none;" required>
                    </div>
                    <div class="grid grid-cols-2 gap-3">
                        <div>
                            <label class="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1.5">Schedule</label>
                            <input id="subjectSchedule" type="text" placeholder="Mon/Wed 9â€“10 AM" class="w-full px-4 py-2.5 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white text-sm">
                        </div>
                        <div>
                            <label class="block text-xs font-semibold uppercase tracking-wider mb-1.5" style="color:#64748b;">Room</label>
                            <input id="subjectRoom" type="text" placeholder="Room 204" class="w-full px-4 py-2.5 rounded-xl text-sm" style="background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.1);color:#e2e8f0;outline:none;">
                        </div>
                    </div>
                    <div class="flex gap-3 pt-1">
                        <button type="button" id="cancelSubjectBtn" class="flex-1 px-4 py-2.5 rounded-xl text-sm font-semibold transition" style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);color:#94a3b8;">Cancel</button>
                        <button type="submit" id="createSubjectSubmitBtn" class="flex-1 bg-gradient-to-r from-indigo-600 to-purple-600 text-white px-4 py-2.5 rounded-xl text-sm font-bold hover:shadow-lg hover:shadow-indigo-500/20 transition flex items-center justify-center gap-2">
                            <i class="fas fa-plus"></i> Create
                        </button>
                    </div>
                </form>
            </div>
        </div>

        </div> <!-- end position:relative wrapper -->

        <script>
            let currentSession = null;
            let timerInterval = null;
            let attendanceInterval = null;
            let selectedClass = null;
            let teacherId = null;

            // â”€â”€ Auth check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            async function checkAuth() {
                try {
                    const res = await axios.get('/api/teacher/me');
                    if (res.data.success) {
                        teacherId = res.data.teacher.id;
                        document.getElementById('teacherDisplayName').textContent = res.data.teacher.name || 'Teacher';
                        document.getElementById('teacherUsernameTag').textContent = '@' + (res.data.teacher.username || 'teacher');
                        loadClasses();
                        loadHistory();
                    } else {
                        window.location.href = '/teacher/login';
                    }
                } catch (e) {
                    window.location.href = '/teacher/login';
                }
            }

            // Sign out
            document.getElementById('logoutBtn').addEventListener('click', async function() {
                try { await axios.post('/api/teacher/logout'); } catch(e) {}
                window.location.href = '/teacher/login';
            });

            // â”€â”€ Create Subject Modal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            function openSubjectModal() { document.getElementById('createSubjectModal').style.display = 'flex'; }
            function closeSubjectModal() { document.getElementById('createSubjectModal').style.display = 'none'; }
            document.getElementById('createSubjectBtn').addEventListener('click', openSubjectModal);
            document.getElementById('closeSubjectModal').addEventListener('click', closeSubjectModal);
            document.getElementById('cancelSubjectBtn').addEventListener('click', closeSubjectModal);
            document.getElementById('createSubjectModal').addEventListener('click', function(e) { if (e.target === this) closeSubjectModal(); });
            document.getElementById('createSubjectForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                var nm = document.getElementById('subjectName').value.trim();
                var cd = document.getElementById('subjectCode').value.trim().toUpperCase();
                var sc = document.getElementById('subjectSchedule').value.trim();
                var rm = document.getElementById('subjectRoom').value.trim();
                var submitBtn = document.getElementById('createSubjectSubmitBtn');
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating...';
                try {
                    await axios.post('/api/teacher/create-subject', { name: nm, code: cd, schedule: sc, room: rm });
                    closeSubjectModal();
                    this.reset();
                    await loadClasses();
                } catch (err) {
                    alert(err.response && err.response.data ? err.response.data.error : 'Failed to create subject');
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="fas fa-plus"></i> Create';
                }
            });

            // â”€â”€ Load classes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            async function loadClasses() {
                try {
                    const response = await axios.get('/api/teacher/classes');
                    const select = document.getElementById('classSelect');
                    select.innerHTML = '<option value="">-- Select a class --</option>';
                    response.data.classes.forEach(cls => {
                        const option = document.createElement('option');
                        option.value = cls.id;
                        option.textContent = \`\${cls.name} (\${cls.code}) - \${cls.schedule}\`;
                        option.dataset.name = cls.name;
                        option.dataset.code = cls.code;
                        select.appendChild(option);
                    });
                    
                    // Check for teacher active session on load
                    await checkActiveSessionForTeacher();
                } catch (error) {
                    console.error('Error loading classes:', error);
                }
            }

            // Restore active session for the teacher on load
            async function checkActiveSessionForTeacher() {
                try {
                    const response = await axios.get(\`/api/active-session?teacherId=\${teacherId}\`);
                    if (response.data.session) {
                        currentSession = response.data.session;
                        
                        // Set dropdown select value
                        const select = document.getElementById('classSelect');
                        select.value = currentSession.classId;
                        
                        // Restore selection reference
                        const selectedOption = select.options[select.selectedIndex];
                        if (selectedOption) {
                            selectedClass = {
                                id: currentSession.classId,
                                name: selectedOption.dataset.name,
                                code: selectedOption.dataset.code
                            };
                        }
                        
                        showActiveSession();
                    }
                } catch (error) {
                    console.error('Error checking active teacher session:', error);
                }
            }

            // Restore active session for a specific class on dropdown select
            async function checkActiveSession(classId) {
                try {
                    const response = await axios.get(\`/api/active-session?classId=\${classId}\`);
                    if (response.data.session) {
                        currentSession = response.data.session;
                        showActiveSession();
                    } else {
                        // If switching class and the old active session was shown, clear interval
                        if (currentSession) {
                            clearInterval(timerInterval);
                            clearInterval(attendanceInterval);
                            currentSession = null;
                            document.getElementById('activeSession').classList.add('hidden');
                        }
                        document.getElementById('qrSection').classList.remove('hidden');
                    }
                } catch (error) {
                    console.error('Error checking active session:', error);
                    document.getElementById('qrSection').classList.remove('hidden');
                }
            }

            // Handle class selection
            document.getElementById('classSelect').addEventListener('change', function() {
                selectedClass = {
                    id: this.value,
                    name: this.options[this.selectedIndex].dataset.name,
                    code: this.options[this.selectedIndex].dataset.code
                };
                
                if (this.value) {
                    checkActiveSession(this.value);
                } else {
                    document.getElementById('qrSection').classList.add('hidden');
                    document.getElementById('activeSession').classList.add('hidden');
                    if (currentSession) {
                        clearInterval(timerInterval);
                        clearInterval(attendanceInterval);
                        currentSession = null;
                    }
                }
            });

            // Generate QR code
            document.getElementById('generateBtn').addEventListener('click', async function() {
                if (!selectedClass || !selectedClass.id) {
                    alert('Please select a class first');
                    return;
                }

                let position;
                try {
                    position = await new Promise((resolve, reject) => {
                        navigator.geolocation.getCurrentPosition(resolve, reject, {
                            enableHighAccuracy: true,
                            timeout: 8000
                        });
                    });
                } catch (geoError) {
                    alert('GPS coordinates are required to start the attendance session. Please allow location permissions in your browser.');
                    return;
                }

                try {
                    const response = await axios.post('/api/generate-qr', {
                        classId: selectedClass.id,
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude,
                        teacherId: teacherId
                    });

                    currentSession = response.data.session;
                    showActiveSession();
                } catch (error) {
                    alert('Error generating QR code: ' + (error.response?.data?.error || error.message));
                }
            });

            // Show active session
            function showActiveSession() {
                document.getElementById('qrSection').classList.add('hidden');
                document.getElementById('activeSession').classList.remove('hidden');
                document.getElementById('sessionClass').textContent = \`\${currentSession.className} (\${currentSession.classCode})\`;

                // Generate QR code
                document.getElementById('qrcode').innerHTML = '';
                new QRCode(document.getElementById('qrcode'), {
                    text: currentSession.id,
                    width: 200,
                    height: 200,
                    colorDark : "#000000",
                    colorLight : "#ffffff",
                    correctLevel : QRCode.CorrectLevel.H
                });

                // Show session ID for manual entry (mobile fallback)
                const existingId = document.getElementById('sessionIdDisplay');
                if (existingId) existingId.remove();
                const sessionIdEl = document.createElement('div');
                sessionIdEl.id = 'sessionIdDisplay';
                sessionIdEl.className = 'mt-3 text-center';
                sessionIdEl.innerHTML = \`
                    <div class="text-[10px] text-slate-400 uppercase font-semibold tracking-wider mb-1">Session Code (manual entry)</div>
                    <div class="flex items-center justify-center gap-2">
                        <code class="text-xs font-mono bg-slate-100 border border-slate-200 rounded-lg px-3 py-1.5 text-slate-700 select-all">\${currentSession.id}</code>
                        <button onclick="navigator.clipboard.writeText('\${currentSession.id}').then(()=>this.textContent='âœ“').catch(()=>{})" class="text-[10px] bg-indigo-50 border border-indigo-100 text-indigo-600 px-2 py-1.5 rounded-lg hover:bg-indigo-100 transition font-semibold">Copy</button>
                    </div>
                \`;
                document.getElementById('qrcode').parentElement.appendChild(sessionIdEl);


                startTimer();
                
                // Start polling for attendance
                loadAttendance();
                clearInterval(attendanceInterval);
                attendanceInterval = setInterval(loadAttendance, 3000);
            }

            // Start countdown timer
            function startTimer() {
                const expiresAt = new Date(currentSession.expiresAt);
                clearInterval(timerInterval);
                
                timerInterval = setInterval(() => {
                    const now = new Date();
                    const diff = expiresAt - now;
                    
                    if (diff <= 0) {
                        clearInterval(timerInterval);
                        clearInterval(attendanceInterval);
                        document.getElementById('timer').textContent = '0:00';
                        document.getElementById('timer').classList.remove('text-indigo-700');
                        document.getElementById('timer').classList.add('text-rose-600');
                        alert('QR code session has expired');
                        stopSession();
                        return;
                    }
                    
                    const minutes = Math.floor(diff / 60000);
                    const seconds = Math.floor((diff % 60000) / 1000);
                    document.getElementById('timer').textContent = \`\${minutes}:\&seconds;\`.replace('&seconds;', seconds.toString().padStart(2, '0'));
                }, 1000);
            }

            // Load attendance
            async function loadAttendance() {
                if (!currentSession) return;
                
                try {
                    const response = await axios.get(\`/api/session/\${currentSession.id}/attendance\`);
                    const list = document.getElementById('attendanceList');
                    const count = document.getElementById('attendanceCount');
                    
                    count.textContent = response.data.attendance.length;
                    
                    if (response.data.attendance.length === 0) {
                        list.innerHTML = '<div class="text-slate-400 text-xs italic text-center py-8">Waiting for students to check in...</div>';
                    } else {
                        list.innerHTML = response.data.attendance.map(att => \`
                            <div class="flex items-center justify-between p-3.5 bg-slate-50 hover:bg-slate-100 rounded-xl border border-slate-200/50 transition">
                                <div class="flex items-center space-x-3">
                                    <div class="w-8 h-8 rounded-full bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-600 text-xs font-bold">
                                        \${att.student_name.charAt(0)}
                                    </div>
                                    <div>
                                        <div class="font-bold text-slate-800 text-sm">\${att.student_name}</div>
                                        <div class="text-[10px] text-slate-500 font-semibold">\${att.enrollment_number}</div>
                                    </div>
                                </div>
                                <div class="text-right text-xs">
                                    <div class="text-emerald-600 font-bold flex items-center justify-end space-x-1">
                                        <i class="fas fa-check-circle"></i>
                                        <span>Verified (\${Math.round(att.distance_meters)}m)</span>
                                    </div>
                                    <div class="text-[10px] text-slate-400 font-medium mt-0.5">\${new Date(att.marked_at).toLocaleTimeString()}</div>
                                </div>
                            </div>
                        \`).join('');
                    }
                } catch (error) {
                    console.error('Error loading attendance:', error);
                }
            }

            // Stop session
            document.getElementById('stopBtn').addEventListener('click', stopSession);

            async function stopSession() {
                if (!currentSession) return;
                
                try {
                    await axios.post(\`/api/session/\${currentSession.id}/stop\`);
                } catch (error) {
                    console.error('Error stopping session:', error);
                }
                
                clearInterval(timerInterval);
                clearInterval(attendanceInterval);
                currentSession = null;
                
                document.getElementById('activeSession').classList.add('hidden');
                document.getElementById('qrSection').classList.remove('hidden');
                
                loadHistory();
            }

            // Load history
            async function loadHistory() {
                try {
                    const response = await axios.get('/api/teacher/attendance-history?teacherId=' + teacherId);
                    const list = document.getElementById('historyList');
                    
                    if (response.data.history.length === 0) {
                        list.innerHTML = '<div class="text-slate-400 text-xs italic text-center py-8">No attendance records stored yet.</div>';
                    } else {
                        list.innerHTML = response.data.history.map(session => \`
                            <div class="p-3 bg-slate-50/60 rounded-xl border border-slate-200/50 flex flex-col justify-between hover:bg-slate-50 transition">
                                <div class="flex justify-between items-start">
                                    <div>
                                        <div class="font-bold text-slate-800 text-sm">\${session.class_name}</div>
                                        <div class="text-[10px] text-indigo-600 font-bold mt-0.5">\${session.class_code}</div>
                                    </div>
                                    <span class="text-[10px] font-bold px-2 py-0.5 rounded-full \${session.is_active ? 'bg-emerald-50 text-emerald-700 border border-emerald-100' : 'bg-slate-100 text-slate-500 border border-slate-200/50' }">
                                        \${session.is_active ? 'Active' : 'Closed'}
                                    </span>
                                </div>
                                <div class="flex justify-between items-center mt-3 pt-2 border-t border-slate-200/40 text-[10px] text-slate-500">
                                    <span>\${new Date(session.created_at).toLocaleDateString()} \${new Date(session.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
                                    <span class="font-bold text-slate-700">\${session.attendance_count} Present</span>
                                </div>
                            </div>
                        \`).join('');
                    }
                } catch (error) {
                    console.error('Error loading history:', error);
                }
            }

            // Initialize
            checkAuth();
        </script>
    </body>
    </html>
  `);
});

// Student dashboard  
app.get('/student', (c) => {
    return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Student Dashboard - Attendance System</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"></script>
        <script src="https://unpkg.com/html5-qrcode"></script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <style>
            body {
                font-family: 'Inter', sans-serif;
            }
            .glass-effect {
                backdrop-filter: blur(16px);
                background-color: rgba(255, 255, 255, 0.8);
                border: 1px solid rgba(255, 255, 255, 0.4);
                box-shadow: 0 10px 30px -10px rgba(16, 185, 129, 0.06);
            }
            .pulse-button {
                position: relative;
                z-index: 1;
            }
            .pulse-button::after {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                border-radius: inherit;
                background: inherit;
                z-index: -1;
                opacity: 0.4;
                animation: pulse-ring 2s cubic-bezier(0.4, 0, 0.2, 1) infinite;
            }
            @keyframes pulse-ring {
                0% { transform: scale(1); opacity: 0.4; }
                100% { transform: scale(1.15); opacity: 0; }
            }
            #reader video {
                border-radius: 12px;
                object-fit: cover;
            }
        </style>
    </head>
    <body class="min-h-screen text-slate-100" style="background:#080b14;font-family:'Inter',sans-serif;">
        <div style="position:fixed;inset:0;z-index:0;background:radial-gradient(ellipse 70% 50% at 10% 0%, rgba(16,185,129,0.12) 0%, transparent 60%),radial-gradient(ellipse 50% 40% at 90% 90%, rgba(6,182,212,0.08) 0%, transparent 55%),#080b14;pointer-events:none;"></div>
        <div style="position:relative;z-index:1;">
        <div class="container mx-auto px-4 py-8 max-w-5xl">
            <!-- Header -->
            <div class="flex flex-col md:flex-row justify-between items-center gap-4 mb-8 p-5 rounded-2xl" style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);backdrop-filter:blur(16px);">
                <div class="flex items-center space-x-4">
                    <div class="w-12 h-12 rounded-2xl flex items-center justify-center text-white text-xl" style="background:linear-gradient(135deg,#10b981,#06b6d4);box-shadow:0 0 24px rgba(16,185,129,0.4);">
                        <i class="fas fa-user-graduate"></i>
                    </div>
                    <div>
                        <h1 class="text-2xl font-bold text-white tracking-tight">Student Dashboard</h1>
                        <p class="text-xs" style="color:#64748b;">Welcome back, <span id="studentName" class="font-bold" style="color:#34d399;">Student</span></p>
                    </div>
                </div>
                <div class="flex items-center space-x-4">
                    <span class="text-xs font-bold px-3 py-1.5 rounded-full" style="background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.3);color:#34d399;">
                        Student Account
                    </span>
                    <a href="/" class="text-sm font-medium transition flex items-center space-x-1" style="color:#64748b;">
                        <i class="fas fa-home"></i> <span>Home</span>
                    </a>
                    <button id="studentLogoutBtn" class="flex items-center space-x-1.5 text-sm font-semibold px-3 py-1.5 rounded-xl transition" style="color:#f87171;background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.2);">
                        <i class="fas fa-right-from-bracket text-xs"></i>
                        <span>Sign Out</span>
                    </button>
                </div>
            </div>

            <!-- Student Identity -->
            <div class="grid md:grid-cols-3 gap-8 mb-8">
                <div class="rounded-2xl p-6 md:col-span-1 flex flex-col justify-between" style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);">
                    <div>
                        <h2 class="text-lg font-bold mb-4 flex items-center space-x-2" style="color:#f1f5f9;">
                            <i class="fas fa-user" style="color:#34d399;"></i>
                            <span>Student Identity</span>
                        </h2>
                        <p class="text-xs mb-4" style="color:#64748b;">Your identity is loaded from your account session.</p>
                        <select id="studentSelect" class="w-full px-4 py-3 rounded-xl text-sm transition hidden" style="background:rgba(15,20,40,0.8);border:1px solid rgba(255,255,255,0.1);color:#e2e8f0;outline:none;">
                            <option value="s1">Alice Brown (CS2024001)</option>
                            <option value="s2">Bob Davis (CS2024002)</option>
                            <option value="s3">Charlie Wilson (CS2024003)</option>
                            <option value="s4">Diana Martinez (CS2024004)</option>
                            <option value="s5">Eva Garcia (CS2024005)</option>
                            <option value="s6">Frank Miller (CS2024006)</option>
                            <option value="s7">Grace Lee (CS2024007)</option>
                            <option value="s8">Henry Taylor (CS2024008)</option>
                        </select>
                    </div>
                </div>

                <!-- QR Scanner Trigger -->
                <div class="rounded-2xl p-6 md:col-span-2 flex flex-col justify-between" style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);">
                    <div>
                        <h2 class="text-lg font-bold mb-3 flex items-center space-x-2" style="color:#f1f5f9;">
                            <i class="fas fa-camera" style="color:#34d399;"></i>
                            <span>Mark Attendance</span>
                        </h2>
                        <p class="text-sm mb-6 leading-relaxed" style="color:#64748b;">
                            Point your device camera at the QR code displayed in the classroom. The system will automatically acquire your coordinates and verify your entry.
                        </p>
                    </div>

                    <!-- Scan Launch Panel -->
                    <div id="scannerSection" class="w-full">
                        <button id="startScanBtn" class="pulse-button w-full md:w-auto bg-gradient-to-r from-emerald-500 to-teal-600 text-white px-6 py-3.5 rounded-xl font-bold hover:shadow-lg hover:shadow-emerald-500/20 transition flex items-center justify-center space-x-2 text-sm">
                            <i class="fas fa-qrcode"></i>
                            <span>Open Attendance Scanner</span>
                        </button>
                        <!-- Manual fallback toggle -->
                        <button id="manualEntryToggle" class="mt-3 text-xs text-slate-500 hover:text-emerald-700 underline underline-offset-2 transition block">
                            Can't scan? Enter session code manually
                        </button>
                    </div>

                    <!-- Manual Session ID Entry (Fallback for HTTP / no camera) -->
                    <div id="manualSection" class="hidden w-full">
                        <div class="bg-amber-50 border border-amber-200 rounded-xl p-4 mb-4">
                            <div class="flex items-start space-x-3">
                                <i class="fas fa-exclamation-triangle text-amber-500 mt-0.5"></i>
                                <div>
                                    <div class="font-bold text-amber-800 text-sm">Camera Unavailable on HTTP</div>
                                    <p class="text-xs text-amber-700 mt-1">Browsers require <strong>HTTPS</strong> to access the camera. Since this server is on HTTP, enter the session code shown on the teacher's screen manually.</p>
                                </div>
                            </div>
                        </div>
                        <div class="flex flex-col sm:flex-row gap-3">
                            <input id="manualSessionId" type="text" placeholder="Paste session ID (e.g. qr_17â€¦)" class="flex-1 px-4 py-3 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-500 bg-white text-sm font-mono" />
                            <button id="submitManualBtn" class="bg-gradient-to-r from-emerald-500 to-teal-600 text-white px-6 py-3 rounded-xl font-bold text-sm hover:shadow-lg hover:shadow-emerald-500/20 transition flex items-center justify-center space-x-2">
                                <i class="fas fa-check-circle"></i>
                                <span>Submit</span>
                            </button>
                        </div>
                        <button id="backToScanBtn" class="mt-3 text-xs text-slate-500 hover:text-emerald-700 underline underline-offset-2 transition">
                            â† Try camera scanner instead
                        </button>
                    </div>

                    <!-- Camera Viewport (Hidden initially) -->
                    <div id="cameraSection" class="hidden w-full">
                        <div id="reader" class="mb-4 rounded-xl overflow-hidden border border-slate-200 bg-black shadow-inner"></div>
                        <button id="stopScanBtn" class="bg-rose-50 hover:bg-rose-100 border border-rose-200 text-rose-600 px-4 py-2 rounded-xl text-xs font-semibold transition flex items-center space-x-1">
                            <i class="fas fa-stop-circle"></i>
                            <span>Close Scanner</span>
                        </button>
                    </div>

                    <!-- Result Panel -->
                    <div id="resultSection" class="hidden mt-4"></div>
                </div>
            </div>

            <!-- Permission guidelines -->
            <div id="permissionGuide" class="rounded-2xl p-6 mb-8" style="background:rgba(99,102,241,0.06);border:1px solid rgba(99,102,241,0.2);">
                <h3 class="text-sm font-bold mb-2 flex items-center space-x-2" style="color:#a5b4fc;">
                    <i class="fas fa-info-circle"></i>
                    <span>Scanner Requirements Checklist</span>
                </h3>
                <ul class="list-disc list-inside space-y-1 text-xs leading-relaxed" style="color:#818cf8;">
                    <li>Grant camera access when prompted by the browser.</li>
                    <li>Grant location (GPS) access; this application validates physical classroom presence.</li>
                    <li>If permissions are blocked, click the lock icon ðŸ”’ in the URL bar to update access rights.</li>
                </ul>
            </div>

            <!-- Student History Log -->
            <div class="rounded-2xl p-6" style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);">
                <h3 class="text-lg font-bold mb-4 flex items-center space-x-2" style="color:#f1f5f9;">
                    <i class="fas fa-history" style="color:#34d399;"></i>
                    <span>My Attendance Log</span>
                </h3>
                <div id="attendanceHistory" class="space-y-3 max-h-[350px] overflow-y-auto pr-1">
                    <p class="text-sm italic" style="color:#475569;">Loading history records...</p>
                </div>
            </div>
        </div>

        </div> <!-- end position:relative wrapper -->

        <script>
            let html5QrCode = null;
            let currentStudentId = 's1';

            // Persistent device ID stored in localStorage so every physical device
            // gets a unique fingerprint even when sharing the same WiFi/NAT IP.
            function getClientId() {
                let id = localStorage.getItem('attendx_client_id');
                if (!id) {
                    id = 'cid_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
                    localStorage.setItem('attendx_client_id', id);
                }
                return id;
            }

            // Track successfully marked sessions so the device can't re-scan them.
            function getMarkedSessions() {
                try { return JSON.parse(localStorage.getItem('attendx_marked') || '{}'); } catch { return {}; }
            }
            function markSessionDone(sessionId, studentId) {
                const marked = getMarkedSessions();
                marked[studentId + '_' + sessionId] = true;
                localStorage.setItem('attendx_marked', JSON.stringify(marked));
            }
            function hasMarkedSession(sessionId, studentId) {
                return !!getMarkedSessions()[studentId + '_' + sessionId];
            }

            // Detect HTTP (no camera support) and show warning on load
            if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
                // Running over HTTP on a remote IP â€” camera will be blocked by the browser
                // Automatically show manual entry mode
                document.addEventListener('DOMContentLoaded', function() {
                    showManualEntry();
                });
            }

            function showManualEntry() {
                document.getElementById('scannerSection').classList.add('hidden');
                document.getElementById('cameraSection').classList.add('hidden');
                document.getElementById('manualSection').classList.remove('hidden');
            }

            function showScannerSection() {
                document.getElementById('scannerSection').classList.remove('hidden');
                document.getElementById('cameraSection').classList.add('hidden');
                document.getElementById('manualSection').classList.add('hidden');
            }

            // Manual entry toggle buttons
            document.getElementById('manualEntryToggle').addEventListener('click', showManualEntry);
            document.getElementById('backToScanBtn').addEventListener('click', showScannerSection);

            // Submit manual session ID
            document.getElementById('submitManualBtn').addEventListener('click', async function() {
                const sessionId = document.getElementById('manualSessionId').value.trim();
                if (!sessionId) {
                    document.getElementById('manualSessionId').focus();
                    return;
                }
                await onScanSuccess(sessionId, null);
                document.getElementById('manualSessionId').value = '';
            });

            // Allow pressing Enter in manual input
            document.getElementById('manualSessionId').addEventListener('keydown', function(e) {
                if (e.key === 'Enter') document.getElementById('submitManualBtn').click();
            });

            // Update student name when selection changes
            document.getElementById('studentSelect').addEventListener('change', function() {
                currentStudentId = this.value;
                const selectedText = this.options[this.selectedIndex].text.split(' (')[0];
                document.getElementById('studentName').textContent = selectedText;
                loadAttendanceHistory();
            });

            // Start scanner
            document.getElementById('startScanBtn').addEventListener('click', async function() {
                // Guard: don't allow scanning if already successfully marked (checked after scan)
                try {
                    document.getElementById('permissionGuide').classList.add('hidden');
                    document.getElementById('scannerSection').classList.add('hidden');
                    document.getElementById('cameraSection').classList.remove('hidden');
                    document.getElementById('resultSection').classList.add('hidden');

                    html5QrCode = new Html5Qrcode("reader");
                    await html5QrCode.start(
                        { facingMode: "environment" },
                        { fps: 10, qrbox: 250 },
                        onScanSuccess,
                        onScanError
                    );
                } catch (error) {
                    console.error('Camera error:', error);
                    
                    const resultSection = document.getElementById('resultSection');
                    let errorMessage = '';
                    
                    const isHttpBlock = error.name === 'NotAllowedError' ||
                        (error.message && (error.message.includes('NotAllowedError') || error.message.includes('secure')));
                    const isHttpOrigin = location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1';

                    if (isHttpOrigin || isHttpBlock) {
                        errorMessage = \`
                            <div class="bg-amber-50 border border-amber-200 rounded-xl p-4">
                                <div class="flex items-start">
                                    <i class="fas fa-lock text-lg text-amber-500 mr-3 mt-0.5"></i>
                                    <div>
                                        <div class="font-bold text-amber-800 text-sm mb-1">HTTPS Required for Camera</div>
                                        <p class="text-xs text-amber-700 mb-3">Mobile browsers only allow camera access on <strong>https://</strong> sites. This dev server uses <strong>http://</strong>.</p>
                                        <p class="text-xs text-amber-700 font-semibold">ðŸ‘‡ Use the manual session code entry below instead:</p>
                                    </div>
                                </div>
                            </div>
                        \`;
                        resultSection.innerHTML = errorMessage;
                        resultSection.classList.remove('hidden');
                        showManualEntry();
                    } else if (error.name === 'NotFoundError') {
                        errorMessage = \`
                            <div class="bg-rose-50 border border-rose-200 rounded-xl p-4">
                                <div class="flex items-start">
                                    <i class="fas fa-video-slash text-lg text-rose-600 mr-3 mt-0.5"></i>
                                    <div>
                                        <div class="font-bold text-rose-800 text-sm">No Camera Detected</div>
                                        <p class="text-xs text-rose-700 mt-1">Make sure you have a working camera or open this page on a mobile device.</p>
                                    </div>
                                </div>
                            </div>
                        \`;
                        resultSection.innerHTML = errorMessage;
                        resultSection.classList.remove('hidden');
                        document.getElementById('permissionGuide').classList.remove('hidden');
                        document.getElementById('scannerSection').classList.remove('hidden');
                        document.getElementById('cameraSection').classList.add('hidden');
                    } else {
                        errorMessage = \`
                            <div class="bg-rose-50 border border-rose-200 rounded-xl p-4">
                                <div class="flex items-start">
                                    <i class="fas fa-exclamation-circle text-lg text-rose-600 mr-3 mt-0.5"></i>
                                    <div>
                                        <div class="font-bold text-rose-800 text-sm">Scanner Error</div>
                                        <p class="text-xs text-rose-700 mt-1">\${error.message || error}</p>
                                    </div>
                                </div>
                            </div>
                        \`;
                        resultSection.innerHTML = errorMessage;
                        resultSection.classList.remove('hidden');
                        document.getElementById('permissionGuide').classList.remove('hidden');
                        document.getElementById('scannerSection').classList.remove('hidden');
                        document.getElementById('cameraSection').classList.add('hidden');
                    }
                }
            });

            // Stop scanner
            document.getElementById('stopScanBtn').addEventListener('click', stopScanner);

            async function stopScanner() {
                if (html5QrCode) {
                    try {
                        await html5QrCode.stop();
                        html5QrCode.clear();
                    } catch (error) {
                        console.error('Error stopping scanner:', error);
                    }
                }
                document.getElementById('scannerSection').classList.remove('hidden');
                document.getElementById('cameraSection').classList.add('hidden');
            }

            // Handle successful scan
            async function onScanSuccess(decodedText, decodedResult) {
                await stopScanner();
                
                const resultSection = document.getElementById('resultSection');
                resultSection.innerHTML = \`
                    <div class="flex items-center justify-center space-x-2 bg-slate-50 border border-slate-200 p-4 rounded-xl">
                        <i class="fas fa-spinner fa-spin text-emerald-600 text-xl"></i>
                        <span class="text-sm font-semibold text-slate-700">Verifying presence and marking attendance...</span>
                    </div>
                \`;
                resultSection.classList.remove('hidden');

                let position;
                try {
                    position = await new Promise((resolve, reject) => {
                        navigator.geolocation.getCurrentPosition(resolve, reject, {
                            enableHighAccuracy: true,
                            timeout: 8000,
                            maximumAge: 0
                        });
                    });
                } catch (geoError) {
                    resultSection.innerHTML = \`
                        <div class="bg-rose-50 border border-rose-200 rounded-xl p-4">
                            <div class="flex items-start">
                                <i class="fas fa-map-marker-alt text-lg text-rose-600 mr-3 mt-0.5"></i>
                                <div>
                                    <div class="font-bold text-rose-800 text-sm mb-1">GPS Coordinates Required</div>
                                    <p class="text-xs text-rose-700">Unable to locate your device. Please ensure location services (GPS) are active and allow browser location permissions.</p>
                                </div>
                            </div>
                        </div>
                    \`;
                    return;
                }

                try {
                    // Check locally first â€” if this device already successfully marked this session, block immediately
                    if (hasMarkedSession(decodedText, currentStudentId)) {
                        resultSection.innerHTML = \`
                            <div class="bg-amber-50 border border-amber-200 rounded-xl p-4">
                                <div class="flex items-start">
                                    <div class="w-8 h-8 rounded-full bg-amber-400 text-white flex items-center justify-center mr-3 flex-shrink-0">
                                        <i class="fas fa-check"></i>
                                    </div>
                                    <div>
                                        <div class="font-bold text-amber-800 text-sm">Already Marked</div>
                                        <p class="text-xs text-amber-700 mt-0.5">Your attendance for this session has already been successfully recorded on this device.</p>
                                    </div>
                                </div>
                            </div>
                        \`;
                        return;
                    }

                    const response = await axios.post('/api/scan-qr', {
                        qrData: decodedText,
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude,
                        studentId: currentStudentId,
                        clientId: getClientId()
                    });

                    resultSection.innerHTML = \`
                        <div class="bg-emerald-50 border border-emerald-200 rounded-xl p-4">
                            <div class="flex items-start">
                                <div class="w-8 h-8 rounded-full bg-emerald-500 text-white flex items-center justify-center mr-3 flex-shrink-0">
                                    <i class="fas fa-check"></i>
                                </div>
                                <div>
                                    <div class="font-bold text-emerald-800 text-sm">Attendance Marked Successfully!</div>
                                    <p class="text-xs text-emerald-700 mt-0.5">\${response.data.class.name} (\${response.data.class.code})</p>
                                    <div class="inline-block mt-2 text-[10px] font-bold px-2 py-0.5 bg-emerald-100 text-emerald-800 rounded">
                                        Distance: \${response.data.distance} meters
                                    </div>
                                </div>
                            </div>
                        </div>
                    \`;

                    // Persist this successful mark so this device cannot re-scan this session
                    markSessionDone(decodedText, currentStudentId);

                    loadAttendanceHistory();

                    // Lock the scan button with a permanent success indicator
                    const startBtn = document.getElementById('startScanBtn');
                    startBtn.disabled = true;
                    startBtn.className = 'w-full md:w-auto bg-emerald-100 border border-emerald-300 text-emerald-700 px-6 py-3.5 rounded-xl font-bold flex items-center justify-center space-x-2 text-sm cursor-not-allowed';
                    startBtn.innerHTML = '<i class="fas fa-check-circle"></i><span>Attendance Marked âœ“</span>';

                    // Also lock the manual submit button
                    const manualBtn = document.getElementById('submitManualBtn');
                    manualBtn.disabled = true;
                    manualBtn.className = 'bg-emerald-100 border border-emerald-300 text-emerald-700 px-6 py-3 rounded-xl font-bold text-sm flex items-center justify-center space-x-2 cursor-not-allowed';

                    // Result stays visible â€” no auto-hide after success
                    // (removed the 8-second hide timeout so the student can clearly see they're done)

                } catch (error) {
                    if (error.response?.data?.error) {
                        const errorMsg = error.response.data.error;
                        resultSection.innerHTML = \`
                            <div class="bg-rose-50 border border-rose-200 rounded-xl p-4">
                                <div class="flex items-start">
                                    <i class="fas fa-exclamation-circle text-lg text-rose-600 mr-3 mt-0.5"></i>
                                    <div>
                                        <div class="font-bold text-rose-800 text-sm">Check-in Blocked</div>
                                        <p class="text-xs text-rose-700 mt-0.5">\${errorMsg}</p>
                                    </div>
                                </div>
                            </div>
                        \`;
                    } else {
                        resultSection.innerHTML = \`
                            <div class="bg-rose-50 border border-rose-200 rounded-xl p-4">
                                <div class="flex items-start">
                                    <i class="fas fa-exclamation-circle text-lg text-rose-600 mr-3 mt-0.5"></i>
                                    <div>
                                        <div class="font-bold text-rose-800 text-sm">Communication Failure</div>
                                        <p class="text-xs text-rose-700 mt-0.5">\${error.message || 'Unknown network error'}</p>
                                    </div>
                                </div>
                            </div>
                        \`;
                    }
                }
            }

            function onScanError(errorMessage) {
                // Ignore scanning cycle errors (default logging can be too noisy)
            }

            // Load attendance history
            async function loadAttendanceHistory() {
                try {
                    const response = await axios.get('/api/student/attendance?studentId=' + currentStudentId);
                    const historyDiv = document.getElementById('attendanceHistory');
                    
                    if (response.data.attendance.length === 0) {
                        historyDiv.innerHTML = '<div class="text-slate-400 text-xs italic text-center py-8">No attendance records logged.</div>';
                    } else {
                        historyDiv.innerHTML = response.data.attendance.map(att => \`
                            <div class="flex items-center justify-between p-3.5 bg-slate-50/60 hover:bg-slate-50 rounded-xl border border-slate-200/50 transition">
                                <div class="flex items-center space-x-3">
                                    <div class="w-8 h-8 rounded-full bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-600 text-xs font-bold">
                                        \${att.class_name.charAt(0)}
                                    </div>
                                    <div>
                                        <div class="font-bold text-slate-800 text-sm">\${att.class_name}</div>
                                        <div class="text-[10px] text-slate-500 font-semibold mt-0.5">Prof. \${att.teacher_name} | \${att.class_code}</div>
                                    </div>
                                </div>
                                <div class="text-right text-xs">
                                    <div class="text-emerald-600 font-bold flex items-center justify-end space-x-1">
                                        <i class="fas fa-check-circle"></i>
                                        <span>Present</span>
                                    </div>
                                    <div class="text-[9px] text-slate-400 font-medium mt-1">
                                        \${new Date(att.marked_at).toLocaleDateString()} \${new Date(att.marked_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                                    </div>
                                </div>
                            </div>
                        \`).join('');
                    }
                } catch (error) {
                    console.error('Error loading attendance history:', error);
                    document.getElementById('attendanceHistory').innerHTML = '<div class="text-rose-500 text-xs italic text-center py-8">Failed to retrieve historical logs.</div>';
                }
            }

            // Add logout handler for student
            const studentLogoutBtn = document.getElementById('studentLogoutBtn');
            if (studentLogoutBtn) {
                studentLogoutBtn.addEventListener('click', async function() {
                    try { await axios.post('/api/student/logout'); } catch(e) {}
                    window.location.href = '/student/login';
                });
            }

            // Initialize
            loadAttendanceHistory();
        </script>
    </body>
    </html>
  `);
});

export default app;
