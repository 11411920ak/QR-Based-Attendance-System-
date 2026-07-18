// Authentication utilities for Cloudflare Workers environment
// Using Web Crypto API (compatible with Cloudflare Workers)

import { SignJWT, jwtVerify } from 'jose'

// Types
export interface User {
  id: number
  email: string
  role: 'admin' | 'teacher' | 'student'
  isActive: boolean
}

export interface JWTPayload {
  userId: number
  email: string
  role: string
  iat?: number
  exp?: number
}

// JWT Secret - Must match the JWT_SECRET var in wrangler.jsonc
const JWT_SECRET = new TextEncoder().encode(
  'your-secret-key-change-in-production-min-32-chars-attendance-system-2025'
)

// Password hashing using Web Crypto API (bcrypt alternative for Cloudflare Workers)
export async function hashPassword(password: string): Promise<string> {
  // Using PBKDF2 with Web Crypto API (works in Cloudflare Workers)
  const encoder = new TextEncoder()
  const data = encoder.encode(password)

  // Generate random salt
  const salt = crypto.getRandomValues(new Uint8Array(16))

  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    data,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  )

  // Derive key using PBKDF2
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  )

  // Combine salt and hash
  const hashArray = new Uint8Array(derivedBits)
  const combined = new Uint8Array(salt.length + hashArray.length)
  combined.set(salt)
  combined.set(hashArray, salt.length)

  // Convert to base64
  return btoa(String.fromCharCode(...combined))
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    // Decode base64 hash
    const combined = Uint8Array.from(atob(hash), c => c.charCodeAt(0))

    // Extract salt (first 16 bytes) and stored hash
    const salt = combined.slice(0, 16)
    const storedHash = combined.slice(16)

    // Hash the provided password with the same salt
    const encoder = new TextEncoder()
    const data = encoder.encode(password)

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      data,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    )

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    )

    const computedHash = new Uint8Array(derivedBits)

    // Compare hashes (constant-time comparison)
    if (computedHash.length !== storedHash.length) return false

    let diff = 0
    for (let i = 0; i < computedHash.length; i++) {
      diff |= computedHash[i] ^ storedHash[i]
    }

    return diff === 0
  } catch (error) {
    console.error('Password verification error:', error)
    return false
  }
}

// JWT token generation
export async function generateToken(payload: JWTPayload): Promise<string> {
  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d') // Token expires in 7 days
    .sign(JWT_SECRET)

  return token
}

// JWT token verification
export async function verifyToken(token: string): Promise<JWTPayload | null> {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET)
    return payload as JWTPayload
  } catch (error) {
    console.error('Token verification error:', error)
    return null
  }
}

// Hash token for storage (for session management)
export async function hashToken(token: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(token)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

// Generate random token for password reset
export function generateRandomToken(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('')
}

// Extract token from Authorization header
export function extractToken(authHeader: string | null): string | null {
  if (!authHeader) return null

  const parts = authHeader.split(' ')
  if (parts.length !== 2 || parts[0] !== 'Bearer') return null

  return parts[1]
}

// Get user from database by ID
export async function getUserById(db: D1Database, userId: number): Promise<User | null> {
  const user = await db.prepare(`
    SELECT id, email, role, is_active as isActive
    FROM users
    WHERE id = ?
  `).bind(userId).first()

  return user as User | null
}

// Get user by email
export async function getUserByEmail(db: D1Database, email: string): Promise<any | null> {
  const user = await db.prepare(`
    SELECT id, email, password_hash, role, is_active as isActive
    FROM users
    WHERE email = ?
  `).bind(email).first()

  return user
}

// Create session in database
export async function createSession(
  db: D1Database,
  userId: number,
  token: string
): Promise<void> {
  const tokenHash = await hashToken(token)
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days

  await db.prepare(`
    INSERT INTO sessions (user_id, token_hash, expires_at)
    VALUES (?, ?, ?)
  `).bind(userId, tokenHash, expiresAt.toISOString()).run()
}

// Verify session exists in database
export async function verifySession(
  db: D1Database,
  token: string
): Promise<boolean> {
  const tokenHash = await hashToken(token)

  const session = await db.prepare(`
    SELECT id FROM sessions
    WHERE token_hash = ? AND expires_at > datetime('now')
  `).bind(tokenHash).first()

  return !!session
}

// Delete session (logout)
export async function deleteSession(
  db: D1Database,
  token: string
): Promise<void> {
  const tokenHash = await hashToken(token)

  await db.prepare(`
    DELETE FROM sessions WHERE token_hash = ?
  `).bind(tokenHash).run()
}

// Clean expired sessions
export async function cleanExpiredSessions(db: D1Database): Promise<void> {
  await db.prepare(`
    DELETE FROM sessions WHERE expires_at < datetime('now')
  `).run()
}

// Get teacher ID by user ID
export async function getTeacherIdByUserId(db: D1Database, userId: number): Promise<string | null> {
  const teacher = await db.prepare(`
    SELECT id FROM teachers WHERE user_id = ?
  `).bind(userId).first()

  return teacher?.id as string | null
}

// Get student ID by user ID
export async function getStudentIdByUserId(db: D1Database, userId: number): Promise<string | null> {
  const student = await db.prepare(`
    SELECT id FROM students WHERE user_id = ?
  `).bind(userId).first()

  return student?.id as string | null
}

// Get user by username (for teacher/student login)
export async function getUserByUsername(db: D1Database, username: string): Promise<any | null> {
  const user = await db.prepare(`
    SELECT id, username, email, password_hash, role, is_active as isActive
    FROM users
    WHERE username = ?
  `).bind(username).first()
  return user
}
