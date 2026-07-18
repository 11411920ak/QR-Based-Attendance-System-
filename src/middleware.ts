// Authentication middleware for Hono
import { Context, Next } from 'hono'
import { getCookie } from 'hono/cookie'
import { extractToken, verifyToken, verifySession, getUserById } from './auth'

type Bindings = {
  DB: D1Database
}

// Extend Context to include user information
export interface AuthContext extends Context {
  env: Bindings
  var: {
    user?: {
      id: number
      email: string
      role: 'admin' | 'teacher' | 'student'
      isActive: boolean
    }
  }
}

// Middleware to verify JWT token
export async function authMiddleware(c: AuthContext, next: Next) {
  const { DB } = c.env

  // Try to get token from Authorization header
  let token = extractToken(c.req.header('Authorization'))

  // If not in header, try cookie
  if (!token) {
    token = getCookie(c, 'auth_token')
  }

  if (!token) {
    return c.json({ success: false, error: 'Authentication required' }, 401)
  }

  // Verify JWT token
  const payload = await verifyToken(token)
  if (!payload) {
    return c.json({ success: false, error: 'Invalid or expired token' }, 401)
  }

  // Verify session exists in database
  const sessionValid = await verifySession(DB, token)
  if (!sessionValid) {
    return c.json({ success: false, error: 'Session expired or invalid' }, 401)
  }

  // Get user from database
  const user = await getUserById(DB, payload.userId)
  if (!user || !user.isActive) {
    return c.json({ success: false, error: 'User not found or inactive' }, 401)
  }

  // Attach user to context
  c.set('user', user)

  await next()
}

// Middleware to check for specific role
export function requireRole(...allowedRoles: ('admin' | 'teacher' | 'student')[]) {
  return async (c: AuthContext, next: Next) => {
    const user = c.get('user')

    if (!user) {
      return c.json({ success: false, error: 'Authentication required' }, 401)
    }

    if (!allowedRoles.includes(user.role)) {
      return c.json({
        success: false,
        error: `Access denied. Required role: ${allowedRoles.join(' or ')}`
      }, 403)
    }

    await next()
  }
}

// Optional authentication - doesn't fail if no token
export async function optionalAuth(c: AuthContext, next: Next) {
  const { DB } = c.env

  let token = extractToken(c.req.header('Authorization'))
  if (!token) {
    token = getCookie(c, 'auth_token')
  }

  if (token) {
    const payload = await verifyToken(token)
    if (payload) {
      const user = await getUserById(DB, payload.userId)
      if (user && user.isActive) {
        c.set('user', user)
      }
    }
  }

  await next()
}
