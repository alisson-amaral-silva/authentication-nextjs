import { BetterSqlite3Adapter } from '@lucia-auth/adapter-sqlite'
import { Lucia } from 'lucia'
import db from './db'
import { cookies } from 'next/headers'

const adapter = new BetterSqlite3Adapter(db, {
  user: 'users',
  session: 'sessions',
})

const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    attributes: {
      secure: process.env.NODE_ENV === 'production',
    },
  },
})

export async function createAuthSession(userId) {
  const session = await lucia.createSession(userId, {})
  const sessionCookie = lucia.createBlankSessionCookie(session.id)
  cookies().set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  )
}

export async function verifyAuth() {
  const sessionCookie = cookies().get(lucia.sessionCookieName)

  if (!sessionCookie) {
    return {
      user: null,
      session: null,
    }
  }

  const sessionId = sessionCookie.value
  const result = await lucia.validateSession(sessionId)

  try {
    if (result.session?.fresh) {
      const sessionCookie = lucia.createBlankSessionCookie(result.session.id)
      cookies().set(
        sessionCookie.name,
        sessionCookie.value,
        sessionCookie.attributes
      )
    }

    //clear existing cookie that has invalid data
    if (!result.session) {
      const sessionCookie = lucia.createBlankSessionCookie()
      cookies().set(
        sessionCookie.name,
        sessionCookie.value,
        sessionCookie.attributes
      )
    }
  } catch (err) {
    console.log('err ', err)
  }

  return result
}
