'use server'

import { createAuthSession } from '@/lib/auth'
import { hashUserPassword } from '@/lib/hash'
import { createUser } from '@/lib/user'
import { redirect } from 'next/navigation'

export async function signUp(prevState, formData) {
  const email = formData.get('email')
  const password = formData.get('password')

  let errors = {}
  if (!email.includes('@')) {
    errors.email = 'Please enter a valid email address'
  }

  if (password.trim().length < 8) {
    errors.password = 'Password must be at least 8 characters long.'
  }

  if (Object.keys(errors).length > 0) {
    return {
      errors,
    }
  }

  const hashedPassword = hashUserPassword(password)

  try {
    //store it in the db (create a new user)
    const userId = createUser(email, hashedPassword)

    await createAuthSession(userId)

    redirect('/training')
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return {
        errors: {
          email: 'It seems like an account for the chosen email already exists',
        },
      }
    }
    throw err
  }
}
