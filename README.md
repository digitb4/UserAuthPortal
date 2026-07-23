# UserAuthPortal

Authentication portal with JWT, MFA via TOTP, session management, and role-based access control.

## Stack

- TypeScript
- Node.js 20
- Express 4.17.1
- MongoDB (via Mongoose)
- JWT Authentication
- bcryptjs for password hashing

## Setup

```bash
npm install
npm run build
npm start
```

## Development

```bash
npm run dev
```

## Testing

```bash
npm test
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/auth/register | Register new user |
| POST | /api/auth/login | Login |
| POST | /api/auth/logout | Logout |
| POST | /api/auth/forgot-password | Request password reset |
| POST | /api/auth/reset-password | Reset password with token |
| GET | /api/profile | Get user profile |
| PUT | /api/profile | Update user profile |
| GET | /api/profile/me | Get own profile |
| GET | /api/admin/users | List all users (admin) |
| PUT | /api/admin/users/:id/role | Change user role (admin) |
| DELETE | /api/admin/users/:id | Delete user (admin) |

<!-- SonarCloud PR analysis trigger -->
