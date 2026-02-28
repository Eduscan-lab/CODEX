# Registration and Login System

Simple authentication app using:
- Node.js + Express
- SQLite (`better-sqlite3`)
- Password hashing with `bcryptjs`
- Session-based auth with `express-session`

## Features
- User registration
- User login
- Protected dashboard route
- Session check endpoint (`/me`)
- Logout

## Run
1. Install dependencies:
   ```bash
   npm install
   ```
2. Start server:
   ```bash
   npm start
   ```
3. Open:
   `http://localhost:3000`

## Security Note
Set a strong production session secret:
```bash
SESSION_SECRET=your-long-random-secret
```
