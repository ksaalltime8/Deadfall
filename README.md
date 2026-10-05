# DEADFALL — Online Zombie Survival

A functional full-stack multiplayer browser-game foundation. It includes:
- Node.js + Express API
- Socket.IO real-time shared world/presence/events
- SQLite persistence for easy local development
- Server-authoritative resources, buildings, missions and combat
- Registration/login with bcrypt + JWT
- Live player map and rankings
- Server-protected private admin panel
- Admin horde and broadcast controls
- Responsive dark military UI

## Run on Windows
1. Install Node.js 20+.
2. Copy `.env.example` to `.env` and change `JWT_SECRET` and admin credentials.
3. In this folder run `npm install`.
4. Run `npm start`.
5. Open `http://localhost:5500`.

## Default admin
The account is created on first startup using `ADMIN_EMAIL` and `ADMIN_PASSWORD` from `.env`. Change both before exposing the server publicly.

## Production
This is a complete playable foundation, not a final AAA production backend. Before public launch, move persistence to MySQL/PostgreSQL, add HTTPS, reverse proxy, CSRF protection if cookie sessions are introduced, durable session/revocation storage, migrations, backups, moderation tooling, anti-cheat telemetry, and load testing.
