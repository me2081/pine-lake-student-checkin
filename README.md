# Pine Lake Student Check-In

Public tablet interface for student check-in and check-out. Students enter a 3-digit code; the public screen does not download or display the roster. The admin-only panel shows each student’s code for staff to retrieve when needed. Names and attendance are stored in a dedicated Neon Postgres database and accessed through Vercel serverless API routes. The browser does not write student records to local storage.

## Cloud configuration

Create these Vercel Production environment variables as Sensitive:

- DATABASE_URL: pooled Neon connection string for the checkin_app role
- CHECKIN_SESSION_SECRET: a random 64-character hex string
- CHECKIN_SETUP_TOKEN: a one-time random token for first admin setup

Do not commit these values to GitHub. The first admin uses CHECKIN_SETUP_TOKEN once to set the real admin passcode; after setup, the endpoint refuses further setup attempts. Admin sessions use secure, HTTP-only cookies. Admin login is limited after repeated failed attempts.

## Database

Apply SQL migrations in order from db/migrations. Migration 002 adds student codes and code-entry rate limiting to the dedicated pine-lake-student-checkin Neon project, not the Parent Manager or MatchFlow databases.
