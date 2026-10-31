# Pine Lake Student Check-In

Public tablet interface for student check-in and check-out. Student names and attendance are stored in a dedicated Neon Postgres database and accessed through Vercel serverless API routes. The browser does not write student records to local storage.

## Cloud configuration

Create these Vercel Production environment variables as Sensitive:

- DATABASE_URL: pooled Neon connection string for the checkin_app role
- CHECKIN_SESSION_SECRET: a random 64-character hex string
- CHECKIN_SETUP_TOKEN: a one-time random token for first admin setup

Do not commit these values to GitHub. The first admin uses CHECKIN_SETUP_TOKEN once to set the real admin passcode; after setup, the endpoint refuses further setup attempts. Admin sessions use secure, HTTP-only cookies. Admin login is limited after repeated failed attempts.

## Database

The schema is in db/migrations/001_checkin_schema.sql. It is applied to the dedicated pine-lake-student-checkin Neon project, not the Parent Manager or MatchFlow databases.
