# Pine Lake Student Check-In

A simple tablet app for student check-in and check-out.

## Data

The app stores student names, attendance, and the admin passcode verifier in the tablet browser's local storage. Data does not sync to other devices. Download the JSON backup regularly before clearing browser data or changing tablets.

The admin passcode only hides the admin controls in this browser. It is not server-side authentication; do not store sensitive information in this app.

## Run

Open `index.html` in a browser, or deploy this static repository with Vercel.