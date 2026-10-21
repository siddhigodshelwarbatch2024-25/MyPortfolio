# Portfolio analytics

The existing HTML portfolio is served by `server.js`. Each visit is written to Render PostgreSQL. The homepage displays only the aggregate unique-visitor count; detailed analytics are available only to an authenticated owner at `/admin`.

## Privacy and attribution

Events contain a server timestamp, pathname without query parameters, source label, external referral hostname, coarse browser family, and coarse device type. A random first-party HTTP-only visitor cookie is HMAC-hashed before storage to estimate unique visitors. Raw IP addresses, full user-agent strings, full referral URLs, and page query strings are not stored. Cookie removal or blocking can cause repeat visitors to be counted as new. `utm_source` labels are supported. The public footer discloses tracking; update the privacy notice for applicable requirements in your jurisdiction.

## Render deployment

1. Connect this project to a Git repository and push the files. Make sure `package-lock.json` is committed; generate it with `npm.cmd install` from the project directory on Windows. Never commit `.env`, raw passwords, bcrypt hashes, or secrets.
2. In an interactive PowerShell terminal, run `npm.cmd run hash-password`. Type an owner password of at least 12 characters at the hidden prompt. Put the resulting bcrypt hash, not the password, into Render's `OWNER_PASSWORD_HASH` secret field.
3. Generate two independent secrets locally. Run `node -e "console.log(require('node:crypto').randomBytes(48).toString('hex'))"` twice. Add the outputs in Render as `SESSION_SECRET` and `TRACKING_SECRET`; keep them private.
4. In Render, choose **New > Blueprint**, select the connected repository, and review `render.yaml`. It creates the web service and an attached PostgreSQL database. The declared `starter` web and `basic-256mb` database plans are paid plans; use a supported persistent database plan if Render's Blueprint review offers different plan names. Do not use an expiring database for production analytics.
5. When prompted, enter `OWNER_PASSWORD_HASH`, `SESSION_SECRET`, and `TRACKING_SECRET` as secret environment values. `DATABASE_URL` is wired from the created database. Deploy and wait for the `/healthz` check to pass.
6. Open the deployed service root once to create a visit. Open `/admin` and sign in. Verify `/api/admin/analytics` returns `401` when signed out, then shows totals after sign-in. Test attribution by opening a URL such as `https://<service>.onrender.com/?utm_source=deployment-check` and confirm that source appears in the signed-in dashboard. A cross-site POST to the analytics endpoint should be rejected.
7. Keep the PostgreSQL database attached on future deploys and configure/verify backups and retention in Render for your selected plan. Deploying application code does not clear the attached database. Back up `TRACKING_SECRET` securely: rotating it changes visitor identity hashes and starts a new unique-visitor cohort.

## Local development

Install dependencies with `npm install`, provide a PostgreSQL `DATABASE_URL` and the three environment values above, then run `npm start` and open `http://localhost:3000`. A `file://` page or a static-only preview server cannot record events because it does not provide the backend endpoint. Local checks do not establish that Render's service, database, secrets, or public URL are configured correctly; verify the deployed URL after deployment.