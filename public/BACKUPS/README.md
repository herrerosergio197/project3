# Blog with articles + embedded login

This project serves a blog-style page where:

- **Public articles** are visible without authentication.
- The **login panel** lives **inside the blog** (in the sidebar column), not on top.
- After signing in, a **members-only** section is enabled.

## How to run

In PowerShell (from the project root):

```powershell
npm install
npm start
```

Then open `http://localhost:3000`.

## MySQL (comments persistence)

Comments are stored in MySQL so they persist across server restarts.

Set these environment variables before running:

- `MYSQL_HOST`
- `MYSQL_PORT` (optional, default `3306`)
- `MYSQL_USER`
- `MYSQL_PASSWORD`
- `MYSQL_DATABASE` (default `blog`)

The server will create the `comments` table automatically (if the database exists and the user has permission).

## Demo users

- `demo` / `demo1234`
- `editor` / `editor1234`

## Structure

- `public/server.js`: login API (`/api/login`, `/api/me`, `/api/logout`) + static files.
- `public/index.html`: blog UI + sidebar access panel.
- `public/about.html`: about page.
- `public/app.js`: blog logic + authentication (token stored in `localStorage`).
- `public/styles.css`: styles.

