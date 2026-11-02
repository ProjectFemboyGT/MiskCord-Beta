# MiskCord

A small chat app: accounts, friend requests, live DMs and a shared HQ channel.

## Run locally
```
pip install -r requirements.txt
uvicorn server:app --port 8000
```
Without `DATABASE_URL` it stores data in a local `miskcord.db` SQLite file.

## Deploy on Render (free)
1. Create a free Postgres database at https://neon.tech and copy its connection string.
2. Push this folder to a GitHub repo.
3. On https://render.com: New > Blueprint, pick the repo (uses `render.yaml`), paste the Neon string as `DATABASE_URL`.
4. Open the `onrender.com` URL and register the owner username first.
