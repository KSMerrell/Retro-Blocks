# Retro Blox

A real multiplayer app: usernames and passwords, a saved database, live game servers, friends, messages, trading, groups, and games that players build and publish. It installs on phones and desktops like an app (Add to Home Screen / Install).

No dependencies. Needs Node 18 or newer.

## Run it on your computer
    node server.js
Open http://localhost:3000. Open it in two browsers, sign up twice, add each other, and play together.

## Put it online (so anyone can play)
Any host that runs Node works. Two easy ones:

**Render** (needs a paid instance because the database lives on a disk): create a Web Service from this folder (push it to GitHub first), or use render.yaml. Keep the disk, it holds your data.

**Fly.io / Railway / any VPS**: use the Dockerfile. Mount a persistent volume at /data. Use HTTPS (these hosts do it for you).

Environment variables: PORT (default 3000), DATA_DIR (default ./data, where db.json is saved). Back up DATA_DIR.

**Free hosting without losing accounts:** create a free Redis database at upstash.com and set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN on the server. Everything (accounts, items, games) is then saved there instead of on the server's disk, so it survives restarts and sleeping.

## How it works
- server.js: accounts (scrypt password hashes, cookie sessions), a document database saved to db.json, WebSocket live rooms for game servers and chat. Messages, trades and friend requests are only sent to the people involved. The server checks who may write each kind of document.
- public/: the app (app.html), login page, and manifest. three.js loads from cdnjs.

## Known limits (honest)
- The token and item economy is kept in each player's browser and sent to the server, so a technically skilled player could cheat themselves tokens. Making the server the only judge of purchases and rewards is the next big step before a large public launch.
- One server process with a single JSON file. Fine for hundreds of players; for thousands, move to a real database.
- No email, so there is no password reset yet. No moderation or reporting tools yet: add them before opening to children.
