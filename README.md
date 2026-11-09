# Bundle Auditor

Paste a website URL. Every script on the page becomes a tower in a 3D city. Taller means heavier. The tool also flags possible leaked API keys, third-party scripts and exposed source maps.

## Run locally

Needs Node 20 or newer. No dependencies to install.

```bash
npm start
```

Open http://localhost:3000. Run the tests with `npm test`.

## Deploy (Render, free tier)

1. Push this repo to GitHub.
2. On render.com choose New, then Blueprint, and pick this repo. `render.yaml` sets everything up.
3. Render gives you a public `https://...onrender.com` address.

GitHub Pages cannot host this app because it needs a running server for the scan API.

## Before going public

- Add a per-visitor scan limit. Right now anyone can run unlimited scans.
- The private-address block resolves DNS twice. Pin the resolved IP before facing hostile users.
- Only scan sites you own or have permission to scan.
