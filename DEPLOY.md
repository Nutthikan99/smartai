# Deploy guide

## Frontend (Cloudflare Pages)
1. Upload the frontend bundle to Cloudflare Pages.
2. Set custom domain to `innovetixai.com` or `www.innovetixai.com`.
3. The frontend calls `https://api.innovetixai.com` by default.

## Backend (recommended: Railway)
1. Create a new Railway project.
2. Deploy the `backend/` folder.
3. Add the environment variables from `backend/.env.example`.
4. After deploy, you will get a public HTTPS URL such as `https://smartkey-api.up.railway.app`.

## Custom domain for backend
In Cloudflare DNS, create a record for:
- `api.innovetixai.com` -> your backend host

Then set:
- `FRONTEND_ORIGIN=https://innovetixai.com`
- `FRONTEND_PREVIEW_ORIGIN=https://smartkey.pages.dev`

## Local test flow
1. Start backend locally.
2. Call `POST /api/create-payment-session`.
3. Open frontend with `window.SMARTKEY_API_BASE = 'http://127.0.0.1:8000'` in the console or update `API_BASE`.
4. Trigger `POST /api/mock-pay/{transaction_id}`.
5. Frontend will show the 4-digit PIN automatically.
