# Moonlite RSVP

Moonlite RSVP is a small party invitation app for `moonlite.rsvp`.

It includes:

- Vite + React frontend
- Vercel Functions API routes
- RSVP confirmation email through Resend
- webhook endpoint protected by a signing secret
- Cloudflare/Vercel-ready domain config

## Development

```zsh
npm install
npm run dev
```

## Build

```zsh
npm run build
```

Required environment variables:

```text
NEXT_PUBLIC_APP_URL
RESEND_API_KEY
RESEND_FROM_EMAIL
RESEND_AUDIENCE_ID
WEBHOOK_SECRET
```
