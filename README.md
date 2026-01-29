# cb-gateway-api

To install dependencies:

```bash
bun install
```

To set up environment variables:

```bash
cp .env.example .env.local
```

Then update the following required variables in `.env.local` with your actual credentials from the IPPS email:

| Variable | Description |
|----------|-------------|
| `CB_CLIENT_ID` | Your cu from IPPS |
| `CB_SECRET` | Your sc from IPPS |
| `CB_ACCESS_TOKEN` | Your access token from IPPS |
| `RSA_PUBLIC_KEY` | Your encryption key from IPPS |

To run:

```bash
bun run index.ts
```

This project was created using `bun init` in bun v1.3.6. [Bun](https://bun.com) is a fast all-in-one JavaScript runtime.
