# Public Domain Scan

This folder contains a standalone public-facing frontend for the existing domain scan workflow.

## Features
- Uses the existing backend public scan endpoints
- Supports environment-based API configuration via VITE_BACKEND_URL
- Can be hosted independently while continuing to use the same backend and database

## Run locally

```bash
npm install
npm run dev
```

Set the backend URL before running:

```bash
export VITE_BACKEND_URL=http://localhost:8000
```
