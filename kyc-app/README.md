# KYC Age Verification App (21+)

Simple Node.js application to verify a user is 21 years or older via date of birth and ID image upload.

## Setup

```bash
cd kyc-app
npm install
npm start
```

App runs at http://localhost:3000 and serves the form at `/`.

## API

`POST /api/verify` multipart/form-data fields:
- `name` (string)
- `dob` (YYYY-MM-DD)
- `idImage` (file)

Returns JSON `{ success: boolean, message: string, file?: string }`.