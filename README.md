# TradeGuard: Stock Order Integrity Workspace

A multi-page HTML, CSS, JavaScript, and FastAPI paper-trading workspace. It creates sample stock order records, signs them with the browser's Web Crypto API, and stores accounts, orders, and activity in a local SQLite database.

## Run the project

Install the backend dependencies, then run the FastAPI server from this folder in PowerShell:

```powershell
py -m pip install -r requirements.txt
py -m uvicorn backend.main:app --reload
```

Open <http://localhost:8000> in a modern browser. The FastAPI app serves both the frontend and `/api` endpoints. If `py` is not available, use `python` instead. Set `TRADEGUARD_DB` to change the SQLite database location.

Static hosts such as S3 only serve the frontend; they cannot run this FastAPI backend. The backend can run as an AWS Lambda function exposed through a Lambda Function URL. Keep in mind that S3's static website endpoint is HTTP-only, while this app's digital signatures require a secure browser context. Without CloudFront, open the HTTPS S3 object URL for `index.html` (for example, `https://BUCKET.s3.REGION.amazonaws.com/index.html`), not the S3 website endpoint. The bucket must allow public reads of the frontend files.

### AWS S3 + Lambda Function URL

1. In `assets/js/config.js`, set `window.TRADEGUARD_API_BASE` to the Lambda Function URL origin, for example `https://abc123.lambda-url.us-east-1.on.aws` (no trailing slash and no `/api` suffix).
2. Package the project and its Python dependencies for Lambda. From the project root, install requirements into a staging directory and zip that directory together with the project files. Include `backend/`, `assets/`, `pages/`, and `index.html` in the deployment package:

   ```bash
   mkdir -p package
   python3 -m pip install -r requirements.txt --target package
   cp -r backend assets pages index.html package/
   cd package && zip -r ../tradeguard-lambda.zip . && cd ..
   ```

   Use a Linux-compatible Python environment matching the Lambda runtime when building dependencies. Configure the Lambda handler as `backend.lambda_handler.handler`.
3. Configure the Lambda Function URL with **Auth type: NONE** for this public browser demo. The API uses its own account login/session authentication; do not put real financial or sensitive data in this demo.
4. Set the Lambda environment variable `TRADEGUARD_ALLOWED_ORIGINS` to the exact HTTPS S3 object origin, such as `https://BUCKET.s3.REGION.amazonaws.com` (origin only, without `/index.html`). The FastAPI app handles CORS; leave the Function URL's separate CORS configuration disabled to avoid duplicate CORS headers.
5. Set `TRADEGUARD_DB` to a writable path. For a quick test, `/tmp/tradeguard.sqlite3` works, but Lambda storage is temporary and data can disappear or differ between execution environments. For persistent SQLite, mount EFS and set the path to a database file on that mount, ensuring the Lambda role, mount target, and file permissions allow writes. EFS-backed SQLite is suitable only for low-concurrency demo use; a production deployment should use a managed database.
6. Upload the frontend files (`index.html`, `pages/`, and `assets/`) to the S3 bucket. Use the HTTPS S3 object URL to open `index.html`. Test `https://YOUR_FUNCTION_URL_ID.lambda-url.REGION.on.aws/api/health`, then test registration in the browser. If you update `config.js`, upload it again and reload the page without cache.

The default `TRADEGUARD_ALLOWED_ORIGINS` is empty, which is suitable for the local same-origin setup. For AWS, the API only permits browser requests from the exact origin listed in that variable.

## Pages and files

```text
index.html                  Home page, project overview, and reference library
pages/
  register.html             Workspace profile form and client-side validation
  orders.html               Signed order form, orders table, and events table
  verify.html               Digital signature verification page
assets/
  css/styles.css            Shared layout, box model, Flexbox, and responsive styles
  js/app.js                 Form handling, API requests, signatures, and DOM updates
  js/config.js              API origin for a separately hosted backend
  images/market-chart.svg   Local illustration used by the pages
backend/main.py             FastAPI endpoints, authentication, and SQLite persistence
backend/lambda_handler.py   AWS Lambda adapter for the FastAPI application
requirements.txt            Python backend dependencies
```

Use the navigation at the top of each page to move between the project features.

## Included features

- Semantic HTML5 page structure, navigation links, lists, and accessible headings.
- Account registration and login with salted PBKDF2 password hashes and expiring bearer sessions.
- Authenticated API endpoints for signed orders, activity events, simulated tampering, and server-side signature verification.
- SQLite persistence with per-account data ownership.
- A stock order form and HTML tables of orders and activity events.
- Responsive CSS using the box model, Flexbox, and media queries.
- JavaScript DOM updates, form events, field validation, API integration, and RSA-PSS digital signatures with SHA-256.
- Curated links to FINRA order-type guidance, MDN Web Crypto documentation, and the project guide.
- A local SVG illustration in the resource library; unrelated placeholder audio/video samples have been removed.
- A record-change control that changes a saved order price without updating its signature; verification should then fail.

## Important limitations

This is a local paper-trading demo, not a live brokerage service. Accounts, orders, and activity are stored in SQLite on the server. Use a unique password; this demonstration does not include email verification, password recovery, production-grade rate limiting, or hardened deployment configuration. Sessions are held in browser session storage and expire after seven days. Each order is signed with a newly generated key; its private key is not saved, while its public key and signature are saved with the order. This demonstrates integrity checking, not proof of user identity or secure key custody. The event history is not an immutable audit log. Do not use this project for real orders, accounts, or financial activity.
