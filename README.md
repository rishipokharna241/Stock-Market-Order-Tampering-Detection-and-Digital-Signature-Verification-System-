# TradeGuard: Stock Order Integrity Workspace

A multi-page HTML, CSS, JavaScript, and FastAPI paper-trading workspace. It creates sample stock order records, signs them with the browser's Web Crypto API, and stores accounts, orders, and activity in a local SQLite database.

## Run the project

Install the backend dependencies, then run the FastAPI server from this folder in PowerShell:

```powershell
py -m pip install -r requirements.txt
py -m uvicorn backend.main:app --reload
```

Open <http://localhost:8000> in a modern browser. The FastAPI app serves both the frontend and `/api` endpoints. If `py` is not available, use `python` instead. Set `TRADEGUARD_DB` to change the SQLite database location.

GitHub Pages only serves static files and cannot run this FastAPI backend. To use the authenticated backend online, deploy the FastAPI app and SQLite storage on a Python host and configure the frontend to call that API, including the required cross-origin settings. The current GitHub Pages site remains the previously deployed static version until such a backend is deployed.

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
  images/market-chart.svg   Local illustration used by the pages
backend/main.py             FastAPI endpoints, authentication, and SQLite persistence
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
