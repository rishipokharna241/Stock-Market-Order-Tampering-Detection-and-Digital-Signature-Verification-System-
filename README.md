# TradeGuard: Stock Order Integrity Workspace

A multi-page HTML, CSS, and JavaScript paper-trading workspace. It creates sample stock order records and uses the browser's Web Crypto API to sign and verify order data.

## Run the project

Digital signatures require a secure browser context. From this folder, start a local server in PowerShell:

```powershell
py -m http.server 8000
```

Then open <http://localhost:8000> in a modern browser. If `py` is not available, try `python -m http.server 8000`.

## Pages and files

```text
index.html                  Home page, project overview, and reference library
pages/
  register.html             Workspace profile form and client-side validation
  orders.html               Signed order form, orders table, and events table
  verify.html               Digital signature verification page
assets/
  css/styles.css            Shared layout, box model, Flexbox, and responsive styles
  js/app.js                 Form handling, browser storage, signatures, and DOM updates
  images/market-chart.svg   Local illustration used by the pages
```

Use the navigation at the top of each page to move between the project features.

## Included features

- Semantic HTML5 page structure, navigation links, lists, and accessible headings.
- A profile form with browser validation, duplicate-email checking, and local profile storage.
- A stock order form and HTML tables of orders and activity events.
- Responsive CSS using the box model, Flexbox, and media queries.
- JavaScript DOM updates, form events, field validation, local storage, and RSA-PSS digital signatures with SHA-256.
- Curated links to FINRA order-type guidance, MDN Web Crypto documentation, and the project guide.
- A local SVG illustration in the resource library; unrelated placeholder audio/video samples have been removed.
- A record-change control that changes a saved order price without updating its signature; verification should then fail.

## Important limitations

This is a client-side paper-trading workspace, not a live brokerage service. Order records, profiles, and activity history are stored in browser local storage and can be edited or deleted by the browser user. Profile creation does not create a cloud account; password sign-in and email verification are not connected. Each order is signed with a newly generated key; its private key is not saved, while its public key and signature are saved with the order. This demonstrates integrity checking, not proof of user identity or secure key custody. The event history is not an immutable audit log. Do not use this project for real orders, accounts, or financial activity.
