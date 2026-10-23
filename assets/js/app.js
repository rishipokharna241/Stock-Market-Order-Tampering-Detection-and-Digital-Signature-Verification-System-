const STORAGE_KEYS = {
  users: "tradeguard-demo-users",
  orders: "tradeguard-demo-orders",
  events: "tradeguard-demo-events",
};

const encoder = new TextEncoder();

function showMessage(message, kind = "info") {
  const element = document.querySelector("#app-message");
  if (!element) return;
  element.textContent = message;
  element.dataset.kind = kind;
  window.setTimeout(() => {
    if (element.textContent === message) element.textContent = "";
  }, 6000);
}

function readStore(key) {
  const stored = localStorage.getItem(key);
  if (stored === null) return [];
  const parsed = JSON.parse(stored);
  if (!Array.isArray(parsed)) {
    throw new Error(`Saved data for "${key}" is not in the expected format.`);
  }
  return parsed;
}

function writeStore(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

function getOrders() {
  return readStore(STORAGE_KEYS.orders);
}

function getEvents() {
  return readStore(STORAGE_KEYS.events);
}

function saveEvent(orderId, type, details) {
  const events = getEvents();
  events.unshift({
    eventId: window.crypto.randomUUID(),
    orderId,
    type,
    details,
    createdAt: new Date().toISOString(),
  });
  writeStore(STORAGE_KEYS.events, events);
}

function canonicalOrder(order) {
  return JSON.stringify({
    orderId: order.orderId,
    side: order.side,
    symbol: order.symbol,
    quantity: order.quantity,
    price: order.price,
    createdAt: order.createdAt,
  });
}

function toBase64(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return window.btoa(binary);
}

function fromBase64(value) {
  const binary = window.atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function createSignedOrder(fields) {
  if (!window.crypto?.subtle) {
    throw new Error("Digital signatures need a secure browser context. Open this project at http://localhost, not as a file.");
  }

  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const order = {
    orderId: window.crypto.randomUUID(),
    side: fields.side,
    symbol: fields.symbol.toUpperCase(),
    quantity: Number(fields.quantity),
    price: Number(Number(fields.price).toFixed(2)),
    createdAt: new Date().toISOString(),
  };
  const signature = await window.crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    keyPair.privateKey,
    encoder.encode(canonicalOrder(order)),
  );

  return {
    ...order,
    publicKey: await window.crypto.subtle.exportKey("jwk", keyPair.publicKey),
    signature: toBase64(signature),
  };
}

async function verifyOrder(order) {
  if (!window.crypto?.subtle) {
    throw new Error("Signature verification needs a secure browser context. Open this project at http://localhost, not as a file.");
  }
  try {
    const publicKey = await window.crypto.subtle.importKey(
      "jwk",
      order.publicKey,
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["verify"],
    );
    return await window.crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      publicKey,
      fromBase64(order.signature),
      encoder.encode(canonicalOrder(order)),
    );
  } catch (error) {
    if (error instanceof DOMException || error instanceof TypeError) return false;
    throw error;
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return date.toLocaleString();
}

async function renderOrders() {
  const body = document.querySelector("#orders-table-body");
  if (!body) return;

  const orders = getOrders();
  if (orders.length === 0) {
    body.innerHTML = '<tr><td colspan="8">No orders yet. Create one using the form above.</td></tr>';
  } else {
    const rows = await Promise.all(orders.map(async (order) => {
      const valid = await verifyOrder(order);
      return `<tr>
        <td><code>${escapeHtml(order.orderId)}</code></td>
        <td>${escapeHtml(order.side)}</td>
        <td>${escapeHtml(order.symbol)}</td>
        <td>${escapeHtml(order.quantity)}</td>
        <td>$${Number(order.price).toFixed(2)}</td>
        <td>${escapeHtml(formatDate(order.createdAt))}</td>
        <td class="${valid ? "status-valid" : "status-invalid"}">${valid ? "Valid" : "Invalid"}</td>
        <td>
          <a class="table-action" href="verify.html?id=${encodeURIComponent(order.orderId)}">Verify</a>
          <button class="table-action" type="button" data-tamper-order="${escapeHtml(order.orderId)}">Simulate change</button>
        </td>
      </tr>`;
    }));
    body.innerHTML = rows.join("");
  }

  await renderEvents();
}

async function renderEvents() {
  const body = document.querySelector("#events-table-body");
  if (!body) return;
  const events = getEvents();
  if (events.length === 0) {
    body.innerHTML = '<tr><td colspan="4">No events yet. Create or verify an order to add events.</td></tr>';
    return;
  }
  body.innerHTML = events.map((event) => `<tr>
    <td>${escapeHtml(event.type)}</td>
    <td><code>${escapeHtml(event.orderId)}</code></td>
    <td>${escapeHtml(event.details)}</td>
    <td>${escapeHtml(formatDate(event.createdAt))}</td>
  </tr>`).join("");
}

function initializeRegistration() {
  const form = document.querySelector("#registration-form");
  if (!form) return;
  const nextLink = document.querySelector("#registration-next");
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const error = document.querySelector("#registration-error");
    const success = document.querySelector("#registration-success");
    error.textContent = "";
    success.textContent = "";
    nextLink.hidden = true;

    if (!form.reportValidity()) return;
    const formData = new FormData(form);
    const fullName = String(formData.get("fullName")).trim();
    const email = String(formData.get("email")).trim().toLowerCase();
    try {
      const users = readStore(STORAGE_KEYS.users);
      if (users.some((user) => user.email === email)) {
        error.textContent = "A profile with this email already exists on this device.";
        return;
      }
      users.push({ fullName, email, registeredAt: new Date().toISOString() });
      writeStore(STORAGE_KEYS.users, users);
    } catch (storageError) {
      error.textContent = `Could not save your profile: ${storageError.message}`;
      return;
    }
    form.reset();
    success.textContent = `Your profile is ready, ${fullName}.`;
    nextLink.hidden = false;
  });
}

function initializeOrders() {
  const form = document.querySelector("#order-form");
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    const formData = new FormData(form);
    const submitButton = form.querySelector('button[type="submit"]');
    submitButton.disabled = true;
    submitButton.textContent = "Signing order…";
    try {
      const order = await createSignedOrder({
        side: String(formData.get("side")),
        symbol: String(formData.get("symbol")).trim(),
        quantity: formData.get("quantity"),
        price: formData.get("price"),
      });
      const orders = getOrders();
      orders.unshift(order);
      writeStore(STORAGE_KEYS.orders, orders);
      saveEvent(order.orderId, "Order created", `${order.side} ${order.quantity} ${order.symbol} at $${order.price.toFixed(2)}; digitally signed.`);
      form.reset();
      showMessage(`Order ${order.orderId} signed and saved.`, "success");
      await renderOrders();
    } catch (error) {
      showMessage(`Could not create the signed order: ${error.message}`, "error");
    } finally {
      submitButton.disabled = false;
      submitButton.textContent = "Sign and submit order";
    }
  });

  document.querySelector("#orders-table-body").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-tamper-order]");
    if (!button) return;
    try {
      const orders = getOrders();
      const order = orders.find((item) => item.orderId === button.dataset.tamperOrder);
      if (!order) throw new Error("The selected order could not be found.");
      order.price = Number((Number(order.price) + 1).toFixed(2));
      writeStore(STORAGE_KEYS.orders, orders);
      saveEvent(order.orderId, "Order record changed", "Changed the saved price without updating its signature.");
      showMessage("Order price changed. Its signature is now invalid.", "error");
      await renderOrders();
    } catch (error) {
      showMessage(`Could not simulate the record change: ${error.message}`, "error");
    }
  });

  renderOrders().catch((error) => showMessage(`Could not load orders: ${error.message}`, "error"));
}

function showVerificationResult(container, valid, orderId) {
  container.innerHTML = `<section class="result-card ${valid ? "valid" : "invalid"}">
    <h3>${valid ? "Signature valid" : "Signature invalid"}</h3>
    <p>Order <code>${escapeHtml(orderId)}</code> ${valid
      ? "matches the data covered by its digital signature."
      : "does not match its digital signature. Its signed data may have changed."}</p>
  </section>`;
}

function initializeVerification() {
  const form = document.querySelector("#verify-form");
  if (!form) return;
  const orderIdInput = form.elements.namedItem("orderId");
  const result = document.querySelector("#verification-result");
  const requestedId = new URLSearchParams(window.location.search).get("id");
  if (requestedId) orderIdInput.value = requestedId;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    const orderId = orderIdInput.value.trim();
    try {
      const order = getOrders().find((item) => item.orderId === orderId);
      if (!order) {
        result.innerHTML = '<section class="result-card invalid"><h3>Order not found</h3><p>Check the ID or create an order first.</p></section>';
        return;
      }
      const valid = await verifyOrder(order);
      saveEvent(order.orderId, "Signature checked", valid ? "Signature verification passed." : "Signature verification failed.");
      showVerificationResult(result, valid, order.orderId);
    } catch (error) {
      showMessage(`Could not verify the order: ${error.message}`, "error");
    }
  });
}

function initialize() {
  try {
    readStore(STORAGE_KEYS.users);
    readStore(STORAGE_KEYS.orders);
    readStore(STORAGE_KEYS.events);
    initializeRegistration();
    initializeOrders();
    initializeVerification();
  } catch (error) {
    showMessage(`Saved workspace data could not be read: ${error.message}`, "error");
  }
}

document.addEventListener("DOMContentLoaded", initialize);
