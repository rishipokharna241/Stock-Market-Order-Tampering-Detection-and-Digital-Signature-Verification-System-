import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = Path(os.environ.get("TRADEGUARD_DB", Path(__file__).with_name("tradeguard.sqlite3")))
SESSION_LIFETIME = timedelta(days=7)


class RegisterRequest(BaseModel):
    fullName: str = Field(min_length=2, max_length=80)
    email: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=8, max_length=128)


class RsaPublicKey(BaseModel):
    kty: Literal["RSA"]
    e: str
    n: str


class OrderRequest(BaseModel):
    orderId: str = Field(min_length=1, max_length=80)
    side: Literal["BUY", "SELL"]
    symbol: str = Field(pattern=r"^[A-Za-z]{1,5}$")
    quantity: int = Field(gt=0, le=1_000_000)
    price: float = Field(gt=0, le=1_000_000)
    createdAt: str = Field(min_length=1, max_length=40)
    publicKey: RsaPublicKey
    signature: str = Field(min_length=1, max_length=2048)


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                registered_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS orders (
                order_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                side TEXT NOT NULL CHECK (side IN ('BUY', 'SELL')),
                symbol TEXT NOT NULL,
                quantity INTEGER NOT NULL CHECK (quantity > 0),
                price REAL NOT NULL CHECK (price > 0),
                created_at TEXT NOT NULL,
                public_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                order_id TEXT NOT NULL,
                type TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="TradeGuard API", version="1.0.0", lifespan=lifespan)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return base64.b64encode(salt).decode("ascii"), base64.b64encode(digest).decode("ascii")


def password_matches(password: str, salt: str, expected_hash: str) -> bool:
    _, actual_hash = hash_password(password, base64.b64decode(salt))
    return secrets.compare_digest(actual_hash, expected_hash)


def public_user(row: sqlite3.Row) -> dict[str, str]:
    return {"fullName": row["full_name"], "email": row["email"]}


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + SESSION_LIFETIME).isoformat()
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (hashlib.sha256(token.encode("ascii")).hexdigest(), user_id, expires_at),
        )
    return token


def authenticated_user(authorization: Annotated[str | None, Header()] = None) -> sqlite3.Row:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in to continue.")
    token = authorization.removeprefix("Bearer ").strip()
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with connect_db() as connection:
        row = connection.execute(
            """SELECT users.* FROM sessions
               JOIN users ON users.id = sessions.user_id
               WHERE sessions.token_hash = ? AND sessions.expires_at > ?""",
            (token_hash, datetime.now(timezone.utc).isoformat()),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your session expired. Please sign in again.")
    return row


def canonical_order(order: OrderRequest | sqlite3.Row) -> bytes:
    price = round(float(order.price if isinstance(order, OrderRequest) else order["price"]), 2)
    if price.is_integer():
        price = int(price)
    fields = {
        "orderId": order.orderId if isinstance(order, OrderRequest) else order["order_id"],
        "side": order.side if isinstance(order, OrderRequest) else order["side"],
        "symbol": (order.symbol if isinstance(order, OrderRequest) else order["symbol"]).upper(),
        "quantity": order.quantity if isinstance(order, OrderRequest) else order["quantity"],
        "price": price,
        "createdAt": order.createdAt if isinstance(order, OrderRequest) else order["created_at"],
    }
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_signature(order: OrderRequest | sqlite3.Row) -> bool:
    try:
        public_key = order.publicKey.model_dump() if isinstance(order, OrderRequest) else json.loads(order["public_key"])
        signature_value = order.signature if isinstance(order, OrderRequest) else order["signature"]

        def decode_jwk(value: str) -> int:
            padded = value + "=" * (-len(value) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

        key = rsa.RSAPublicNumbers(
            decode_jwk(public_key["e"]),
            decode_jwk(public_key["n"]),
        ).public_key()
        if key.key_size < 2048:
            return False
        signature = base64.b64decode(signature_value, validate=True)
        key.verify(
            signature,
            canonical_order(order),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def record_event(user_id: int, order_id: str, event_type: str, details: str) -> None:
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO events (event_id, user_id, order_id, type, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (secrets.token_hex(16), user_id, order_id, event_type, details, utc_now()),
        )


def serialize_order(row: sqlite3.Row) -> dict:
    return {
        "orderId": row["order_id"],
        "side": row["side"],
        "symbol": row["symbol"],
        "quantity": row["quantity"],
        "price": row["price"],
        "createdAt": row["created_at"],
        "publicKey": json.loads(row["public_key"]),
        "signature": row["signature"],
    }


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest) -> dict:
    full_name = payload.fullName.strip()
    email = payload.email.strip().lower()
    if len(full_name) < 2 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=400, detail="Enter a valid name and email address.")
    salt, password_hash = hash_password(payload.password)
    now = utc_now()
    try:
        with connect_db() as connection:
            cursor = connection.execute(
                "INSERT INTO users (full_name, email, password_salt, password_hash, registered_at) VALUES (?, ?, ?, ?, ?)",
                (full_name, email, salt, password_hash, now),
            )
            user_id = cursor.lastrowid
            user = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    except sqlite3.IntegrityError as error:
        if "users.email" in str(error):
            raise HTTPException(status_code=409, detail="An account with this email already exists.") from error
        raise
    return {"token": create_session(user_id), "user": public_user(user)}


@app.post("/api/auth/login")
def login(payload: LoginRequest) -> dict:
    email = payload.email.strip().lower()
    with connect_db() as connection:
        user = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if user is None or not password_matches(payload.password, user["password_salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    return {"token": create_session(user["id"]), "user": public_user(user)}


@app.get("/api/auth/me")
def get_me(user: Annotated[sqlite3.Row, Depends(authenticated_user)]) -> dict:
    return {"user": public_user(user)}


@app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(user: Annotated[sqlite3.Row, Depends(authenticated_user)], authorization: Annotated[str, Header()]) -> None:
    token = authorization.removeprefix("Bearer ").strip()
    with connect_db() as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (hashlib.sha256(token.encode()).hexdigest(),))


@app.get("/api/orders")
def list_orders(user: Annotated[sqlite3.Row, Depends(authenticated_user)]) -> list[dict]:
    with connect_db() as connection:
        rows = connection.execute(
            "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)
        ).fetchall()
    return [serialize_order(row) for row in rows]


@app.post("/api/orders", status_code=status.HTTP_201_CREATED)
def create_order(payload: OrderRequest, user: Annotated[sqlite3.Row, Depends(authenticated_user)]) -> dict:
    if not verify_signature(payload):
        raise HTTPException(status_code=422, detail="Order signature is invalid.")
    order = payload.model_dump()
    order["symbol"] = order["symbol"].upper()
    order["price"] = round(order["price"], 2)
    try:
        with connect_db() as connection:
            connection.execute(
                """INSERT INTO orders
                   (order_id, user_id, side, symbol, quantity, price, created_at, public_key, signature)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    order["orderId"], user["id"], order["side"], order["symbol"], order["quantity"],
                    order["price"], order["createdAt"], json.dumps(order["publicKey"]), order["signature"],
                ),
            )
    except sqlite3.IntegrityError as error:
        if "orders.order_id" in str(error):
            raise HTTPException(status_code=409, detail="An order with this ID already exists.") from error
        raise
    record_event(
        user["id"],
        order["orderId"],
        "Order created",
        f'{order["side"]} {order["quantity"]} {order["symbol"]} at ${order["price"]:.2f}; digitally signed.',
    )
    return order


@app.patch("/api/orders/{order_id}/simulate-change")
def simulate_order_change(order_id: str, user: Annotated[sqlite3.Row, Depends(authenticated_user)]) -> dict:
    with connect_db() as connection:
        order = connection.execute(
            "SELECT * FROM orders WHERE order_id = ? AND user_id = ?", (order_id, user["id"])
        ).fetchone()
        if order is None:
            raise HTTPException(status_code=404, detail="Order not found.")
        changed_price = round(order["price"] + 1, 2)
        connection.execute("UPDATE orders SET price = ? WHERE order_id = ?", (changed_price, order_id))
    record_event(user["id"], order_id, "Order record changed", "Changed the saved price without updating its signature.")
    with connect_db() as connection:
        changed = connection.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,)).fetchone()
    return serialize_order(changed)


@app.post("/api/orders/{order_id}/verify")
def verify_saved_order(order_id: str, user: Annotated[sqlite3.Row, Depends(authenticated_user)]) -> dict:
    with connect_db() as connection:
        order = connection.execute(
            "SELECT * FROM orders WHERE order_id = ? AND user_id = ?", (order_id, user["id"])
        ).fetchone()
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found.")
    valid = verify_signature(order)
    record_event(
        user["id"],
        order_id,
        "Signature checked",
        "Signature verification passed." if valid else "Signature verification failed.",
    )
    return {"orderId": order_id, "valid": valid}


@app.get("/api/events")
def list_events(user: Annotated[sqlite3.Row, Depends(authenticated_user)]) -> list[dict]:
    with connect_db() as connection:
        rows = connection.execute(
            "SELECT * FROM events WHERE user_id = ? ORDER BY created_at DESC LIMIT 100", (user["id"],)
        ).fetchall()
    return [
        {
            "eventId": row["event_id"],
            "orderId": row["order_id"],
            "type": row["type"],
            "details": row["details"],
            "createdAt": row["created_at"],
        }
        for row in rows
    ]


@app.get("/", include_in_schema=False)
@app.get("/index.html", include_in_schema=False)
def serve_index() -> FileResponse:
    return FileResponse(PROJECT_ROOT / "index.html")


@app.get("/README.md", include_in_schema=False)
def serve_readme() -> FileResponse:
    return FileResponse(PROJECT_ROOT / "README.md")


app.mount("/assets", StaticFiles(directory=PROJECT_ROOT / "assets"), name="assets")
app.mount("/pages", StaticFiles(directory=PROJECT_ROOT / "pages"), name="pages")
