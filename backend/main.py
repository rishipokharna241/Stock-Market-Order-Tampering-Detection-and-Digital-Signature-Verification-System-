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
from pymongo import ASCENDING, MongoClient
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MONGODB_URI = os.environ.get("TRADEGUARD_MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DATABASE = os.environ.get("TRADEGUARD_MONGODB_DATABASE", "tradeguard")
SQLITE_MIGRATION_PATH = Path(os.environ.get("TRADEGUARD_DB", Path(__file__).with_name("tradeguard.sqlite3")))
SESSION_LIFETIME = timedelta(days=7)
mongo_client: MongoClient | None = None
database: Database | None = None


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


def get_database() -> Database:
    if database is None:
        raise RuntimeError("MongoDB has not been initialized.")
    return database


def migrate_sqlite_data(target: Database) -> None:
    if not SQLITE_MIGRATION_PATH.exists():
        return

    with sqlite3.connect(SQLITE_MIGRATION_PATH) as connection:
        connection.row_factory = sqlite3.Row
        tables = {
            row["name"]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        for row in connection.execute("SELECT * FROM users").fetchall() if "users" in tables else []:
            target.users.update_one(
                {"_id": str(row["id"])},
                {
                    "$setOnInsert": {
                        "full_name": row["full_name"],
                        "email": row["email"].strip().lower(),
                        "password_salt": row["password_salt"],
                        "password_hash": row["password_hash"],
                        "registered_at": row["registered_at"],
                    }
                },
                upsert=True,
            )
        for row in connection.execute("SELECT * FROM sessions").fetchall() if "sessions" in tables else []:
            target.sessions.update_one(
                {"_id": row["token_hash"]},
                {
                    "$setOnInsert": {
                        "user_id": str(row["user_id"]),
                        "expires_at": datetime.fromisoformat(row["expires_at"]),
                    }
                },
                upsert=True,
            )
        for row in connection.execute("SELECT * FROM orders").fetchall() if "orders" in tables else []:
            target.orders.update_one(
                {"_id": row["order_id"]},
                {
                    "$setOnInsert": {
                        "orderId": row["order_id"],
                        "user_id": str(row["user_id"]),
                        "side": row["side"],
                        "symbol": row["symbol"],
                        "quantity": row["quantity"],
                        "price": row["price"],
                        "createdAt": row["created_at"],
                        "publicKey": json.loads(row["public_key"]),
                        "signature": row["signature"],
                    }
                },
                upsert=True,
            )
        for row in connection.execute("SELECT * FROM events").fetchall() if "events" in tables else []:
            target.events.update_one(
                {"_id": row["event_id"]},
                {
                    "$setOnInsert": {
                        "eventId": row["event_id"],
                        "user_id": str(row["user_id"]),
                        "orderId": row["order_id"],
                        "type": row["type"],
                        "details": row["details"],
                        "createdAt": row["created_at"],
                    }
                },
                upsert=True,
            )


def initialize_database() -> None:
    global mongo_client, database
    mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    mongo_client.admin.command("ping")
    database = mongo_client[MONGODB_DATABASE]
    database.users.create_index([("email", ASCENDING)], unique=True)
    database.orders.create_index([("user_id", ASCENDING), ("createdAt", ASCENDING)])
    database.events.create_index([("user_id", ASCENDING), ("createdAt", ASCENDING)])
    database.sessions.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
    migrate_sqlite_data(database)


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    try:
        yield
    finally:
        if mongo_client is not None:
            mongo_client.close()


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


def public_user(row: dict) -> dict[str, str]:
    return {"fullName": row["full_name"], "email": row["email"]}


def create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    get_database().sessions.insert_one(
        {
            "_id": hashlib.sha256(token.encode("ascii")).hexdigest(),
            "user_id": user_id,
            "expires_at": datetime.now(timezone.utc) + SESSION_LIFETIME,
        }
    )
    return token


def authenticated_user(authorization: Annotated[str | None, Header()] = None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in to continue.")
    token = authorization.removeprefix("Bearer ").strip()
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    db = get_database()
    session = db.sessions.find_one(
        {"_id": token_hash, "expires_at": {"$gt": datetime.now(timezone.utc)}}
    )
    user = db.users.find_one({"_id": session["user_id"]}) if session else None
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your session expired. Please sign in again.")
    return user


def canonical_order(order: OrderRequest | dict) -> bytes:
    price = round(float(order.price if isinstance(order, OrderRequest) else order["price"]), 2)
    if price.is_integer():
        price = int(price)
    fields = {
        "orderId": order.orderId if isinstance(order, OrderRequest) else order["orderId"],
        "side": order.side if isinstance(order, OrderRequest) else order["side"],
        "symbol": (order.symbol if isinstance(order, OrderRequest) else order["symbol"]).upper(),
        "quantity": order.quantity if isinstance(order, OrderRequest) else order["quantity"],
        "price": price,
        "createdAt": order.createdAt if isinstance(order, OrderRequest) else order["createdAt"],
    }
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_signature(order: OrderRequest | dict) -> bool:
    try:
        public_key = order.publicKey.model_dump() if isinstance(order, OrderRequest) else order["publicKey"]
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


def record_event(user_id: str, order_id: str, event_type: str, details: str) -> None:
    event_id = secrets.token_hex(16)
    get_database().events.insert_one(
        {
            "_id": event_id,
            "eventId": event_id,
            "user_id": user_id,
            "orderId": order_id,
            "type": event_type,
            "details": details,
            "createdAt": utc_now(),
        }
    )


def serialize_order(row: dict) -> dict:
    return {
        "orderId": row["orderId"],
        "side": row["side"],
        "symbol": row["symbol"],
        "quantity": row["quantity"],
        "price": row["price"],
        "createdAt": row["createdAt"],
        "publicKey": row["publicKey"],
        "signature": row["signature"],
    }


@app.get("/api/health")
def health() -> dict[str, str]:
    get_database().command("ping")
    return {"status": "ok", "database": "mongodb"}


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest) -> dict:
    full_name = payload.fullName.strip()
    email = payload.email.strip().lower()
    if len(full_name) < 2 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=400, detail="Enter a valid name and email address.")
    salt, password_hash = hash_password(payload.password)
    now = utc_now()
    try:
        user_id = secrets.token_hex(16)
        user = {
            "_id": user_id,
            "full_name": full_name,
            "email": email,
            "password_salt": salt,
            "password_hash": password_hash,
            "registered_at": now,
        }
        get_database().users.insert_one(user)
    except DuplicateKeyError as error:
        raise HTTPException(status_code=409, detail="An account with this email already exists.") from error
    return {"token": create_session(user_id), "user": public_user(user)}


@app.post("/api/auth/login")
def login(payload: LoginRequest) -> dict:
    email = payload.email.strip().lower()
    user = get_database().users.find_one({"email": email})
    if user is None or not password_matches(payload.password, user["password_salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    return {"token": create_session(user["_id"]), "user": public_user(user)}


@app.get("/api/auth/me")
def get_me(user: Annotated[dict, Depends(authenticated_user)]) -> dict:
    return {"user": public_user(user)}


@app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(user: Annotated[dict, Depends(authenticated_user)], authorization: Annotated[str, Header()]) -> None:
    token = authorization.removeprefix("Bearer ").strip()
    get_database().sessions.delete_one({"_id": hashlib.sha256(token.encode()).hexdigest()})


@app.get("/api/orders")
def list_orders(user: Annotated[dict, Depends(authenticated_user)]) -> list[dict]:
    rows = get_database().orders.find({"user_id": user["_id"]}).sort("createdAt", -1)
    return [serialize_order(row) for row in rows]


@app.post("/api/orders", status_code=status.HTTP_201_CREATED)
def create_order(payload: OrderRequest, user: Annotated[dict, Depends(authenticated_user)]) -> dict:
    if not verify_signature(payload):
        raise HTTPException(status_code=422, detail="Order signature is invalid.")
    order = payload.model_dump()
    order["symbol"] = order["symbol"].upper()
    order["price"] = round(order["price"], 2)
    try:
        saved_order = {**order, "publicKey": payload.publicKey.model_dump(), "user_id": user["_id"]}
        get_database().orders.insert_one({"_id": order["orderId"], **saved_order})
    except DuplicateKeyError as error:
        raise HTTPException(status_code=409, detail="An order with this ID already exists.") from error
    record_event(
        user["_id"],
        order["orderId"],
        "Order created",
        f'{order["side"]} {order["quantity"]} {order["symbol"]} at ${order["price"]:.2f}; digitally signed.',
    )
    return order


@app.patch("/api/orders/{order_id}/simulate-change")
def simulate_order_change(order_id: str, user: Annotated[dict, Depends(authenticated_user)]) -> dict:
    db = get_database()
    order = db.orders.find_one({"_id": order_id, "user_id": user["_id"]})
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found.")
    changed_price = round(order["price"] + 1, 2)
    db.orders.update_one({"_id": order_id}, {"$set": {"price": changed_price}})
    record_event(user["_id"], order_id, "Order record changed", "Changed the saved price without updating its signature.")
    changed = db.orders.find_one({"_id": order_id, "user_id": user["_id"]})
    return serialize_order(changed)


@app.post("/api/orders/{order_id}/verify")
def verify_saved_order(order_id: str, user: Annotated[dict, Depends(authenticated_user)]) -> dict:
    order = get_database().orders.find_one({"_id": order_id, "user_id": user["_id"]})
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found.")
    valid = verify_signature(order)
    record_event(
        user["_id"],
        order_id,
        "Signature checked",
        "Signature verification passed." if valid else "Signature verification failed.",
    )
    return {"orderId": order_id, "valid": valid}


@app.get("/api/events")
def list_events(user: Annotated[dict, Depends(authenticated_user)]) -> list[dict]:
    rows = get_database().events.find({"user_id": user["_id"]}).sort("createdAt", -1).limit(100)
    return [
        {
            "eventId": row["eventId"],
            "orderId": row["orderId"],
            "type": row["type"],
            "details": row["details"],
            "createdAt": row["createdAt"],
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
