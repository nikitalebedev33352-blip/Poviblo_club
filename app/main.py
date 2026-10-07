import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt
from flask import Flask, jsonify, request

from auth import require_scope
from db import get_connection

app = Flask(__name__)


# =========================
# HEALTH
# =========================

@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


# =========================
# TOKEN
# =========================

@app.post("/token")
def create_token():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "invalid_request"}), 400

    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    requested_scopes = data.get("scopes", [])

    if not client_id or not client_secret:
        return jsonify({"error": "invalid_request"}), 400

    if not isinstance(requested_scopes, list):
        return jsonify({"error": "invalid_scope"}), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        # Ищем клиента
        cur.execute(
            """
            SELECT id, client_secret_hash
            FROM clients
            WHERE client_id = %s
            """,
            (client_id,),
        )

        client = cur.fetchone()

        if client is None:
            return jsonify({"error": "invalid_client"}), 401

        client_db_id = client[0]
        stored_secret_hash = client[1]

        # Хэшируем присланный client_secret
        provided_secret_hash = hashlib.sha256(
            client_secret.encode("utf-8")
        ).hexdigest()

        # Сравниваем хэши
        if not hmac.compare_digest(
            provided_secret_hash,
            stored_secret_hash,
        ):
            return jsonify({"error": "invalid_client"}), 401

        # Получаем scopes, разрешённые этому клиенту
        cur.execute(
            """
            SELECT scope
            FROM client_scopes
            WHERE client_id = %s
            """,
            (client_db_id,),
        )

        allowed_scopes = {row[0] for row in cur.fetchall()}

        # Проверяем, что клиент не запросил лишний scope
        if not set(requested_scopes).issubset(allowed_scopes):
            return jsonify({"error": "invalid_scope"}), 403

        # Токен будет жить 30 минут
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=30)

        payload = {
            "sub": client_id,
            "scopes": requested_scopes,
            "iat": now,
            "exp": expires_at,
        }

        access_token = jwt.encode(
            payload,
            os.getenv("TOKEN_SECRET", "training-secret"),
            algorithm="HS256",
        )

        return jsonify(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 1800,
            }
        ), 200

    finally:
        cur.close()
        conn.close()


# =========================
# USERS
# =========================

@app.get("/users")
@require_scope("users.read")
def get_users():
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT id, name, email
            FROM users
            ORDER BY id
            """
        )

        rows = cur.fetchall()

        users = [
            {
                "id": row[0],
                "name": row[1],
                "email": row[2],
            }
            for row in rows
        ]

        return jsonify(users), 200

    finally:
        cur.close()
        conn.close()


@app.post("/users")
@require_scope("users.write")
def create_user():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "invalid_request"}), 400

    name = data.get("name")
    email = data.get("email")

    if not name or not email:
        return jsonify({"error": "name_and_email_required"}), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            INSERT INTO users (name, email)
            VALUES (%s, %s)
            RETURNING id
            """,
            (name, email),
        )

        user_id = cur.fetchone()[0]
        conn.commit()

        return jsonify(
            {
                "id": user_id,
                "name": name,
                "email": email,
            }
        ), 201

    finally:
        cur.close()
        conn.close()


@app.delete("/users/<int:user_id>")
@require_scope("users.write")
def delete_user(user_id):
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            DELETE FROM users
            WHERE id = %s
            RETURNING id
            """,
            (user_id,),
        )

        deleted_user = cur.fetchone()

        if deleted_user is None:
            conn.rollback()
            return jsonify({"error": "user_not_found"}), 404

        conn.commit()

        return "", 204

    finally:
        cur.close()
        conn.close()


# =========================
# PAYMENTS
# =========================

@app.get("/payments")
@require_scope("payments.read")
def get_payments():
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT id, user_id, amount, created_at
            FROM payments
            ORDER BY id
            """
        )

        rows = cur.fetchall()

        payments = [
            {
                "id": row[0],
                "user_id": row[1],
                "amount": float(row[2]),
                "created_at": row[3].isoformat(),
            }
            for row in rows
        ]

        return jsonify(payments), 200

    finally:
        cur.close()
        conn.close()


@app.post("/payments")
@require_scope("payments.write")
def create_payment():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "invalid_request"}), 400

    user_id = data.get("user_id")
    amount = data.get("amount")

    if user_id is None or amount is None:
        return jsonify({"error": "user_id_and_amount_required"}), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        # Проверяем, существует ли пользователь
        cur.execute(
            """
            SELECT id
            FROM users
            WHERE id = %s
            """,
            (user_id,),
        )

        if cur.fetchone() is None:
            return jsonify({"error": "user_not_found"}), 404

        cur.execute(
            """
            INSERT INTO payments (user_id, amount)
            VALUES (%s, %s)
            RETURNING id, created_at
            """,
            (user_id, amount),
        )

        payment = cur.fetchone()
        conn.commit()

        return jsonify(
            {
                "id": payment[0],
                "user_id": user_id,
                "amount": amount,
                "created_at": payment[1].isoformat(),
            }
        ), 201

    finally:
        cur.close()
        conn.close()


@app.delete("/payments/<int:payment_id>")
@require_scope("payments.write")
def delete_payment(payment_id):
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            DELETE FROM payments
            WHERE id = %s
            RETURNING id
            """,
            (payment_id,),
        )

        deleted_payment = cur.fetchone()

        if deleted_payment is None:
            conn.rollback()
            return jsonify({"error": "payment_not_found"}), 404

        conn.commit()

        return "", 204

    finally:
        cur.close()
        conn.close()


# =========================
# START
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)