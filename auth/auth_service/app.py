import logging

import jwt
from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash

from .config import load_settings
from .db import find_user_by_id, find_user_by_login, get_connection
from .tokens import TokenService

LOGGER = logging.getLogger(__name__)


def public_profile(user):
    return {
        "id": user["id"],
        "login": user["login"],
        "full_name": user["full_name"],
        "nickname": user["nickname"],
        "photo": user.get("photo"),
        "birth_date": user["birth_date"].isoformat() if user.get("birth_date") else None,
        "created_at": user["created_at"].isoformat() if user.get("created_at") else None,
    }


def create_app(settings=None, token_service=None):
    settings = settings or load_settings()
    token_service = token_service or TokenService(settings)
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 8192
    app.json.sort_keys = False

    @app.get("/health/live")
    def live():
        return jsonify(status="ok")

    @app.get("/health/ready")
    def ready():
        try:
            with get_connection(settings) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
        except Exception:
            LOGGER.exception("Database readiness check failed")
            return jsonify(status="unavailable"), 503
        return jsonify(status="ok")

    @app.post("/auth/login")
    def login():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="invalid_request"), 400
        username = body.get("login")
        password = body.get("password")
        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or not 1 <= len(username) <= 50
            or not 1 <= len(password) <= 1024
        ):
            return jsonify(error="invalid_request"), 400
        try:
            user = find_user_by_login(settings, username)
            valid = bool(user) and check_password_hash(user["password_hash"], password)
        except Exception:
            LOGGER.exception("Login lookup failed")
            return jsonify(error="service_unavailable"), 503
        if not valid:
            return jsonify(error="invalid_credentials"), 401
        token, expires_in = token_service.issue_access_token(user["id"])
        response = jsonify(access_token=token, token_type="Bearer", expires_in=expires_in)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/auth/me")
    def me():
        header = request.headers.get("Authorization", "")
        parts = header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify(error="unauthorized"), 401
        try:
            user_id = token_service.verify_access_token(parts[1])
        except jwt.InvalidTokenError:
            return jsonify(error="unauthorized"), 401
        try:
            user = find_user_by_id(settings, user_id)
        except Exception:
            LOGGER.exception("Profile lookup failed")
            return jsonify(error="service_unavailable"), 503
        if not user:
            return jsonify(error="unauthorized"), 401
        response = jsonify(user=public_profile(user))
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="request_too_large"), 413

    return app
