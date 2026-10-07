import os
from functools import wraps

import jwt
from flask import jsonify, request


def require_scope(required_scope):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization")

            if not auth_header:
                return jsonify({"error": "missing_token"}), 401

            try:
                token = auth_header.split(" ")[1]

                payload = jwt.decode(
                    token,
                    os.getenv("TOKEN_SECRET", "training-secret"),
                    algorithms=["HS256"],
                )

            except Exception:
                return jsonify({"error": "invalid_token"}), 401

            scopes = payload.get("scopes", [])

            if required_scope not in scopes:
                return jsonify({"error": "insufficient_scope"}), 403

            return func(*args, **kwargs)

        return wrapper

    return decorator
