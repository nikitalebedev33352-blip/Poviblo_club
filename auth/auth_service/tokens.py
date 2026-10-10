from datetime import datetime, timedelta, timezone

import jwt


class TokenService:
    def __init__(self, settings):
        self.settings = settings
        self.private_key = settings.private_key_path.read_bytes()
        # Validate the signing key during startup, not on the first login.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = serialization.load_pem_private_key(self.private_key, password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise RuntimeError("JWT signing key must be RSA with at least 2048 bits")

    def issue_access_token(self, user_id):
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=self.settings.access_token_minutes)
        payload = {
            "sub": str(user_id),
            "iss": self.settings.jwt_issuer,
            "aud": self.settings.jwt_audience,
            "iat": now,
            "nbf": now,
            "exp": expires,
            "token_use": "access",
        }
        token = jwt.encode(
            payload,
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.settings.jwt_key_id, "typ": "JWT"},
        )
        return token, self.settings.access_token_minutes * 60

    def verify_access_token(self, token):
        from cryptography.hazmat.primitives import serialization
        private = serialization.load_pem_private_key(self.private_key, password=None)
        public = private.public_key()
        payload = jwt.decode(
            token,
            public,
            algorithms=["RS256"],
            issuer=self.settings.jwt_issuer,
            audience=self.settings.jwt_audience,
            options={"require": ["sub", "iss", "aud", "iat", "nbf", "exp"]},
            leeway=5,
        )
        if payload.get("token_use") != "access":
            raise jwt.InvalidTokenError("Wrong token type")
        sub = payload["sub"]
        if not isinstance(sub, str) or not sub.isdecimal() or int(sub) < 1:
            raise jwt.InvalidTokenError("Invalid subject")
        return int(sub)
