import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_host: str
    database_port: int
    database_name: str
    database_user: str
    database_password: str
    private_key_path: Path
    jwt_issuer: str
    jwt_audience: str
    jwt_key_id: str
    access_token_minutes: int


def load_settings() -> Settings:
    required = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD", "JWT_PRIVATE_KEY_PATH")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError("Missing required environment variables: " + ", ".join(missing))
    minutes = int(os.environ.get("JWT_ACCESS_TOKEN_MINUTES", "15"))
    if not 1 <= minutes <= 60:
        raise RuntimeError("JWT_ACCESS_TOKEN_MINUTES must be between 1 and 60")
    return Settings(
        database_host=os.environ["DB_HOST"],
        database_port=int(os.environ.get("DB_PORT", "5432")),
        database_name=os.environ["DB_NAME"],
        database_user=os.environ["DB_USER"],
        database_password=os.environ["DB_PASSWORD"],
        private_key_path=Path(os.environ["JWT_PRIVATE_KEY_PATH"]),
        jwt_issuer=os.environ.get("JWT_ISSUER", "povidlo-auth"),
        jwt_audience=os.environ.get("JWT_AUDIENCE", "povidlo-api"),
        jwt_key_id=os.environ.get("JWT_KEY_ID", "povidlo-auth-key-1"),
        access_token_minutes=minutes,
    )
