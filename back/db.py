import os
import psycopg2


def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "postgresql"),
        port=os.getenv("DB_PORT", "5432"),
        database=os.getenv("DB_NAME", "devops"),
        user=os.getenv("DB_USER", "devops"),
        password=os.getenv("DB_PASSWORD", "devops"),
    )
