import psycopg2
from psycopg2.extras import RealDictCursor


def get_connection(settings):
    return psycopg2.connect(
        host=settings.database_host,
        port=settings.database_port,
        dbname=settings.database_name,
        user=settings.database_user,
        password=settings.database_password,
        connect_timeout=5,
    )


def find_user_by_login(settings, login):
    with get_connection(settings) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """SELECT id, login, password_hash, full_name, nickname
                   FROM users WHERE login = %s""",
                (login,),
            )
            return cursor.fetchone()


def find_user_by_id(settings, user_id):
    with get_connection(settings) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """SELECT id, login, full_name, nickname, photo, birth_date, created_at
                   FROM users WHERE id = %s""",
                (user_id,),
            )
            return cursor.fetchone()
