import os
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager

DSN = os.environ.get("VO_DSN", "postgresql://vo@127.0.0.1:5433/world")

@contextmanager
def cursor():
    conn = psycopg2.connect(DSN)
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SET search_path TO world")
        yield cur
        conn.commit()
    finally:
        conn.close()

def q(sql, params=None):
    with cursor() as cur:
        cur.execute(sql, params or ())
        return cur.fetchall()

def one(sql, params=None):
    rows = q(sql, params)
    return rows[0] if rows else None
