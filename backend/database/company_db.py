import aiosqlite
import os
from backend.config import get_settings

settings = get_settings()

COMPANY_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'employee',
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    full_name TEXT NOT NULL,
    department TEXT,
    position TEXT,
    salary REAL,
    ssn TEXT,
    hire_date DATE,
    manager_id INTEGER
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER,
    product_name TEXT,
    quantity INTEGER,
    total_amount REAL,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER,
    transaction_type TEXT,
    amount REAL,
    balance_after REAL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


async def init_company_db():
    os.makedirs(os.path.dirname(settings.company_db_path), exist_ok=True)
    async with aiosqlite.connect(settings.company_db_path) as db:
        await db.executescript(COMPANY_SCHEMA)
        await db.commit()


async def get_company_db():
    async with aiosqlite.connect(settings.company_db_path) as db:
        db.row_factory = aiosqlite.Row
        yield db