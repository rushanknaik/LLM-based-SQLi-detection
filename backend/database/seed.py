import aiosqlite
from backend.config import get_settings

settings = get_settings()


async def seed_company_data():
    async with aiosqlite.connect(settings.company_db_path) as db:
        # Check if already seeded
        async with db.execute("SELECT COUNT(*) FROM users") as cur:
            count = (await cur.fetchone())[0]
        if count > 0:
            return

        # Seed users
        users = [
            ("alice", "alice@corp.com", "hash_alice", "employee"),
            ("bob", "bob@corp.com", "hash_bob", "employee"),
            ("charlie", "charlie@corp.com", "hash_charlie", "admin"),
            ("diana", "diana@corp.com", "hash_diana", "employee"),
            ("eve", "eve@corp.com", "hash_eve", "employee"),
            ("frank", "frank@corp.com", "hash_frank", "admin"),
        ]
        await db.executemany(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
            users
        )

        # Seed employees
        employees = [
            (1, "Alice Johnson", "Engineering", "Software Engineer", 85000, "123-45-6789", "2021-03-15", 3),
            (2, "Bob Smith", "Marketing", "Marketing Analyst", 62000, "234-56-7890", "2020-06-01", 6),
            (3, "Charlie Brown", "Engineering", "Engineering Manager", 120000, "345-67-8901", "2018-01-10", None),
            (4, "Diana Prince", "HR", "HR Specialist", 58000, "456-78-9012", "2022-07-20", 6),
            (5, "Eve Wilson", "Finance", "Financial Analyst", 75000, "567-89-0123", "2021-11-05", 6),
            (6, "Frank Castle", "Executive", "VP of Operations", 180000, "678-90-1234", "2016-04-22", None),
        ]
        await db.executemany(
            "INSERT INTO employees (user_id, full_name, department, position, salary, ssn, hire_date, manager_id) VALUES (?,?,?,?,?,?,?,?)",
            employees
        )

        # Seed orders
        orders = [
            (1, "Laptop Pro X", 2, 2999.98, "completed"),
            (2, "Office Chair", 5, 1499.95, "pending"),
            (3, "Monitor 4K", 1, 599.99, "completed"),
            (4, "Keyboard Wireless", 10, 899.90, "shipped"),
            (1, "USB Hub", 3, 89.97, "completed"),
            (5, "Standing Desk", 1, 750.00, "pending"),
        ]
        await db.executemany(
            "INSERT INTO orders (customer_id, product_name, quantity, total_amount, status) VALUES (?,?,?,?,?)",
            orders
        )

        # Seed transactions
        transactions = [
            (1001, "deposit", 5000.00, 15000.00, "Monthly salary"),
            (1002, "withdrawal", 200.00, 3800.00, "ATM withdrawal"),
            (1001, "transfer", 1500.00, 13500.00, "Rent payment"),
            (1003, "deposit", 8500.00, 42000.00, "Bonus payment"),
            (1002, "purchase", 349.99, 3450.01, "Online shopping"),
            (1004, "deposit", 3200.00, 12200.00, "Freelance income"),
        ]
        await db.executemany(
            "INSERT INTO transactions (account_id, transaction_type, amount, balance_after, description) VALUES (?,?,?,?,?)",
            transactions
        )

        await db.commit()
        print("[seed] Company database seeded successfully.")