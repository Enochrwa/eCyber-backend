# backend/test_db.py
from app.database import init_db, Base, engine


def test_database():
    print("Testing database initialization...")
    init_db()

    # Verify tables exist
    from sqlalchemy import inspect

    inspector = inspect(engine)
    tables = inspector.get_table_names()
    print("Existing tables:", tables)

    assert "users" in tables, "Users table not created"
    print("Database test passed successfully!")


if __name__ == "__main__":
    test_database()
