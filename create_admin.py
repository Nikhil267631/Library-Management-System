
from getpass import getpass
from werkzeug.security import generate_password_hash
from db import get_db_connection

print("===== Create Library Admin Account =====")

name = input("Enter admin name: ").strip()
email = input("Enter admin email: ").strip().lower()
password = getpass("Create admin password: ")
confirm_password = getpass("Confirm admin password: ")

if not name or not email or not password:
    print("All fields are required.")

elif password != confirm_password:
    print("Passwords do not match.")

elif len(password) < 8:
    print("Password must contain at least 8 characters.")

else:
    connection = get_db_connection()

    if connection:
        cursor = connection.cursor()

        try:
            password_hash = generate_password_hash(password)

            query = """
                INSERT INTO admins (name, email, password_hash)
                VALUES (%s, %s, %s)
            """

            cursor.execute(query, (name, email, password_hash))
            connection.commit()

            print("Admin account created successfully!")

        except Exception as error:
            connection.rollback()
            print("Could not create admin account.")
            print("Check whether this email is already registered.")

        finally:
            cursor.close()
            connection.close()
    else:
        print("Database connection failed.")
