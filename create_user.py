"""Create a new admin user"""
from getpass import getpass
import sys

from flask import current_app
from tryg import tryg, bcrypt
from tryg import User, tryg_db

def main():
    """Main entry point for script."""
    with tryg.app_context():
        tryg_db.metadata.create_all(tryg_db.engine)
        if User.query.all():
            print('A user already exists! Create another? (y/n):')
            create = input()
            if create == 'n':
                return

        print('Enter username: ')
        username = input()
        password = getpass()
        assert password == getpass('Password (again):')

        user = User(
            username=username, 
            password=bcrypt.generate_password_hash(password))
        tryg_db.session.add(user)
        tryg_db.session.commit()
        print('User added.')


if __name__ == '__main__':
    sys.exit(main())