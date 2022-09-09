from models import db, create_data

if __name__ == '__main__':
    db.create_all()
    create_data()