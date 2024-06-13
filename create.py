from app import db, app  # Corrected import statement

with app.app_context():
    db.create_all()
