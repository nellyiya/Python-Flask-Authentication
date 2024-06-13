# Create virtual environment
py -m .venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install required packages
pip install flask flask_sqlalchemy flask_login flask_wtf flask_bcrypt

# Generate requirements.txt file
pip freeze > requirements.txt

# Run Flask app
py .\app.py

# Deactivate virtual environment
deactivate
