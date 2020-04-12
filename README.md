# OAuth Demo
An OAuth2 demo introduces how to setup OAuth client with Django.  

## Quick Start
1. Create virtual environment
1. Install requirements
```bash
pip install -r requirements.txt
```
1. Run the server
```bash
python manage.py migrate
python manage.py runserver
```

## Behind the scene
The OAuth2 configuration is located at settings.py

The default session backend is sqlite3.
