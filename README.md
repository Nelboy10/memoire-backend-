# Memoire Backend

This is the backend for the Memoire application, built using Django and Django REST Framework.

## Local Development Setup

Follow these instructions to set up and run the backend locally. By default, the application is configured to use a local **SQLite** database for development.

### Prerequisites

- Python 3.10+ installed on your machine
- Git

### Installation Steps

1. **Clone the repository (if not already done)**
   ```bash
   git clone <repository-url>
   cd memoire-backend-
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows (PowerShell)
   .\venv\Scripts\Activate.ps1
   
   # On Windows (Command Prompt)
   venv\Scripts\activate.bat
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install the dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the local database**
   The project uses SQLite by default when running locally without a remote database configuration.
   Apply the migrations to set up your database schema:
   ```bash
   python manage.py migrate
   ```

5. **Create a superuser (optional but recommended for accessing the admin panel)**
   ```bash
   python manage.py createsuperuser
   ```

6. **Run the development server**
   ```bash
   python manage.py runserver
   ```
   
   The API will be available at `http://127.0.0.1:8000/`.

## Configuration (Optional)

If you wish to connect to a remote PostgreSQL database (like Neon) in production or standard development, you can create a `.env` file in the root directory and add the following configuration:

```env
DATABASE_URL=postgres://user:password@hostname:port/dbname
```
Otherwise, the local SQLite database (`db.sqlite3`) generated will be used seamlessly.
