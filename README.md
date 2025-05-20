# Expense Tracker API

This project is a simple Expense Tracker API built with Flask and SQLite.

## Features
- User registration and login with hashed passwords
- JWT-based authentication
- CRUD operations for expenses
- Expense categories
- Date-based filters: past week, month, 3 months, or custom range

## Setup

1. **Clone the repository**
2. **Install dependencies**
   ```sh
   pip install flask python-dotenv bcrypt pyjwt
   ```
3. **Create a `.env` file**
   Add your secret key:
   ```
   SECRET_KEY=your_secret_key_here
   ```
4. **Run the API**
   ```sh
   python api.py
   ```

## API Endpoints

### Auth
- `POST /auth/register`
  ```json
  {
    "username": "yourname",
    "email": "your@email.com",
    "password": "yourpassword"
  }
  ```
- `POST /auth/login`
  ```json
  {
    "username": "yourname",
    "password": "yourpassword"
  }
  ```
- `POST /auth/logout`
  (No body required)

### Expenses
- `GET /expanses?filter=week|month|3months|custom&start_date=YYYY-MM-DD&end_date=YYYY-MM-DD`
  (Requires `Authorization: Bearer <token>` header)
- `POST /expanses`
  ```json
  {
    "amount": 10.5,
    "description": "Lunch",
    "category": "Food"
  }
  ```
- `PUT /expanses/<expanse_id>`
  ```json
  {
    "amount": 12.0,
    "description": "Updated lunch",
    "category": "Food"
  }
  ```
- `DELETE /expanses/<expanse_id>`
  (No body required)

## Project Source

This project is based on the requirements and roadmap from:
https://roadmap.sh/projects/expense-tracker-api
This URL leads to the webpage that proposed this project.
