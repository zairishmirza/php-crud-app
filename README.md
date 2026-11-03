# PHP CRUD App

A beginner-friendly user management system built with **PHP, MySQLi and MySQL**. The whole app runs on just three PHP files, using one reusable `crud()` function for every database operation.

## Features

- User registration with validation and password hashing
- Login with username or email
- Forgot username and forgot password (token-based reset, 1-hour expiry)
- Dashboard after successful login
- Users list, edit and delete (admin only)
- Login history (successful and failed attempts)
- CSRF protection, prepared statements, and output escaping

## Tech Stack

- PHP 8+ (MySQLi with mysqlnd)
- MySQL / MariaDB
- HTML and CSS
- XAMPP or WAMP for local development

## Project Structure

```
crud_app/
├── schema.sql       # Creates the database and tables
├── db.php           # Database connection and session start
├── functions.php    # Reusable crud() function and helpers
└── index.php        # The whole app, routed with ?page=...
```

## Database

Three related tables in a database named `crud_app`:

| Table | Purpose |
|---|---|
| `users` | Accounts: name, username, email, hashed password, role, status |
| `password_resets` | Hashed reset tokens with expiry |
| `login_logs` | Login attempts per user |

`password_resets` and `login_logs` reference `users(user_id)` with `ON DELETE CASCADE`.

## Installation

1. Clone the repository into your web server folder (`htdocs` for XAMPP, `www` for WAMP):
   ```bash
   git clone https://github.com/YOUR-USERNAME/php-crud-app.git
   ```
2. Open phpMyAdmin, go to the **SQL** tab (or **Import**), and run `schema.sql`.
3. Edit `db.php` if your MySQL username or password differs from the defaults (`root` / empty).
4. Visit `http://localhost/php-crud-app/index.php`.
5. Register your first account. **The first registered user becomes the admin.**

## Routes

| URL | Page |
|---|---|
| `index.php?page=register` | Registration |
| `index.php?page=login` | Login |
| `index.php?page=dashboard` | Dashboard |
| `index.php?page=users` | Users list |
| `index.php?page=edit&id=1` | Edit user |
| `index.php?page=forgot_username` | Username recovery |
| `index.php?page=forgot_password` | Password recovery |
| `index.php?page=logout` | Logout |

Deleting a user is a POST request from the Users table (admin only).

## Using the `crud()` function

```php
// Create
crud($conn, "INSERT", "users", ["username" => "ali", "email" => "ali@gmail.com"]);

// Read
$rows = crud($conn, "SELECT", "users", [], ["user_id" => 1]);

// Update
crud($conn, "UPDATE", "users", ["phone" => "03001234567"], ["user_id" => 1]);

// Delete
crud($conn, "DELETE", "users", [], ["user_id" => 1]);
```

Values use prepared statements. Table and column names are checked against a whitelist inside the function.

## Security Notes

- Passwords hashed with `password_hash()` and verified with `password_verify()`
- Prepared statements for all queries
- Session ID regenerated on login
- CSRF tokens on all forms
- Reset tokens stored as SHA-256 hashes
- Admin-only user management

## Limitations

This is a learning project, not production-ready:

- Forgot username/password results are shown on screen because localhost has no mail server. A real app should email them.
- Database credentials are in `db.php`. Do not commit real production credentials.

## Ideas for Next Steps

- Search and pagination on the users list
- Profile picture upload
- Email sending with PHPMailer
- Rate limiting for login attempts
- Migrating to PDO

## License

MIT License. Free to use for learning.
