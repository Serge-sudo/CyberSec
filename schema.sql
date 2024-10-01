DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    secret_phrase TEXT NOT NULL,
    password_set_time TEXT NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    lockout_time TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
