-- Create database
CREATE DATABASE login_db;

-- Connect to the database
\c login_db;

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Failed login attempts table
CREATE TABLE failed_login_attempts (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_failed_attempts_email ON failed_login_attempts(email, attempted_at);
CREATE INDEX idx_failed_attempts_ip ON failed_login_attempts(ip_address, attempted_at);

-- Insert demo users (passwords: alice=password123, bob=secure456)
INSERT INTO users (email, password_hash) VALUES
    ('alice@example.com', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'),
    ('bob@example.com', '6cf615d5bcaac778352a8f1f3360d23f02f34ec182e259897fd6ce485d7870d4');

-- Optional: Create a cleanup function to remove old failed attempts
CREATE OR REPLACE FUNCTION cleanup_old_attempts() RETURNS void AS $$
BEGIN
    DELETE FROM failed_login_attempts 
    WHERE attempted_at < NOW() - INTERVAL '1 hour';
END;
$$ LANGUAGE plpgsql;