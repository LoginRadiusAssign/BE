# Brute-Force Protected Login Application

A full-stack login application with comprehensive brute-force protection mechanisms including user-level suspension and IP-level blocking.

## 🔒 Features

- **User-Level Suspension**: Locks user account for 15 minutes after 5 failed attempts within 5 minutes
- **IP-Level Blocking**: Blocks IP address after 100 failed attempts within 5 minutes across all users
- **Real-time Feedback**: Clear error messages for locked/blocked attempts
- **Persistent Storage**: PostgreSQL database for data persistence across restarts
- **Modern UI**: React-based responsive interface with Tailwind CSS
- **Comprehensive Testing**: Unit tests for core security logic

## 🏗️ Architecture

### Tech Stack
- **Frontend**: React 18 with Tailwind CSS and Lucide icons
- **Backend**: Flask (Python) REST API
- **Database**: PostgreSQL 14+
- **Testing**: Python unittest with mocking

### Design Decisions

1. **Database Schema**:
   - `users` table: Stores user credentials with SHA-256 hashed passwords
   - `failed_login_attempts` table: Tracks all failed attempts with timestamps
   - Indexed on email+timestamp and ip+timestamp for query performance

2. **Security Logic**:
   - Time-window based checks using SQL queries
   - Separate thresholds for user and IP level
   - Failed attempts cleared on successful login
   - IP address extracted from X-Forwarded-For header for proxy support

3. **Stateless Design**:
   - No in-memory state; all data in PostgreSQL
   - Scales horizontally across multiple servers
   - Survives application restarts

## 📦 Installation & Setup

### Prerequisites
- Node.js 16+
- Python 3.9+
- PostgreSQL 14+

### Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup PostgreSQL database
psql -U postgres
# Then run commands from schema.sql

# Create .env file
cp .env.example .env
# Edit .env with your database credentials

# Run the application
python app.py
```

Backend will run on `http://localhost:5000`
Backend Deployed on Render

### Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Update API endpoint in src/App.js if needed
# Default: http://localhost:5000

# Start development server
npm start
```

Frontend will run on `http://localhost:3000`
Frontend Deployed on Vercel

### Running Tests

```bash
# Backend tests
cd backend
python -m pytest test_app.py -v

# Or with unittest
python test_app.py
```

## 🗄️ Database Schema

```sql
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Failed login attempts
CREATE TABLE failed_login_attempts (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🧪 Testing the System

### Demo Accounts
- **Email**: alice@example.com | **Password**: password123
- **Email**: bob@example.com | **Password**: secure456

### Test Scenarios

**User Suspension Test**:
1. Try logging in with `alice@example.com` and wrong password
2. Repeat 5 times within 5 minutes
3. 6th attempt should show suspension message
4. Wait 15 minutes or use correct password after suspension ends

**IP Block Test**:
1. Make 100 failed login attempts from same IP (can use different emails)
2. 101st attempt should show IP block message
3. Block lasts until 5-minute window expires

## 🚀 Deployment

### Backend (Railway/Render)
1. Create PostgreSQL database instance
2. Set environment variables:
   - `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`
3. Deploy backend with `gunicorn app:app`

### Frontend (Vercel/Netlify)
1. Update API endpoint to deployed backend URL
2. Build: `npm run build`
3. Deploy `build` directory

## 📊 API Endpoints

### POST `/api/login`
Login endpoint with brute-force protection

**Request**:
```json
{
  "email": "alice@example.com",
  "password": "password123"
}
```

**Responses**:
- `200`: Successful login
- `401`: Invalid credentials
- `403`: User suspended or IP blocked
- `400`: Missing credentials

### GET `/api/health`
Health check endpoint

## 🔧 Configuration

Thresholds can be adjusted in `app.py`:

```python
USER_FAILED_ATTEMPT_THRESHOLD = 5
USER_FAILED_ATTEMPT_WINDOW = 5  # minutes
USER_SUSPENSION_DURATION = 15  # minutes

IP_FAILED_ATTEMPT_THRESHOLD = 100
IP_FAILED_ATTEMPT_WINDOW = 5  # minutes
```

## 📁 Project Structure

```
project/
├── backend/
│   ├── app.py              # Flask application
│   ├── test_app.py         # Unit tests
│   ├── requirements.txt    # Python dependencies
│   ├── schema.sql          # Database schema
│   └── .env.example        # Environment template
├── frontend/
│   ├── src/
│   │   └── App.js          # React application
│   ├── package.json        # Node dependencies
│   └── tailwind.config.js  # Tailwind configuration
└── README.md
```

## 🧰 Testing Coverage

Unit tests cover:
- Password hashing consistency
- User suspension logic
- IP blocking logic
- Successful login flow
- Failed login recording
- Threshold validation
- Time window expiration
- API endpoint responses

Run tests with coverage:
```bash
python -m pytest test_app.py --cov=app --cov-report=html
```

## 🤖 AI Usage Report

**AI-Generated Components** (~70%):
- Initial Flask API structure
- React component boilerplate
- Database schema design
- Basic unit test structure

**Manual Development** (~30%):
- Security logic fine-tuning
- Edge case handling
- IP extraction logic
- Test case scenarios
- Documentation

**Time Breakdown**:
- AI code generation: ~2 hours
- Testing & debugging: ~3 hours
- Refinement & optimization: ~2 hours
- Documentation: ~1 hour
- **Total**: ~8 hours

**AI Tools Used**:
- ChatGPT/Claude for initial code generation
- GitHub Copilot for code completion
- Manual review and testing of all AI-generated code

## 📝 License

MIT

## 👤 Author

G Meghashyam

## 🙏 Acknowledgments

- Flask documentation
- React documentation
- PostgreSQL documentation