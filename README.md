# 🛡️ Phishing Email Detection Tool

A comprehensive web application for analyzing emails and detecting potential phishing attempts using customizable suspicious phrase detection.

## 📋 Features

- **Email Analysis**: Upload and analyze `.eml` email files for suspicious content
- **Customizable Detection Rules**: Upload CSV/Excel files with your own suspicious phrases and segments
- **Database Storage**: Automatically stores flagged emails and analysis results
- **Statistical Reports**: View occurrence reports and phrase statistics
- **Real-time Analysis**: Get immediate feedback on email safety
- **Deduplication**: Prevents duplicate storage of the same emails

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or higher
- PostgreSQL database (configured via environment variables)

### Installation

1. **Clone or download the project**
   ```bash
   cd phish-detect
   ```

2. **Activate the virtual environment**
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   
   Ensure your `.env.local` file contains the database connection details:
   ```env
   PGDATABASE=your_database_name
   PGHOST=your_database_host
   PGPORT=5432
   PGUSER=your_username
   PGPASSWORD=your_password
   ```

5. **Run the application**
   ```powershell
   .\venv\Scripts\python.exe -m streamlit run app.py --server.port 8502
   ```

6. **Access the application**
   
   Open your browser and navigate to: `http://localhost:8502`

## 📁 Project Structure

```
phish-detect/
├── app.py                    # Main Streamlit application
├── database_service.py       # Database operations and connection management
├── email_parser.py          # Email parsing functionality
├── phishing_detector.py     # Core phishing detection logic
├── advanced_parser.py       # Advanced email parsing features
├── requirements.txt         # Python dependencies
├── .env.local              # Environment variables (database config)
├── .streamlit/
│   └── config.toml         # Streamlit configuration
├── venv/                   # Virtual environment
└── test_*.py              # Test files
```

## 🔧 Usage

### 1. Setup File Format

Create a CSV or Excel file with suspicious phrases using this format:

| start_segment | end_segment | suspicious_phrase |
|---------------|-------------|-------------------|
| subject       | subject     | urgent action required |
| body          | body        | click here now |
| headers       | headers     | no-reply |

**Supported segments:**
- `subject` - Email subject line
- `body` - Email body content
- `headers` - Email headers
- `from` - From address
- `to` - To address

### 2. Email File Requirements

- Upload `.eml` format email files
- Files should be standard RFC 2822 format
- Both plain text and HTML emails are supported

### 3. Analysis Process

1. **Upload Setup File**: Choose your CSV/Excel file with detection rules
2. **Upload Email File**: Select the `.eml` file to analyze
3. **Run Analysis**: Click "🚀 Run Phishing Detection"
4. **View Results**: Review findings, risk assessment, and detailed analysis

### 4. Database Features

- **View Database Report**: See statistics about flagged emails and top suspicious phrases
- **View All Flagged Emails**: Browse previously analyzed suspicious emails
- **Automatic Storage**: Suspicious emails are automatically stored for future reference

## 🗄️ Database Schema

The application uses PostgreSQL with the following main tables:

- `flagged_emails` - Stores suspicious emails with metadata
- `analysis_results` - Detailed findings for each email
- `phrase_statistics` - Aggregated statistics about suspicious phrases

## 🧪 Testing

Run the comprehensive database tests:

```bash
python test_database_service.py
```

This will verify:
- Database connectivity
- Email storage and retrieval
- Deduplication functionality
- Phrase statistics tracking
- Date parsing accuracy

## 🔍 How It Works

1. **Email Parsing**: The system parses `.eml` files to extract headers, subject, body, and metadata
2. **Segment Analysis**: Each email segment is analyzed against the provided suspicious phrases
3. **Pattern Matching**: Case-insensitive matching identifies potential phishing indicators
4. **Risk Assessment**: Emails with suspicious findings are flagged as potential phishing attempts
5. **Database Storage**: Results are stored with proper deduplication and statistics tracking

## 📊 Features in Detail

### Real-time Analysis
- Immediate feedback on email safety
- Detailed context for each suspicious finding
- Line-by-line analysis with context display

### Statistical Reporting
- Track most common suspicious phrases
- Monitor detection trends over time
- View recent flagged emails

### Data Management
- Automatic deduplication prevents duplicate storage
- Comprehensive CRUD operations for flagged emails
- Atomic database transactions ensure data integrity

## 🛠️ Configuration

### Streamlit Configuration
The `.streamlit/config.toml` file contains application settings. Default port is 8502.

### Database Configuration
All database settings are managed through environment variables in `.env.local`:

```env
PGDATABASE=neondb
PGHOST=your-host.neon.tech
PGPORT=5432
PGUSER=your_username
PGPASSWORD=your_password
```

## 🚨 Security Notes

- Never commit `.env.local` to version control
- Use strong database passwords
- Ensure your database connection uses SSL in production
- Regularly update dependencies for security patches

## 📝 License

This project is for educational and security research purposes.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📞 Support

For issues or questions:
1. Check the test files for examples
2. Review the database service documentation
3. Ensure all environment variables are properly configured
4. Verify database connectivity

---

**⚠️ Important**: This tool is designed for security research and educational purposes. Always ensure you have proper authorization before analyzing emails that don't belong to you.
