# ThreatWatch — Log Analysis \& Threat Detection System

A cybersecurity project that parses SSH and Apache server logs, detects threats using rule-based detection, generates alerts with severity levels, stores them in a MySQL database, and displays everything on a Flask dashboard.

\---

## Screenshots

> ## Screenshots



\### Live Alerts Dashboard

!\[Live Alerts](screenshots/1\_live\_alerts.png)



\### Alert Detail Modal

!\[Alert Modal](screenshots/2\_alert\_modal.png)



\### Log Viewer

!\[Log Viewer](screenshots/3\_log\_viewer.png)



\### Database History

!\[Database History](screenshots/4\_database\_history.png)Features

* SSH log parsing and brute force detection
* Apache log parsing and web scan detection
* 5 detection rules (Brute Force, User Enumeration, Web Scanning, Sensitive Path Access, HTTP 500 Spike)
* Alert severity levels — Critical, High, Medium
* Click-to-open alert modal with full event breakdown
* MySQL database integration for permanent alert storage
* Flask web dashboard with 3 tabs — Live Alerts, Log Viewer, Database History
* New Simulation button to generate fresh attack logs
* alerts.log file saved automatically on every scan

\---

## Tech Stack

|Technology|Purpose|
|-|-|
|Python 3|Backend logic and log parsing|
|Flask|Web server and dashboard|
|MySQL|Permanent alert storage|
|Regex|Log pattern detection|
|HTML / CSS / JavaScript|Frontend dashboard|

\---

## Project Structure

```
log\\\_threat\\\_detector/
  ├── app.py                  # Flask web server
  ├── analyzer.py             # Core threat detection engine
  ├── database.py             # MySQL database integration
  ├── generate\\\_sample\\\_logs.py # Sample log generator
  ├── run\\\_analysis.py         # CLI runner (no Flask needed)
  ├── requirements.txt        # Python dependencies
  ├── .gitignore
  └── templates/
        └── dashboard.html    # Web dashboard UI
```

\---

## Detection Rules

|Rule|Trigger|Severity|
|-|-|-|
|SSH Brute Force|More than 5 failed SSH logins from same IP|CRITICAL / HIGH|
|SSH User Enumeration|3+ invalid usernames probed from same IP|HIGH|
|Apache Directory Scan|8+ suspicious HTTP responses (401/403/404)|CRITICAL / HIGH|
|Sensitive Path Access|Requests to /.env, /admin, /phpmyadmin etc.|CRITICAL|
|HTTP 500 Error Spike|3+ server errors from same IP|MEDIUM|

\---

## Setup \& Installation

### 1\. Clone the repository

```bash
git clone https://github.com/YOUR\\\_USERNAME/log-threat-detector.git
cd log-threat-detector
```

### 2\. Install dependencies

```bash
pip install -r requirements.txt
```

### 3\. Configure MySQL

Open `database.py` and update:

```python
DB\\\_CONFIG = {
    "host":     "localhost",
    "port":     3306,        # your MySQL port
    "user":     "root",
    "password": "yourpassword",
    "database": "threatwatch"
}
```

### 4\. Run the dashboard

```bash
# Windows
set PYTHONUTF8=1
python app.py

# Mac/Linux
python app.py
```

### 5\. Open browser

```
http://127.0.0.1:5000
```

\---

## CLI Usage (without Flask)

```bash
python run\\\_analysis.py
```

\---

## How It Works

```
Sample Logs Generated
        ↓
analyzer.py parses SSH + Apache logs
        ↓
5 Detection Rules applied
        ↓
Alerts created with severity levels
        ↓
Saved to alerts.log + MySQL database
        ↓
Flask dashboard displays everything
```

\---

## Author

**Adithya B R**  
Cybersecurity Enthusiast | Python Developer

\---

## License

MIT License

