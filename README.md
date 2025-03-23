#PhishNet: AI-Powered Phishing URL Detection Extension

##Project Overview
This project is a browser extension integrated with a backend system designed to detect phishing websites and malicious URLs in real-time. It utilizes multiple external APIs, SSL validation, domain age checks, and other indicators to classify URLs as Safe, Suspicious, or Malicious. Each scan is logged in a MongoDB database, and results are displayed through a dashboard and the browser extension.

##Features
Real-time phishing detection and classification
Integration with multiple security APIs
Domain age verification and SSL certificate grading
URL expansion and unshortening support
MongoDB database for logging scan results
Browser extension with real-time alerts
Dashboard to view scan history and analysis results
Basic email scraping to extract and scan URLs from emails

##Technology Stack
Frontend: HTML, CSS, JavaScript
Backend: Node.js (Express.js), Python (Flask)
Database: MongoDB
Browser Extension: JavaScript (Manifest v3)
####External APIs:
VirusTotal
AbuseIPDB
WhoisXMLAPI
SSL Labs API
Unshorten.me API

##How It Works
Users visit a website or provide a URL, or the system scrapes URLs from emails.
####The backend processes the URL through:
Blacklist checks (VirusTotal, AbuseIPDB)
Whois lookup for domain creation date and registrar
SSL Labs API to fetch SSL certificate grading
URL unshortening for shortened links
The system classifies the URL and provides reasons for the decision.
Results are stored in MongoDB for record-keeping.
The browser extension displays the classification result in real-time.
A dashboard allows users to review the scan history.
