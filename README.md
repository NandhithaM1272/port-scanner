# 🔐 Advanced Network Security Scanner

A web-based network security application that allows users to scan authorized targets, identify open ports and services, and analyze potential security risks.

## What It Does

- Scans IP addresses and hostnames
- Detects open TCP and UDP ports
- Identifies running services and versions
- Classifies detected ports based on security risk
- Provides security recommendations
- Stores scan history for each logged-in user
- Allows users to view history for different targets
- Generates security reports

## Built With

**Frontend**
- React
- JavaScript
- HTML
- CSS

**Backend**
- Python
- Flask
- Nmap

**Database**
- Supabase

## Project Structure

```text
port-scanner/
├── backend/
│   ├── app.py
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── README.md
│
└── .gitignore
