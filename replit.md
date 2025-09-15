# IOC Extractor & Triage Application

## Overview

This is a client-side web application for cybersecurity professionals to extract and validate Indicators of Compromise (IOCs) from text data. The application uses regular expressions to identify various types of IOCs including IP addresses, domains, URLs, email addresses, file hashes, Bitcoin addresses, filenames, and CVE identifiers. It provides a dark-themed interface for analyzing security data with export capabilities and real-time validation features.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Single Page Application (SPA)**: Built with vanilla HTML, CSS, and JavaScript without frameworks
- **Client-side Processing**: All IOC extraction and validation happens in the browser using JavaScript regular expressions
- **Responsive Design**: CSS Grid and Flexbox layout with mobile-first responsive design principles
- **Dark Theme**: Consistent dark color scheme optimized for security work environments

### Data Processing Architecture
- **Pattern-based Extraction**: Uses predefined regular expressions for each IOC type (IPv4/IPv6, domains, URLs, emails, hashes, Bitcoin addresses, filenames, CVEs)
- **Real-time Validation**: Immediate processing and categorization of extracted IOCs
- **IP Classification**: Built-in logic to identify private IP ranges and RFC 6890 special-use addresses
- **Hash Type Detection**: Automatic classification of MD5, SHA1, and SHA256 hashes based on length

### User Interface Components
- **Sticky Header**: Contains application title and action buttons (Clear, Export CSV/JSON, Copy All)
- **Input Panel**: Large textarea for pasting raw text data with extract and sample data buttons
- **Results Panel**: Dynamic display of categorized IOCs with icons and counts
- **Toast Notifications**: Non-intrusive feedback system for user actions
- **Export System**: Multiple output formats (CSV, JSON) for integration with other security tools

### State Management
- **Global State**: Simple JavaScript object (`currentResults`) to store extracted IOC data
- **Category System**: Structured IOC classification with icons and human-readable names
- **No Persistence**: All data is session-based with no local storage or server communication

## External Dependencies

### No External Services
- **Fully Offline**: Application operates entirely client-side without API calls or server dependencies
- **No Authentication**: No user accounts or authentication mechanisms required
- **No Database**: All processing happens in memory during the browser session
- **Self-contained**: No CDN dependencies or external JavaScript libraries

### Browser APIs Used
- **Clipboard API**: For copy-to-clipboard functionality
- **File API**: For CSV/JSON export download capabilities
- **DOM API**: Standard browser APIs for UI manipulation and event handling

### Potential Integration Points
- **CSV Export**: Compatible with spreadsheet applications and SIEM tools
- **JSON Export**: Structured data format for API consumption and automation tools
- **Copy Functionality**: Enables easy integration with other security analysis tools