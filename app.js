/**
 * IOC Extractor & Triage Application
 * Extracts and validates Indicators of Compromise from text
 */

// Global state
let currentResults = null;

// IOC Categories
const IOC_CATEGORIES = {
    ipv4: { name: 'IPv4 Addresses', icon: '🌐' },
    ipv6: { name: 'IPv6 Addresses', icon: '🌐' },
    domains: { name: 'Domain Names', icon: '🏷️' },
    urls: { name: 'URLs', icon: '🔗' },
    emails: { name: 'Email Addresses', icon: '📧' },
    hashes: { name: 'Hashes', icon: '🔐' },
    bitcoin: { name: 'Bitcoin Addresses', icon: '₿' },
    filenames: { name: 'File Names', icon: '📄' },
    cves: { name: 'CVE IDs', icon: '🛡️' }
};

// Regular expressions for IOC extraction
const IOC_PATTERNS = {
    ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    ipv6: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b/g,
    domains: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/g,
    urls: /https?:\/\/(?:[-\w.])+(?::[0-9]+)?(?:\/(?:[\w._~!$&'()*+,;=:@-]|%[0-9a-fA-F]{2})*)*(?:\?(?:[\w._~!$&'()*+,;=:@/?-]|%[0-9a-fA-F]{2})*)?(?:#(?:[\w._~!$&'()*+,;=:@/?-]|%[0-9a-fA-F]{2})*)?/g,
    emails: /\b[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b/g,
    hashes: {
        md5: /\b[a-fA-F0-9]{32}\b/g,
        sha1: /\b[a-fA-F0-9]{40}\b/g,
        sha256: /\b[a-fA-F0-9]{64}\b/g
    },
    bitcoin: /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/g,
    filenames: /\b[a-zA-Z0-9._-]+\.[a-zA-Z]{2,5}\b/g,
    cves: /CVE-\d{4}-\d{4,}/gi
};

// Private IP ranges and RFC 6890 special-use ranges for tagging
const PRIVATE_IP_RANGES = [
    { start: [10, 0, 0, 0], end: [10, 255, 255, 255], name: 'private-range' },
    { start: [172, 16, 0, 0], end: [172, 31, 255, 255], name: 'private-range' },
    { start: [192, 168, 0, 0], end: [192, 168, 255, 255], name: 'private-range' },
    { start: [127, 0, 0, 0], end: [127, 255, 255, 255], name: 'special-use' }, // Loopback
    { start: [169, 254, 0, 0], end: [169, 254, 255, 255], name: 'special-use' }, // Link Local
    { start: [224, 0, 0, 0], end: [239, 255, 255, 255], name: 'special-use' }, // Multicast
    { start: [192, 0, 2, 0], end: [192, 0, 2, 255], name: 'special-use' }, // TEST-NET-1
    { start: [198, 51, 100, 0], end: [198, 51, 100, 255], name: 'special-use' }, // TEST-NET-2
    { start: [203, 0, 113, 0], end: [203, 0, 113, 255], name: 'special-use' }, // TEST-NET-3
    { start: [100, 64, 0, 0], end: [100, 127, 255, 255], name: 'special-use' }, // Carrier-grade NAT
    { start: [0, 0, 0, 0], end: [0, 255, 255, 255], name: 'special-use' }, // "This" Network
    { start: [240, 0, 0, 0], end: [255, 255, 255, 254], name: 'special-use' }, // Reserved
    { start: [255, 255, 255, 255], end: [255, 255, 255, 255], name: 'special-use' }, // Broadcast
    { start: [198, 18, 0, 0], end: [198, 19, 255, 255], name: 'special-use' }, // Benchmarking
    { start: [192, 0, 0, 0], end: [192, 0, 0, 255], name: 'special-use' }, // IETF Protocol Assignments
    { start: [192, 88, 99, 0], end: [192, 88, 99, 255], name: 'special-use' }, // 6to4 Relay Anycast
    { start: [233, 252, 0, 0], end: [233, 252, 0, 255], name: 'special-use' } // MCAST-TEST-NET
];

// Sample data for demonstration
const SAMPLE_DATA = `Subject: Urgent Security Alert - Malware Detection
From: security@company.com
To: admin@company.com
Date: Mon, 15 Sep 2025 10:30:00 +0000
X-Originating-IP: 192.168.1.100

Suspicious activity detected from IP 185.220.101.42 and 2001:db8::1
Malicious domains: evil-site.malware.com, phishing-bank.net
URLs accessed: https://evil-site.malware.com/download.php?id=123
Bitcoin payment: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

Files involved:
- malware.exe (MD5: 5d41402abc4b2a76b9719d911017c592)
- trojan.dll (SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d)  
- rootkit.sys (SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)

CVE References: CVE-2025-1234, CVE-2024-5678

Log entries show connections to:
- 203.0.113.45:443
- hacker-tools.darkweb.onion
- contact@cybercriminal.org

Please investigate immediately.`;

/**
 * Initialize the application
 */
function init() {
    setupEventListeners();
    loadStoredResults();
    showToast('IOC Extractor ready', 'info');
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
    // Header buttons
    document.getElementById('clear-btn').addEventListener('click', clearAll);
    document.getElementById('export-csv-btn').addEventListener('click', exportCSV);
    document.getElementById('export-json-btn').addEventListener('click', exportJSON);
    document.getElementById('copy-all-btn').addEventListener('click', copyAll);
    
    // Input buttons
    document.getElementById('extract-btn').addEventListener('click', extractIOCs);
    document.getElementById('sample-data-btn').addEventListener('click', loadSampleData);
    
    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
    
    // Auto-resize textarea
    const textarea = document.getElementById('input-text');
    textarea.addEventListener('input', autoResizeTextarea);
}

/**
 * Handle keyboard shortcuts
 */
function handleKeyboardShortcuts(event) {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        event.preventDefault();
        extractIOCs();
    } else if ((event.ctrlKey || event.metaKey) && event.key === 'k') {
        event.preventDefault();
        clearAll();
    }
}

/**
 * Auto-resize textarea based on content
 */
function autoResizeTextarea() {
    const textarea = document.getElementById('input-text');
    textarea.style.height = 'auto';
    textarea.style.height = Math.max(200, textarea.scrollHeight) + 'px';
}

/**
 * Load sample data into textarea
 */
function loadSampleData() {
    document.getElementById('input-text').value = SAMPLE_DATA;
    autoResizeTextarea();
    showToast('Sample data loaded', 'success');
}

/**
 * Clear all data
 */
function clearAll() {
    document.getElementById('input-text').value = '';
    currentResults = null;
    localStorage.removeItem('ioc_run');
    displayResults({});
    autoResizeTextarea();
    showToast('All data cleared', 'info');
}

/**
 * Extract IOCs from input text
 */
function extractIOCs() {
    const inputText = document.getElementById('input-text').value.trim();
    
    if (!inputText) {
        showToast('Please enter some text to analyze', 'warning');
        return;
    }
    
    showToast('Extracting IOCs...', 'info');
    
    try {
        const results = performExtraction(inputText);
        currentResults = results;
        
        // Store in localStorage
        localStorage.setItem('ioc_run', JSON.stringify(results));
        
        displayResults(results);
        
        const totalCount = Object.values(results).reduce((sum, items) => sum + items.length, 0);
        showToast(`Extracted ${totalCount} IOCs`, 'success');
        
    } catch (error) {
        console.error('Extraction error:', error);
        showToast('Error during extraction', 'error');
    }
}

/**
 * Perform IOC extraction from text
 */
function performExtraction(text) {
    const results = {};
    const now = new Date().toISOString();
    
    // Extract IPv4 addresses
    results.ipv4 = extractAndValidateIPv4(text, now);
    
    // Extract IPv6 addresses
    results.ipv6 = extractAndValidateIPv6(text, now);
    
    // Extract domains
    results.domains = extractAndValidateDomains(text, now);
    
    // Extract URLs
    results.urls = extractAndValidateURLs(text, now);
    
    // Extract emails
    results.emails = extractAndValidateEmails(text, now);
    
    // Extract hashes
    results.hashes = extractAndValidateHashes(text, now);
    
    // Extract Bitcoin addresses
    results.bitcoin = extractAndValidateBitcoin(text, now);
    
    // Extract filenames
    results.filenames = extractAndValidateFilenames(text, now);
    
    // Extract CVE IDs
    results.cves = extractAndValidateCVEs(text, now);
    
    return results;
}

/**
 * Extract and validate IPv4 addresses
 */
function extractAndValidateIPv4(text, timestamp) {
    const matches = [...text.matchAll(IOC_PATTERNS.ipv4)];
    const seen = new Set();
    const results = [];
    
    for (const match of matches) {
        const ip = match[0];
        const key = ip.toLowerCase();
        
        if (seen.has(key)) continue;
        seen.add(key);
        
        // Validate IPv4 format
        if (!isValidIPv4(ip)) continue;
        
        const notes = [];
        const ipRange = getIPRange(ip);
        if (ipRange) notes.push(ipRange);
        
        results.push({
            value: ip,
            notes,
            firstSeen: timestamp
        });
    }
    
    return results;
}

/**
 * Extract and validate IPv6 addresses
 */
function extractAndValidateIPv6(text, timestamp) {
    const matches = [...text.matchAll(IOC_PATTERNS.ipv6)];
    const seen = new Set();
    const results = [];
    
    for (const match of matches) {
        const ip = match[0].toLowerCase();
        const key = ip;
        
        if (seen.has(key)) continue;
        seen.add(key);
        
        // Basic IPv6 validation
        if (!isValidIPv6(ip)) continue;
        
        const notes = [];
        if (ip.startsWith('::1') || ip === '::1') notes.push('loopback');
        if (ip.startsWith('fe80:')) notes.push('link-local');
        if (ip.startsWith('ff')) notes.push('multicast');
        
        results.push({
            value: ip,
            notes,
            firstSeen: timestamp
        });
    }
    
    return results;
}

/**
 * Extract and validate domains
 */
function extractAndValidateDomains(text, timestamp) {
    const matches = [...text.matchAll(IOC_PATTERNS.domains)];
    const seen = new Set();
    const results = [];
    
    for (const match of matches) {
        const domain = match[0].toLowerCase();
        const key = domain;
        
        if (seen.has(key)) continue;
        seen.add(key);
        
        // Validate domain format
        if (!isValidDomain(domain)) continue;
        
        results.push({
            value: domain,
            notes: [],
            firstSeen: timestamp
        });
    }
    
    return results;
}

/**
 * Extract and validate URLs
 */
function extractAndValidateURLs(text, timestamp) {
    const matches = [...text.matchAll(IOC_PATTERNS.urls)];
    const seen = new Set();
    const hostCounts = {};
    const results = [];
    
    for (const match of matches) {
        const url = match[0];
        const key = url.toLowerCase();
        
        if (seen.has(key)) continue;
        seen.add(key);
        
        // Validate URL format
        if (!isValidURL(url)) continue;
        
        const notes = [];
        try {
            const urlObj = new URL(url);
            const host = urlObj.hostname.toLowerCase();
            hostCounts[host] = (hostCounts[host] || 0) + 1;
            
            if (hostCounts[host] > 1) {
                notes.push('duplicate-host');
            }
        } catch (e) {
            // Invalid URL, skip
            continue;
        }
        
        results.push({
            value: url,
            notes,
            firstSeen: timestamp
        });
    }
    
    return results;
}

/**
 * Extract and validate email addresses
 */
function extractAndValidateEmails(text, timestamp) {
    const matches = [...text.matchAll(IOC_PATTERNS.emails)];
    const seen = new Set();
    const results = [];
    
    for (const match of matches) {
        const email = match[0].toLowerCase();
        const key = email;
        
        if (seen.has(key)) continue;
        seen.add(key);
        
        // Validate email format
        if (!isValidEmail(email)) continue;
        
        results.push({
            value: email,
            notes: [],
            firstSeen: timestamp
        });
    }
    
    return results;
}

/**
 * Extract and validate hashes
 */
function extractAndValidateHashes(text, timestamp) {
    const results = [];
    const seen = new Set();
    
    // Extract MD5 hashes
    const md5Matches = [...text.matchAll(IOC_PATTERNS.hashes.md5)];
    for (const match of md5Matches) {
        const hash = match[0].toLowerCase();
        if (seen.has(hash)) continue;
        seen.add(hash);
        
        results.push({
            value: hash,
            algo: 'MD5',
            notes: [],
            firstSeen: timestamp
        });
    }
    
    // Extract SHA1 hashes
    const sha1Matches = [...text.matchAll(IOC_PATTERNS.hashes.sha1)];
    for (const match of sha1Matches) {
        const hash = match[0].toLowerCase();
        if (seen.has(hash)) continue;
        seen.add(hash);
        
        results.push({
            value: hash,
            algo: 'SHA1',
            notes: [],
            firstSeen: timestamp
        });
    }
    
    // Extract SHA256 hashes
    const sha256Matches = [...text.matchAll(IOC_PATTERNS.hashes.sha256)];
    for (const match of sha256Matches) {
        const hash = match[0].toLowerCase();
        if (seen.has(hash)) continue;
        seen.add(hash);
        
        results.push({
            value: hash,
            algo: 'SHA256',
            notes: [],
            firstSeen: timestamp
        });
    }
    
    return results;
}

/**
 * Extract and validate Bitcoin addresses
 */
function extractAndValidateBitcoin(text, timestamp) {
    const matches = [...text.matchAll(IOC_PATTERNS.bitcoin)];
    const seen = new Set();
    const results = [];
    
    for (const match of matches) {
        const address = match[0];
        const key = address;
        
        if (seen.has(key)) continue;
        seen.add(key);
        
        // Basic Bitcoin address validation
        if (!isValidBitcoinAddress(address)) continue;
        
        results.push({
            value: address,
            notes: [],
            firstSeen: timestamp
        });
    }
    
    return results;
}

/**
 * Extract and validate filenames
 */
function extractAndValidateFilenames(text, timestamp) {
    const matches = [...text.matchAll(IOC_PATTERNS.filenames)];
    const seen = new Set();
    const results = [];
    
    for (const match of matches) {
        const filename = match[0];
        const key = filename.toLowerCase();
        
        if (seen.has(key)) continue;
        seen.add(key);
        
        // Validate filename format and exclude URLs/domains
        if (!isValidFilename(filename)) continue;
        
        // Exclude if this filename appears to be part of a URL or domain
        const beforeMatch = text.substring(Math.max(0, match.index - 20), match.index);
        const afterMatch = text.substring(match.index + filename.length, match.index + filename.length + 20);
        const contextText = beforeMatch + filename + afterMatch;
        
        if (IOC_PATTERNS.urls.test(contextText) || IOC_PATTERNS.domains.test(contextText)) continue;
        
        results.push({
            value: filename,
            notes: [],
            firstSeen: timestamp
        });
    }
    
    return results;
}

/**
 * Extract and validate CVE IDs
 */
function extractAndValidateCVEs(text, timestamp) {
    const matches = [...text.matchAll(IOC_PATTERNS.cves)];
    const seen = new Set();
    const results = [];
    
    for (const match of matches) {
        const cve = match[0].toUpperCase();
        const key = cve;
        
        if (seen.has(key)) continue;
        seen.add(key);
        
        // Validate CVE format and extract year/id as integers
        const cveMatch = cve.match(/^CVE-(\d{4})-(\d{4,})$/);
        if (!cveMatch) continue;
        
        const year = parseInt(cveMatch[1], 10);
        const id = parseInt(cveMatch[2], 10);
        
        if (year < 1999 || year > new Date().getFullYear() + 1 || id < 0) continue;
        
        results.push({
            value: cve,
            year: year,
            id: id,
            notes: [],
            firstSeen: timestamp
        });
    }
    
    return results;
}

/**
 * Validation functions
 */
function isValidIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    
    for (const part of parts) {
        // Check for leading zeros (except '0' itself)
        if (part.length > 1 && part[0] === '0') return false;
        
        const num = parseInt(part, 10);
        if (isNaN(num) || num < 0 || num > 255) return false;
    }
    return true;
}

function isValidIPv6(ip) {
    // Simplified IPv6 validation
    const parts = ip.split(':');
    if (parts.length < 3 || parts.length > 8) return false;
    
    let doubleColonCount = 0;
    for (let i = 0; i < parts.length - 1; i++) {
        if (parts[i] === '' && parts[i + 1] === '') {
            doubleColonCount++;
            if (doubleColonCount > 1) return false;
        }
    }
    
    for (const part of parts) {
        if (part !== '' && !/^[0-9a-fA-F]{1,4}$/.test(part)) return false;
    }
    
    return true;
}

function isValidDomain(domain) {
    if (domain.length > 253) return false;
    if (domain.startsWith('.') || domain.endsWith('.')) return false;
    
    const parts = domain.split('.');
    if (parts.length < 2) return false;
    
    // Check TLD length
    const tld = parts[parts.length - 1];
    if (tld.length < 2 || tld.length > 24) return false;
    
    for (const part of parts) {
        if (part.length === 0 || part.length > 63) return false;
        if (!/^[a-zA-Z0-9-]+$/.test(part)) return false;
        if (part.startsWith('-') || part.endsWith('-')) return false;
    }
    
    return true;
}

function isValidURL(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch {
        return false;
    }
}

function isValidEmail(email) {
    const [local, domain] = email.split('@');
    if (!local || !domain) return false;
    if (local.length > 64 || domain.length > 253) return false;
    
    // Validate local part
    if (!/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)) return false;
    
    // Use domain validator for domain part
    return isValidDomain(domain);
}

function isValidBitcoinAddress(address) {
    // Simplified Bitcoin address validation
    if (address.startsWith('1') || address.startsWith('3')) {
        return /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(address);
    } else if (address.startsWith('bc1')) {
        return /^bc1[a-z0-9]{39,59}$/.test(address);
    }
    return false;
}

function isValidFilename(filename) {
    const parts = filename.split('.');
    if (parts.length < 2) return false;
    
    const name = parts.slice(0, -1).join('.');
    const ext = parts[parts.length - 1];
    
    if (name.length === 0 || ext.length < 2 || ext.length > 5) return false;
    if (!/^[a-zA-Z0-9._-]+$/.test(name)) return false;
    if (!/^[a-zA-Z]{2,5}$/.test(ext)) return false;
    
    return true;
}

function isValidCVE(cve) {
    const match = cve.match(/^CVE-(\d{4})-(\d{4,})$/);
    if (!match) return false;
    
    const year = parseInt(match[1], 10);
    const id = parseInt(match[2], 10);
    
    return year >= 1999 && year <= new Date().getFullYear() + 1 && id >= 0;
}

/**
 * Get IP range classification
 */
function getIPRange(ip) {
    const parts = ip.split('.').map(Number);
    
    for (const range of PRIVATE_IP_RANGES) {
        if (isInRange(parts, range.start, range.end)) {
            return range.name;
        }
    }
    
    return null;
}

function isInRange(ip, start, end) {
    for (let i = 0; i < 4; i++) {
        if (ip[i] < start[i] || ip[i] > end[i]) return false;
        if (ip[i] > start[i] && ip[i] < end[i]) return true;
    }
    return true;
}

/**
 * Display extraction results
 */
function displayResults(results) {
    const container = document.getElementById('results-container');
    
    const totalCount = Object.values(results).reduce((sum, items) => sum + items.length, 0);
    
    if (totalCount === 0) {
        container.innerHTML = `
            <div class="no-results">
                <div class="no-results-icon">🔍</div>
                <p>No IOCs found</p>
                <p class="no-results-hint">Try different text or check the sample data</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = '';
    
    for (const [category, items] of Object.entries(results)) {
        if (items.length === 0) continue;
        
        const card = createIOCCard(category, items);
        container.appendChild(card);
    }
}

/**
 * Create IOC card element
 */
function createIOCCard(category, items) {
    const categoryInfo = IOC_CATEGORIES[category];
    const card = document.createElement('div');
    card.className = 'ioc-card expanded';
    card.dataset.category = category;
    
    card.innerHTML = `
        <div class="ioc-card-header" tabindex="0" role="button" aria-expanded="true">
            <div class="ioc-card-title">
                <span>${categoryInfo.icon}</span>
                <span>${categoryInfo.name}</span>
                <span class="ioc-count">${items.length}</span>
            </div>
            <div class="ioc-card-actions">
                <button class="btn btn-small btn-secondary copy-category-btn" data-category="${category}">Copy</button>
                <span class="collapse-icon">▼</span>
            </div>
        </div>
        <div class="ioc-card-content">
            <div class="ioc-content-header">
                <div class="view-toggle">
                    <button class="view-btn active" data-view="list">List</button>
                    <button class="view-btn" data-view="table">Table</button>
                </div>
            </div>
            <div class="ioc-list" data-view="list">
                ${createListView(items)}
            </div>
            <div class="ioc-table" data-view="table" style="display: none;">
                ${createTableView(items, category)}
            </div>
        </div>
    `;
    
    // Add event listeners
    const header = card.querySelector('.ioc-card-header');
    header.addEventListener('click', (e) => {
        if (e.target.closest('.copy-category-btn')) return;
        toggleCard(card);
    });
    
    header.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            toggleCard(card);
        }
    });
    
    const copyBtn = card.querySelector('.copy-category-btn');
    copyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        copyCategory(category);
    });
    
    const viewButtons = card.querySelectorAll('.view-btn');
    viewButtons.forEach(btn => {
        btn.addEventListener('click', () => toggleView(card, btn.dataset.view));
    });
    
    return card;
}

/**
 * Create list view for IOC items
 */
function createListView(items) {
    return items.map(item => {
        const notesHtml = item.notes.length > 0 
            ? `<div class="ioc-item-notes">${item.notes.map(note => `<span class="ioc-note">${escapeHtml(note)}</span>`).join('')}</div>`
            : '';
        
        return `
            <div class="ioc-item ${item.notes.length > 0 ? 'has-notes' : ''}">
                <div>${escapeHtml(item.value)}</div>
                ${notesHtml}
            </div>
        `;
    }).join('');
}

/**
 * Create table view for IOC items
 */
function createTableView(items, category) {
    const algoColumn = category === 'hashes' ? '<th>Algorithm</th>' : '';
    const tableHeader = `
        <table>
            <thead>
                <tr>
                    <th>Value</th>
                    ${algoColumn}
                    <th>Notes</th>
                    <th>First Seen</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    const tableRows = items.map(item => {
        const algoCell = category === 'hashes' ? `<td>${item.algo || ''}</td>` : '';
        const notesText = item.notes.join(', ');
        const dateText = new Date(item.firstSeen).toLocaleString();
        
        return `
            <tr>
                <td>${escapeHtml(item.value)}</td>
                ${algoCell}
                <td class="notes-cell">${escapeHtml(notesText)}</td>
                <td>${dateText}</td>
            </tr>
        `;
    }).join('');
    
    return `
        <div class="ioc-table-wrapper">
            ${tableHeader}
                ${tableRows}
            </tbody>
        </table>
        </div>
    `;
}

/**
 * Toggle card expanded/collapsed state
 */
function toggleCard(card) {
    card.classList.toggle('expanded');
    card.classList.toggle('collapsed');
    
    const header = card.querySelector('.ioc-card-header');
    const isExpanded = card.classList.contains('expanded');
    header.setAttribute('aria-expanded', isExpanded);
}

/**
 * Toggle between list and table view
 */
function toggleView(card, view) {
    const viewButtons = card.querySelectorAll('.view-btn');
    const listView = card.querySelector('[data-view="list"]');
    const tableView = card.querySelector('[data-view="table"]');
    
    viewButtons.forEach(btn => btn.classList.remove('active'));
    card.querySelector(`[data-view="${view}"]`).classList.add('active');
    
    if (view === 'list') {
        listView.style.display = 'block';
        tableView.style.display = 'none';
    } else {
        listView.style.display = 'none';
        tableView.style.display = 'block';
    }
}

/**
 * Copy functions
 */
function copyCategory(category) {
    if (!currentResults || !currentResults[category]) {
        showToast('No data to copy', 'warning');
        return;
    }
    
    const items = currentResults[category];
    const text = items.map(item => item.value).join('\n');
    
    copyToClipboard(text, `${IOC_CATEGORIES[category].name} copied (${items.length} items)`);
}

function copyAll() {
    if (!currentResults) {
        showToast('No data to copy', 'warning');
        return;
    }
    
    const sections = [];
    let totalCount = 0;
    
    for (const [category, items] of Object.entries(currentResults)) {
        if (items.length === 0) continue;
        
        const categoryInfo = IOC_CATEGORIES[category];
        sections.push(`=== ${categoryInfo.name} (${items.length}) ===`);
        sections.push(items.map(item => item.value).join('\n'));
        sections.push('');
        totalCount += items.length;
    }
    
    const text = sections.join('\n');
    copyToClipboard(text, `All IOCs copied (${totalCount} items)`);
}

function copyToClipboard(text, successMessage) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showToast(successMessage, 'success');
        }).catch(() => {
            showToast('Copy failed', 'error');
        });
    } else {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showToast(successMessage, 'success');
        } catch {
            showToast('Copy failed', 'error');
        }
        document.body.removeChild(textarea);
    }
}

/**
 * Export functions
 */
function exportCSV() {
    if (!currentResults) {
        showToast('No data to export', 'warning');
        return;
    }
    
    const rows = [['Category', 'Value', 'Algorithm', 'Notes', 'First Seen']];
    
    for (const [category, items] of Object.entries(currentResults)) {
        for (const item of items) {
            rows.push([
                IOC_CATEGORIES[category].name,
                sanitizeCSVField(item.value),
                sanitizeCSVField(item.algo || ''),
                sanitizeCSVField(item.notes.join('; ')),
                sanitizeCSVField(item.firstSeen)
            ]);
        }
    }
    
    const csv = rows.map(row => 
        row.map(field => `"${field.replace(/"/g, '""')}"`).join(',')
    ).join('\n');
    
    downloadFile(csv, 'ioc-extraction.csv', 'text/csv');
    showToast('CSV exported', 'success');
}

function exportJSON() {
    if (!currentResults) {
        showToast('No data to export', 'warning');
        return;
    }
    
    const json = JSON.stringify(currentResults, null, 2);
    downloadFile(json, 'ioc-extraction.json', 'application/json');
    showToast('JSON exported', 'success');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Load stored results from localStorage
 */
function loadStoredResults() {
    try {
        const stored = localStorage.getItem('ioc_run');
        if (stored) {
            currentResults = JSON.parse(stored);
            displayResults(currentResults);
        }
    } catch (error) {
        console.warn('Failed to load stored results:', error);
    }
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    container.appendChild(toast);
    
    // Trigger animation
    requestAnimationFrame(() => {
        toast.classList.add('show');
    });
    
    // Remove after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            if (toast.parentNode) {
                container.removeChild(toast);
            }
        }, 300);
    }, 3000);
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Sanitize CSV field to prevent formula injection
 */
function sanitizeCSVField(text) {
    if (typeof text !== 'string') return String(text);
    
    // Prefix with apostrophe if starts with formula characters
    if (/^[=+\-@]/.test(text)) {
        return "'" + text;
    }
    
    return text;
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}