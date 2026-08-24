// Global State
let activePage = 'overview';

// Initialize App
document.addEventListener('DOMContentLoaded', () => {
    setupNavigation();
    setupSimulatedIPPanel();
    setupPasswordStrengthMeters();
    
    // Initial data fetch
    fetchOverviewStats();
    
    // Setup Lucide icons replacement
    if (window.lucide) {
        window.lucide.createIcons();
    }
});

// ----------------- NAVIGATION -----------------
function setupNavigation() {
    const trigger = document.getElementById('nav-dropdown-trigger');
    const menu = document.getElementById('nav-dropdown-list');
    const items = menu.querySelectorAll('.nav-dropdown-item');
    const label = document.getElementById('current-page-label');

    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        const expanded = trigger.getAttribute('aria-expanded') === 'true';
        trigger.setAttribute('aria-expanded', !expanded);
        menu.classList.toggle('show');
    });

    document.addEventListener('click', () => {
        trigger.setAttribute('aria-expanded', 'false');
        menu.classList.remove('show');
    });

    items.forEach(item => {
        item.addEventListener('click', () => {
            const pageId = item.getAttribute('data-page');
            
            // Update Active class in menu
            items.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            
            // Close dropdown and update button label
            label.textContent = item.textContent;
            trigger.setAttribute('aria-expanded', 'false');
            menu.classList.remove('show');
            
            // Switch views
            navigateToPage(pageId);
        });
    });
}

function navigateToPage(pageId) {
    activePage = pageId;
    
    // Update dropdown selection labels in case navigating from quick buttons
    const items = document.querySelectorAll('.nav-dropdown-item');
    const label = document.getElementById('current-page-label');
    items.forEach(item => {
        if (item.getAttribute('data-page') === pageId) {
            items.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            label.textContent = item.textContent;
        }
    });

    // Hide all views and show active one
    document.querySelectorAll('.page-view').forEach(view => {
        view.classList.remove('active');
    });
    const activeView = document.getElementById(`page-${pageId}`);
    if (activeView) {
        activeView.classList.add('active');
    }

    // Refresh context data
    if (pageId === 'overview') {
        fetchOverviewStats();
    } else if (pageId === 'ip-manager') {
        fetchIPPolicyData();
    } else if (pageId === 'log-analyzer') {
        fetchLogAnalyzerData();
    } else if (pageId === 'create-account') {
        updateSimulatedIPDetails();
    }
    
    // Reset forms when switching pages
    resetForms();
}

function resetForms() {
    const alerts = document.querySelectorAll('.form-status-alert');
    alerts.forEach(a => {
        a.classList.add('hidden');
        a.textContent = '';
    });
    
    const warnings = document.querySelectorAll('.attempts-warning');
    warnings.forEach(w => w.classList.add('hidden'));

    // Reset password strength bars
    updateStrengthBar('reg-strength-fill', 'reg-strength-text', '');
    updateStrengthBar('reset-strength-fill', 'reset-strength-text', '');
}

// ----------------- SIMULATED IP PANEL -----------------
function setupSimulatedIPPanel() {
    const select = document.getElementById('simulated-ip-select');
    const input = document.getElementById('custom-ip-input');
    
    select.addEventListener('change', () => {
        if (select.value === 'custom') {
            input.classList.remove('hidden');
            input.focus();
        } else {
            input.classList.add('hidden');
            updateSimulatedIPDetails();
        }
        
        // Refresh active page if needed
        if (activePage === 'overview') {
            fetchOverviewStats();
        } else if (activePage === 'log-analyzer') {
            fetchLogAnalyzerData();
        }
    });

    input.addEventListener('input', debounce(() => {
        updateSimulatedIPDetails();
    }, 500));
}

function getSelectedIP() {
    const select = document.getElementById('simulated-ip-select');
    const input = document.getElementById('custom-ip-input');
    
    if (select.value === 'custom') {
        return input.value.trim();
    }
    return select.value;
}

// Helper to make API calls with optional Simulated IP header
function getFetchHeaders() {
    const headers = {
        'Content-Type': 'application/json'
    };
    const simulatedIP = getSelectedIP();
    if (simulatedIP) {
        headers['X-Simulated-IP'] = simulatedIP;
    }
    return headers;
}

// ----------------- PASSWORD STRENGTH METERS -----------------
function setupPasswordStrengthMeters() {
    const regPass = document.getElementById('reg-password');
    const resetPass = document.getElementById('reset-password');
    
    if (regPass) {
        regPass.addEventListener('input', () => {
            const score = checkPasswordCriteria(regPass.value);
            updateStrengthBar('reg-strength-fill', 'reg-strength-text', regPass.value, score);
        });
    }
    
    if (resetPass) {
        resetPass.addEventListener('input', () => {
            const score = checkPasswordCriteria(resetPass.value);
            updateStrengthBar('reset-strength-fill', 'reset-strength-text', resetPass.value, score);
        });
    }
}

function checkPasswordCriteria(password) {
    if (!password) return { score: 0, criteria: {} };
    
    const criteria = {
        length: password.length >= 8,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        digit: /[0-9]/.test(password),
        special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    };
    
    const score = Object.values(criteria).filter(Boolean).length;
    return { score, criteria };
}

function updateStrengthBar(fillId, textId, val, result = { score: 0, criteria: {} }) {
    const fill = document.getElementById(fillId);
    const label = document.getElementById(textId);
    
    if (!val) {
        fill.style.width = '0%';
        fill.style.backgroundColor = 'transparent';
        label.textContent = 'Password Strength: Empty';
        return;
    }
    
    const percentage = (result.score / 5) * 100;
    fill.style.width = `${percentage}%`;
    
    let strength = '';
    let color = '';
    
    if (result.score <= 2) {
        strength = 'Weak (Non-compliant)';
        color = 'var(--accent-red)';
    } else if (result.score <= 4) {
        strength = 'Medium (Borderline)';
        color = 'var(--accent-amber)';
    } else {
        strength = 'Strong (Compliant)';
        color = 'var(--accent-teal)';
    }
    
    fill.style.backgroundColor = color;
    label.textContent = `Password Strength: ${strength}`;
}

// ----------------- PAGE 1: OVERVIEW METRICS -----------------
async function fetchOverviewStats() {
    try {
        const response = await fetch('/api/stats', {
            headers: getFetchHeaders()
        });
        const data = await response.json();
        
        // Update Stat Cards
        document.getElementById('overview-accounts-count').textContent = data.accounts_count;
        document.getElementById('overview-whitelist-count').textContent = data.whitelist_count;
        document.getElementById('overview-blacklist-count').textContent = data.blacklist_count;
        document.getElementById('overview-login-events-count').textContent = data.login_events_count;
        
        // Update Threat Summary
        document.getElementById('overview-success-logins').textContent = data.success_logins;
        document.getElementById('overview-failed-logins').textContent = data.failed_logins;
        
        // Update Suspicious IPs Callout
        const listDiv = document.getElementById('overview-suspicious-list');
        listDiv.innerHTML = '';
        
        if (data.suspicious_ips && data.suspicious_ips.length > 0) {
            data.suspicious_ips.forEach(ip => {
                const item = document.createElement('div');
                item.className = 'suspicious-item';
                item.innerHTML = `
                    <span class="suspicious-ip">${ip.ip_address}</span>
                    <span class="suspicious-count">${ip.fail_count} Failed Attempts</span>
                `;
                listDiv.appendChild(item);
            });
        } else {
            listDiv.innerHTML = '<em class="empty-state">No suspicious activity detected</em>';
        }
    } catch (err) {
        console.error('Error fetching statistics:', err);
    }
}

// ----------------- PAGE 2: REGISTER -----------------
async function updateSimulatedIPDetails() {
    const ipInput = document.getElementById('reg-ip-address');
    if (ipInput) {
        ipInput.value = getSelectedIP();
        auditRegisterIP();
    }
}

async function auditRegisterIP() {
    const ipInput = document.getElementById('reg-ip-address');
    const badge = document.getElementById('reg-ip-classification');
    if (!ipInput || !badge) return;
    
    const ip = ipInput.value.trim();
    
    if (!ip) {
        badge.textContent = 'Unknown';
        badge.className = 'badge badge-invalid';
        return;
    }
    
    badge.className = 'badge';
    badge.textContent = 'Verifying...';
    
    try {
        const response = await fetch('/api/ip-manager/lookup', {
            method: 'POST',
            headers: getFetchHeaders(),
            body: JSON.stringify({ ip_address: ip })
        });
        const data = await response.json();
        
        if (data.status === 'success') {
            const classification = data.classification;
            badge.textContent = classification;
            
            // Match badge styles
            let badgeClass = 'badge-invalid';
            if (classification === 'Public') badgeClass = 'badge-public';
            else if (classification === 'Private') badgeClass = 'badge-private';
            else if (classification === 'Loopback') badgeClass = 'badge-loopback';
            else if (classification === 'Military') badgeClass = 'badge-military';
            else if (classification === 'Reserved/R&D') badgeClass = 'badge-reserved';
            
            badge.className = `badge ${badgeClass}`;
        } else {
            badge.textContent = 'Invalid Format';
            badge.className = 'badge badge-invalid';
        }
    } catch (err) {
        badge.textContent = 'Offline';
        badge.className = 'badge badge-invalid';
    }
}

async function handleRegister(event) {
    event.preventDefault();
    const usernameInput = document.getElementById('reg-username');
    const passwordInput = document.getElementById('reg-password');
    const ipInput = document.getElementById('reg-ip-address');
    const statusAlert = document.getElementById('reg-status-alert');
    
    statusAlert.classList.add('hidden');
    statusAlert.className = 'form-status-alert';
    
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: getFetchHeaders(),
            body: JSON.stringify({
                username: usernameInput.value,
                password: passwordInput.value,
                ip_address: ipInput.value.trim()
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            statusAlert.textContent = data.message;
            statusAlert.classList.add('success');
            statusAlert.classList.remove('hidden');
            usernameInput.value = '';
            passwordInput.value = '';
            ipInput.value = getSelectedIP();
            auditRegisterIP();
            updateStrengthBar('reg-strength-fill', 'reg-strength-text', '');
        } else {
            statusAlert.textContent = data.message || 'Error occurred.';
            statusAlert.classList.add('error');
            statusAlert.classList.remove('hidden');
        }
    } catch (err) {
        statusAlert.textContent = 'Server connection error.';
        statusAlert.classList.add('error');
        statusAlert.classList.remove('hidden');
    }
}

// ----------------- PAGE 3: LOGIN -----------------
async function handleLogin(event) {
    event.preventDefault();
    const usernameInput = document.getElementById('login-username');
    const passwordInput = document.getElementById('login-password');
    const statusAlert = document.getElementById('login-status-alert');
    const attemptsWarning = document.getElementById('login-attempts-warning');
    const attemptsText = document.getElementById('login-attempts-text');
    
    statusAlert.classList.add('hidden');
    statusAlert.className = 'form-status-alert';
    attemptsWarning.classList.add('hidden');
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: getFetchHeaders(),
            body: JSON.stringify({
                username: usernameInput.value,
                password: passwordInput.value
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            statusAlert.textContent = data.message;
            statusAlert.classList.add('success');
            statusAlert.classList.remove('hidden');
            usernameInput.value = '';
            passwordInput.value = '';
        } else {
            statusAlert.textContent = data.message || 'Invalid Credentials.';
            statusAlert.classList.add('error');
            statusAlert.classList.remove('hidden');
            
            // Handle lockout and failed login attempts display
            if (data.remaining_attempts !== undefined) {
                attemptsWarning.classList.remove('hidden');
                if (data.remaining_attempts === 0) {
                    attemptsText.textContent = 'Account Locked due to security policy.';
                } else {
                    attemptsText.textContent = `Remaining attempts: ${data.remaining_attempts}`;
                }
            }
        }
    } catch (err) {
        statusAlert.textContent = 'Server connection error.';
        statusAlert.classList.add('error');
        statusAlert.classList.remove('hidden');
    }
}

// ----------------- PAGE 4: RESET PASSWORD -----------------
async function handleResetPassword(event) {
    event.preventDefault();
    const usernameInput = document.getElementById('reset-username');
    const passwordInput = document.getElementById('reset-password');
    const confirmInput = document.getElementById('reset-confirm-password');
    const statusAlert = document.getElementById('reset-status-alert');
    
    statusAlert.classList.add('hidden');
    statusAlert.className = 'form-status-alert';
    
    if (passwordInput.value !== confirmInput.value) {
        statusAlert.textContent = 'Passwords do not match.';
        statusAlert.classList.add('error');
        statusAlert.classList.remove('hidden');
        return;
    }
    
    try {
        const response = await fetch('/api/reset-password', {
            method: 'POST',
            headers: getFetchHeaders(),
            body: JSON.stringify({
                username: usernameInput.value,
                new_password: passwordInput.value,
                confirm_password: confirmInput.value
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            statusAlert.textContent = data.message;
            statusAlert.classList.add('success');
            statusAlert.classList.remove('hidden');
            usernameInput.value = '';
            passwordInput.value = '';
            confirmInput.value = '';
            updateStrengthBar('reset-strength-fill', 'reset-strength-text', '');
        } else {
            statusAlert.textContent = data.message || 'Error occurred.';
            statusAlert.classList.add('error');
            statusAlert.classList.remove('hidden');
        }
    } catch (err) {
        statusAlert.textContent = 'Server connection error.';
        statusAlert.classList.add('error');
        statusAlert.classList.remove('hidden');
    }
}

// ----------------- PAGE 5: IP MANAGER -----------------
async function fetchIPPolicyData() {
    try {
        const response = await fetch('/api/ip-manager', {
            headers: getFetchHeaders()
        });
        const data = await response.json();
        
        renderIPTable('whitelist-table-body', data.whitelist, 'whitelist');
        renderIPTable('blacklist-table-body', data.blacklist, 'blacklist');
        
        if (window.lucide) {
            window.lucide.createIcons();
        }
    } catch (err) {
        console.error('Error fetching IP manager data:', err);
    }
}

function renderIPTable(bodyId, ipList, listType) {
    const tbody = document.getElementById(bodyId);
    tbody.innerHTML = '';
    
    if (ipList && ipList.length > 0) {
        ipList.forEach(item => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="font-mono">${item.ip_address}</td>
                <td>${item.created_at}</td>
                <td class="text-right">
                    <button class="action-btn-remove" onclick="removeIP('${item.ip_address}', '${listType}')" title="Remove Rule">
                        <i data-lucide="trash-2"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } else {
        tbody.innerHTML = `<tr><td colspan="3" class="text-center italic text-muted">No ${listType}ed IPs registered.</td></tr>`;
    }
}

async function lookupIP() {
    const input = document.getElementById('lookup-ip-input');
    const resultBox = document.getElementById('lookup-result-box');
    const resIp = document.getElementById('lookup-res-ip');
    const resClass = document.getElementById('lookup-res-class');
    const resStatus = document.getElementById('lookup-res-status');
    
    const ip = input.value.trim();
    if (!ip) return;
    
    try {
        const response = await fetch('/api/ip-manager/lookup', {
            method: 'POST',
            headers: getFetchHeaders(),
            body: JSON.stringify({ ip_address: ip })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            resultBox.classList.remove('hidden');
            resIp.textContent = data.ip_address;
            
            // Set classification
            resClass.textContent = data.classification;
            let classBadge = 'badge-invalid';
            if (data.classification === 'Public') classBadge = 'badge-public';
            else if (data.classification === 'Private') classBadge = 'badge-private';
            else if (data.classification === 'Loopback') classBadge = 'badge-loopback';
            else if (data.classification === 'Military') classBadge = 'badge-military';
            else if (data.classification === 'Reserved/R&D') classBadge = 'badge-reserved';
            resClass.className = `result-value badge ${classBadge}`;
            
            // Set status
            resStatus.textContent = data.list_status;
            let statusBadge = 'badge-invalid';
            if (data.list_status === 'Whitelisted') statusBadge = 'badge-public';
            else if (data.list_status === 'Blacklisted') statusBadge = 'badge-reserved';
            resStatus.className = `result-value badge ${statusBadge}`;
        } else {
            alert(data.message || 'Lookup failed.');
        }
    } catch (err) {
        console.error('Error during IP lookup:', err);
    }
}

async function addIPFromLookup(listType) {
    const resIp = document.getElementById('lookup-res-ip').textContent;
    if (!resIp || resIp === '--') return;
    
    await addIPRule(resIp, listType);
    document.getElementById('lookup-result-box').classList.add('hidden');
    document.getElementById('lookup-ip-input').value = '';
}

async function manualAddIP(listType) {
    const input = document.getElementById('add-policy-ip');
    const alertBox = document.getElementById('policy-status-alert');
    const ip = input.value.trim();
    
    alertBox.classList.add('hidden');
    alertBox.className = 'form-status-alert';
    
    if (!ip) return;
    
    const success = await addIPRule(ip, listType);
    
    if (success) {
        alertBox.textContent = `IP successfully added to ${listType}.`;
        alertBox.classList.add('success');
        alertBox.classList.remove('hidden');
        input.value = '';
    } else {
        alertBox.textContent = `Failed to add IP to ${listType}. Please check format.`;
        alertBox.classList.add('error');
        alertBox.classList.remove('hidden');
    }
}

async function addIPRule(ipAddress, listType) {
    try {
        const response = await fetch('/api/ip-manager/add', {
            method: 'POST',
            headers: getFetchHeaders(),
            body: JSON.stringify({
                ip_address: ipAddress,
                list_type: listType
            })
        });
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            fetchIPPolicyData();
            return true;
        }
    } catch (err) {
        console.error('Error adding IP rule:', err);
    }
    return false;
}

async function removeIP(ipAddress, listType) {
    try {
        const response = await fetch('/api/ip-manager/remove', {
            method: 'POST',
            headers: getFetchHeaders(),
            body: JSON.stringify({
                ip_address: ipAddress,
                list_type: listType
            })
        });
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            fetchIPPolicyData();
        }
    } catch (err) {
        console.error('Error removing IP rule:', err);
    }
}

// ----------------- PAGE 6: PASSWORD CHECKER -----------------
function auditPassword() {
    const input = document.getElementById('check-password-input');
    const fill = document.getElementById('audit-strength-fill');
    const label = document.getElementById('audit-strength-text');
    
    const val = input.value;
    const { score, criteria } = checkPasswordCriteria(val);
    
    // Update individual checkboxes
    updateChecklistItem('req-len', criteria.length);
    updateChecklistItem('req-upper', criteria.upper);
    updateChecklistItem('req-lower', criteria.lower);
    updateChecklistItem('req-digit', criteria.digit);
    updateChecklistItem('req-special', criteria.special);
    
    // Update general strength bar
    updateStrengthBar('audit-strength-fill', 'audit-strength-text', val, { score, criteria });
}

function updateChecklistItem(id, isValid) {
    const item = document.getElementById(id);
    const icon = item.querySelector('i');
    
    if (isValid) {
        item.className = 'checklist-item valid';
        icon.setAttribute('data-lucide', 'check-square');
    } else {
        item.className = 'checklist-item invalid';
        icon.setAttribute('data-lucide', 'x-square');
    }
    
    if (window.lucide) {
        window.lucide.createIcons();
    }
}

// ----------------- PAGE 7: LOG ANALYZER -----------------
async function fetchLogAnalyzerData() {
    try {
        // Fetch stats first
        const statsResponse = await fetch('/api/stats', {
            headers: getFetchHeaders()
        });
        const statsData = await statsResponse.json();
        
        document.getElementById('logs-success-logins').textContent = statsData.success_logins;
        document.getElementById('logs-failed-logins').textContent = statsData.failed_logins;
        document.getElementById('logs-flagged-ips').textContent = statsData.suspicious_ips ? statsData.suspicious_ips.length : 0;
        
        // Render suspicious list
        const suspList = document.getElementById('logs-suspicious-list');
        suspList.innerHTML = '';
        if (statsData.suspicious_ips && statsData.suspicious_ips.length > 0) {
            statsData.suspicious_ips.forEach(ip => {
                const div = document.createElement('div');
                div.className = 'suspicious-item';
                div.innerHTML = `
                    <span class="suspicious-ip">${ip.ip_address}</span>
                    <span class="suspicious-count">${ip.fail_count} Fails</span>
                `;
                suspList.appendChild(div);
            });
        } else {
            suspList.innerHTML = '<em class="empty-state">No suspicious activity detected.</em>';
        }
        
        // Fetch logs
        const logsResponse = await fetch('/api/logs', {
            headers: getFetchHeaders()
        });
        const logsData = await logsResponse.json();
        
        const tbody = document.getElementById('access-log-table-body');
        tbody.innerHTML = '';
        
        if (logsData.logs && logsData.logs.length > 0) {
            logsData.logs.forEach(log => {
                const tr = document.createElement('tr');
                
                // Format event badge
                let eventBadge = '';
                if (log.event_type === 'success') {
                    eventBadge = '<span class="event-badge event-success">SUCCESS</span>';
                } else if (log.event_type === 'failed') {
                    eventBadge = '<span class="event-badge event-failed">FAILED</span>';
                } else if (log.event_type === 'signup_blocked') {
                    eventBadge = '<span class="event-badge event-blocked">SIGNUP BLOCKED</span>';
                } else {
                    eventBadge = `<span class="event-badge">${log.event_type.toUpperCase()}</span>`;
                }
                
                // IP Class Badge format
                let classBadge = 'badge-invalid';
                if (log.ip_classification) {
                    const c = log.ip_classification;
                    if (c.startsWith('Public')) classBadge = 'badge-public';
                    else if (c.startsWith('Private')) classBadge = 'badge-private';
                    else if (c.startsWith('Loopback')) classBadge = 'badge-loopback';
                    else if (c.startsWith('Military')) classBadge = 'badge-military';
                    else if (c.startsWith('Reserved/R&D')) classBadge = 'badge-reserved';
                    else if (c.startsWith('Blacklisted')) classBadge = 'badge-reserved';
                }
                
                tr.innerHTML = `
                    <td>${log.timestamp}</td>
                    <td>${log.username || '-'}</td>
                    <td class="font-mono">${log.ip_address}</td>
                    <td>${eventBadge}</td>
                    <td><span class="badge ${classBadge}">${log.ip_classification || 'Unknown'}</span></td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center italic text-muted">No log activity registered.</td></tr>';
        }
        
    } catch (err) {
        console.error('Error fetching log analyzer data:', err);
    }
}

// ----------------- UTILS -----------------
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
