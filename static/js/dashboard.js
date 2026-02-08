document.addEventListener('DOMContentLoaded', function() {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    const transferForm = document.getElementById('transferForm');
    if (transferForm) {
        transferForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = {
                to_account: document.getElementById('toAccount').value,
                amount: parseFloat(document.getElementById('amount').value),
                description: document.getElementById('description').value
            };
            try {
                const response = await fetch('/transfer', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify(formData)
                });
                const data = await response.json();
                if (response.ok) {
                    showAlert('success', 'Transfer initiated successfully!');
                    if (data.fraud_score > 0.8) {
                        showAlert('warning',
                            `Transaction flagged for review (Fraud Score: ${(data.fraud_score * 100).toFixed(1)}%)`);
                    }
                    transferForm.reset();
                    setTimeout(() => {
                        window.location.reload();
                    }, 2000);
                } else {
                    showAlert('danger', data.error || 'Transfer failed');
                }
            } catch (error) {
                showAlert('danger', 'Network error. Please try again.');
            }
        });
    }
    function updateSecurityDashboard() {
        fetch('/api/security-metrics')
            .then(response => response.json())
            .then(data => {
                const threatLevel = document.querySelector('.threat-level');
                if (threatLevel) {
                    threatLevel.className = `security-level level-${data.threat_level.toLowerCase()}`;
                    threatLevel.style.width = `${data.threat_level === 'High' ? 100 : data.threat_level === 'Medium' ? 66 : 33}%`;
                }
                const systemHealth = document.getElementById('systemHealth');
                if (systemHealth) {
                    systemHealth.textContent = `${data.system_health}%`;
                    systemHealth.style.color = data.system_health > 90 ? '#28a745' :
                                              data.system_health > 75 ? '#ffc107' : '#dc3545';
                }
            })
            .catch(error => console.error('Failed to fetch security metrics:', error));
    }
    if (window.location.pathname.includes('security-dashboard')) {
        setInterval(updateSecurityDashboard, 30000);
        updateSecurityDashboard();
    }
    let timeoutWarning;
    let logoutTimer;
    function resetSessionTimers() {
        clearTimeout(timeoutWarning);
        clearTimeout(logoutTimer);
        timeoutWarning = setTimeout(() => {
            showAlert('warning',
                'Your session will expire in 5 minutes. Please save your work.',
                true);
        }, 25 * 60 * 1000);
        logoutTimer = setTimeout(() => {
            showAlert('info', 'Session expired. Redirecting to login...', true);
            setTimeout(() => {
                window.location.href = '/logout';
            }, 3000);
        }, 30 * 60 * 1000);
    }
    ['click', 'keypress', 'mousemove', 'scroll'].forEach(event => {
        document.addEventListener(event, resetSessionTimers, { passive: true });
    });
    resetSessionTimers();
    function showAlert(type, message, persistent = false) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        const container = document.querySelector('.container');
        container.insertBefore(alertDiv, container.firstChild);
        if (!persistent) {
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.classList.remove('show');
                    setTimeout(() => alertDiv.remove(), 150);
                }
            }, 5000);
        }
    }
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('input', function(e) {
            const password = e.target.value;
            const strength = checkPasswordStrength(password);
            const strengthBar = document.getElementById('passwordStrength');
            if (strengthBar) {
                strengthBar.style.width = `${strength.score * 25}%`;
                strengthBar.className = `progress-bar ${strength.color}`;
                strengthBar.textContent = strength.text;
            }
        });
    }
    function checkPasswordStrength(password) {
        let score = 0;
        let suggestions = [];
        if (password.length >= 12) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[a-z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;
        const levels = [
            { score: 0, text: 'Very Weak', color: 'bg-danger' },
            { score: 1, text: 'Weak', color: 'bg-danger' },
            { score: 2, text: 'Fair', color: 'bg-warning' },
            { score: 3, text: 'Good', color: 'bg-info' },
            { score: 4, text: 'Strong', color: 'bg-success' },
            { score: 5, text: 'Very Strong', color: 'bg-success' }
        ];
        return levels[score];
    }
    document.querySelectorAll('.copy-account').forEach(button => {
        button.addEventListener('click', function() {
            const accountNumber = this.getAttribute('data-account');
            navigator.clipboard.writeText(accountNumber).then(() => {
                showAlert('success', 'Account number copied to clipboard!');
            });
        });
    });
});
