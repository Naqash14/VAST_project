// VAST Vulnerability Scanner - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    const popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Password strength indicator for all password fields
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    passwordInputs.forEach(input => {
        if (input.id.includes('password') && !input.id.includes('confirm')) {
            input.addEventListener('input', function() {
                updatePasswordStrength(this.value, this.id);
            });
        }
    });

    // Confirm password match
    const confirmPasswordInputs = document.querySelectorAll('input[id*="confirm_password"]');
    confirmPasswordInputs.forEach(input => {
        input.addEventListener('input', function() {
            const passwordId = this.id.replace('confirm_', '');
            const passwordInput = document.getElementById(passwordId);
            if (passwordInput) {
                checkPasswordMatch(passwordInput.value, this.value, this.id);
            }
        });
    });

    // Auto-submit OTP when all digits are entered
    const otpInputs = document.querySelectorAll('input[name="otp"][maxlength="6"]');
    otpInputs.forEach(input => {
        input.addEventListener('input', function() {
            if (this.value.length === 6) {
                this.form.submit();
            }
        });
    });

    // Code editor functionality
    const codeTextareas = document.querySelectorAll('textarea[name="code_content"]');
    codeTextareas.forEach(textarea => {
        // Add line numbers
        addLineNumbers(textarea);
        
        // Syntax highlighting for code preview
        if (textarea.closest('.code-preview')) {
            highlightSyntax(textarea);
        }
    });

    // File upload preview
    const fileInputs = document.querySelectorAll('input[type="file"][accept*=".py,.java,.js,.cpp,.c,.php,.rb,.go,.rs"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                previewFile(file, input.dataset.previewTarget);
            }
        });
    });

    // Scan progress animation
    const scanButtons = document.querySelectorAll('button[type="submit"][name="scanner_type"]');
    scanButtons.forEach(button => {
        button.addEventListener('click', function() {
            if (!this.classList.contains('disabled')) {
                showScanProgress(this);
            }
        });
    });

    // Collapse all findings buttons
    const collapseButtons = document.querySelectorAll('[data-bs-toggle="collapse"]');
    collapseButtons.forEach(button => {
        button.addEventListener('click', function() {
            const target = document.querySelector(this.dataset.bsTarget);
            if (target) {
                const icon = this.querySelector('i');
                if (icon) {
                    if (target.classList.contains('show')) {
                        icon.className = 'fas fa-chevron-down me-1';
                    } else {
                        icon.className = 'fas fa-chevron-up me-1';
                    }
                }
            }
        });
    });

    // Auto-refresh scan results every 30 seconds on scan page
    if (window.location.pathname.includes('/scan/')) {
        setInterval(refreshScanResults, 30000);
    }

    // Initialize charts if Chart.js is available
    if (typeof Chart !== 'undefined') {
        initializeCharts();
    }
});

// Password strength calculation
function updatePasswordStrength(password, inputId) {
    let strength = 0;
    const feedback = [];
    
    // Length check
    if (password.length >= 8) strength += 1;
    else feedback.push("At least 8 characters");
    
    // Lowercase check
    if (/[a-z]/.test(password)) strength += 1;
    else feedback.push("Add lowercase letters");
    
    // Uppercase check
    if (/[A-Z]/.test(password)) strength += 1;
    else feedback.push("Add uppercase letters");
    
    // Digit check
    if (/[0-9]/.test(password)) strength += 1;
    else feedback.push("Add numbers");
    
    // Special character check
    if (/[^A-Za-z0-9]/.test(password)) strength += 1;
    else feedback.push("Add special characters");
    
    // Update UI
    const strengthBar = document.getElementById(`${inputId}-strength-bar`);
    const strengthText = document.getElementById(`${inputId}-strength-text`);
    const feedbackElement = document.getElementById(`${inputId}-feedback`);
    
    if (strengthBar && strengthText) {
        const percentage = (strength / 5) * 100;
        strengthBar.style.width = `${percentage}%`;
        
        let colorClass, text;
        if (strength <= 1) {
            colorClass = 'bg-danger';
            text = 'Weak';
        } else if (strength <= 3) {
            colorClass = 'bg-warning';
            text = 'Medium';
        } else if (strength <= 4) {
            colorClass = 'bg-info';
            text = 'Good';
        } else {
            colorClass = 'bg-success';
            text = 'Strong';
        }
        
        strengthBar.className = `progress-bar ${colorClass}`;
        strengthText.textContent = `${text} password`;
        strengthText.className = `text-${colorClass.replace('bg-', '')}`;
    }
    
    if (feedbackElement && feedback.length > 0) {
        feedbackElement.innerHTML = feedback.map(item => 
            `<small class="d-block text-danger">✗ ${item}</small>`
        ).join('');
    }
}

// Check password match
function checkPasswordMatch(password, confirmPassword, inputId) {
    const matchElement = document.getElementById(`${inputId}-match`);
    if (!matchElement) return;
    
    if (confirmPassword === '') {
        matchElement.textContent = '';
        matchElement.className = 'form-text';
        return;
    }
    
    if (password === confirmPassword) {
        matchElement.textContent = '✓ Passwords match';
        matchElement.className = 'form-text text-success';
    } else {
        matchElement.textContent = '✗ Passwords do not match';
        matchElement.className = 'form-text text-danger';
    }
}

// Add line numbers to textarea
function addLineNumbers(textarea) {
    const wrapper = document.createElement('div');
    wrapper.className = 'code-editor-wrapper';
    wrapper.style.position = 'relative';
    
    const lineNumbers = document.createElement('div');
    lineNumbers.className = 'line-numbers';
    lineNumbers.style.cssText = `
        position: absolute;
        left: 0;
        top: 0;
        bottom: 0;
        width: 40px;
        background-color: #f5f5f5;
        border-right: 1px solid #ddd;
        font-family: monospace;
        font-size: 14px;
        line-height: 1.5;
        text-align: right;
        padding: 10px 5px;
        color: #666;
        overflow: hidden;
        user-select: none;
    `;
    
    textarea.parentNode.insertBefore(wrapper, textarea);
    wrapper.appendChild(lineNumbers);
    wrapper.appendChild(textarea);
    
    textarea.style.paddingLeft = '50px';
    textarea.style.fontFamily = 'monospace';
    textarea.style.lineHeight = '1.5';
    
    function updateLineNumbers() {
        const lines = textarea.value.split('\n').length;
        lineNumbers.innerHTML = Array.from({length: lines}, (_, i) => 
            `<div>${i + 1}</div>`
        ).join('');
    }
    
    textarea.addEventListener('input', updateLineNumbers);
    textarea.addEventListener('scroll', function() {
        lineNumbers.scrollTop = this.scrollTop;
    });
    
    updateLineNumbers();
}

// Show scan progress animation
function showScanProgress(button) {
    const originalText = button.innerHTML;
    button.innerHTML = `
        <span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
        Scanning...
    `;
    button.disabled = true;
    
    // Re-enable after 5 seconds (in case of error)
    setTimeout(() => {
        button.innerHTML = originalText;
        button.disabled = false;
    }, 5000);
}

// Refresh scan results
function refreshScanResults() {
    const scanResultsContainer = document.querySelector('.scan-results-container');
    if (scanResultsContainer) {
        fetch(window.location.href)
            .then(response => response.text())
            .then(html => {
                const parser = new DOMParser();
                const newDoc = parser.parseFromString(html, 'text/html');
                const newResults = newDoc.querySelector('.scan-results-container');
                if (newResults) {
                    scanResultsContainer.innerHTML = newResults.innerHTML;
                }
            })
            .catch(error => console.error('Error refreshing results:', error));
    }
}

// Initialize charts
function initializeCharts() {
    const ctx = document.getElementById('scanStatsChart');
    if (ctx) {
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [12, 19, 3, 5, 2],
                    backgroundColor: [
                        '#dc3545',
                        '#ffc107',
                        '#17a2b8',
                        '#6c757d',
                        '#adb5bd'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                    }
                }
            }
        });
    }
}

// Preview uploaded file
function previewFile(file, targetId) {
    if (!file.type.startsWith('text/')) {
        return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
        const target = document.getElementById(targetId);
        if (target) {
            target.value = e.target.result;
            if (target.hasLineNumbers) {
                updateLineNumbers(target);
            }
        }
    };
    reader.readAsText(file);
}

// Basic syntax highlighting
function highlightSyntax(textarea) {
    const code = textarea.value;
    const highlighted = code
        .replace(/(".*?"|'.*?')/g, '<span class="text-primary">$1</span>')
        .replace(/\b(function|def|class|import|from|if|else|for|while|return)\b/g, 
                '<span class="text-danger">$1</span>')
        .replace(/\b(true|false|null|undefined)\b/g, 
                '<span class="text-warning">$1</span>')
        .replace(/\b(\d+)\b/g, 
                '<span class="text-info">$1</span>');
    
    const preview = document.createElement('div');
    preview.className = 'code-highlight-preview';
    preview.style.cssText = textarea.style.cssText;
    preview.innerHTML = highlighted;
    
    textarea.style.display = 'none';
    textarea.parentNode.appendChild(preview);
}
