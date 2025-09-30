// MCP Security Scanner Admin Interface JavaScript

// API utility functions
const API = {
    async get(url) {
        try {
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`GET ${url} failed:`, error);
            throw error;
        }
    },

    async post(url, data) {
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`POST ${url} failed:`, error);
            throw error;
        }
    },

    async put(url, data) {
        try {
            const response = await fetch(url, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`PUT ${url} failed:`, error);
            throw error;
        }
    },

    async delete(url) {
        try {
            const response = await fetch(url, {
                method: 'DELETE'
            });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`DELETE ${url} failed:`, error);
            throw error;
        }
    }
};

// UI utility functions
const UI = {
    showLoading(elementId) {
        const element = document.getElementById(elementId);
        if (element) {
            element.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';
        }
    },

    showError(elementId, message) {
        const element = document.getElementById(elementId);
        if (element) {
            element.innerHTML = `<div class="alert alert-danger">${message}</div>`;
        }
    },

    showSuccess(message) {
        this.showToast(message, 'success');
    },

    showToast(message, type = 'info') {
        // Create toast element
        const toast = document.createElement('div');
        toast.className = `alert alert-${type}`;
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1050;
            min-width: 300px;
            animation: slideIn 0.3s ease;
        `;
        toast.innerHTML = `
            ${message}
            <button type="button" class="close" onclick="this.parentElement.remove()" style="float: right; margin-left: 10px;">&times;</button>
        `;

        document.body.appendChild(toast);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 5000);
    },

    formatTimestamp(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleString();
    },

    formatSeverity(severity) {
        const colors = {
            'Critical': 'danger',
            'High': 'warning', 
            'Medium': 'info',
            'Low': 'success'
        };
        return `<span class="severity-badge ${severity}">${severity}</span>`;
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

// Modal management
const Modal = {
    show(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('show');
            modal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
    },

    hide(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('show');
            modal.style.display = 'none';
            document.body.style.overflow = 'auto';
        }
    },

    hideAll() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.classList.remove('show');
            modal.style.display = 'none';
        });
        document.body.style.overflow = 'auto';
    }
};

// Form validation
const Validator = {
    required(value, fieldName) {
        if (!value || value.trim() === '') {
            return `${fieldName} is required`;
        }
        return null;
    },

    pattern(value, regex, message) {
        if (value && !regex.test(value)) {
            return message;
        }
        return null;
    },

    validateForm(formId, rules) {
        const form = document.getElementById(formId);
        if (!form) return false;

        let isValid = true;
        const errors = {};

        // Clear previous errors
        form.querySelectorAll('.is-invalid').forEach(el => el.classList.remove('is-invalid'));
        form.querySelectorAll('.invalid-feedback').forEach(el => el.remove());

        // Validate each field
        Object.keys(rules).forEach(fieldName => {
            const field = form.querySelector(`[name="${fieldName}"]`);
            if (!field) return;

            const value = field.value;
            const fieldRules = rules[fieldName];

            for (let rule of fieldRules) {
                const error = rule(value);
                if (error) {
                    errors[fieldName] = error;
                    field.classList.add('is-invalid');
                    
                    const feedback = document.createElement('div');
                    feedback.className = 'invalid-feedback';
                    feedback.textContent = error;
                    field.parentNode.appendChild(feedback);
                    
                    isValid = false;
                    break;
                }
            }
        });

        return isValid;
    }
};

// Auto-refresh manager
const AutoRefresh = {
    intervals: {},

    start(key, callback, intervalMs = 30000) {
        this.stop(key);
        this.intervals[key] = setInterval(callback, intervalMs);
    },

    stop(key) {
        if (this.intervals[key]) {
            clearInterval(this.intervals[key]);
            delete this.intervals[key];
        }
    },

    stopAll() {
        Object.keys(this.intervals).forEach(key => this.stop(key));
    }
};

// Page visibility handler for auto-refresh optimization
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        AutoRefresh.stopAll();
    } else {
        // Restart auto-refresh when page becomes visible
        if (typeof restartAutoRefresh === 'function') {
            restartAutoRefresh();
        }
    }
});

// Global error handler
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    UI.showToast('An unexpected error occurred. Please refresh the page.', 'danger');
});

// Close modals when clicking outside
document.addEventListener('click', (event) => {
    if (event.target.classList.contains('modal')) {
        Modal.hideAll();
    }
});

// Keyboard navigation
document.addEventListener('keydown', (event) => {
    // Close modals with Escape key
    if (event.key === 'Escape') {
        Modal.hideAll();
    }
    
    // Refresh with F5 or Ctrl+R
    if (event.key === 'F5' || (event.ctrlKey && event.key === 'r')) {
        if (typeof refreshData === 'function') {
            event.preventDefault();
            refreshData();
        }
    }
});

// Export for global use
window.API = API;
window.UI = UI;
window.Modal = Modal;
window.Validator = Validator;
window.AutoRefresh = AutoRefresh;