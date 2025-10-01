// LLM Dashboard JavaScript functionality
class LLMDashboard {
    constructor() {
        this.autoRefresh = true;
        this.refreshInterval = 30000; // 30 seconds
        this.charts = {};
        this.init();
    }

    init() {
        this.setupAutoRefresh();
        this.setupEventListeners();
        this.loadCharts();
        this.updateTimestamps();
    }

    setupAutoRefresh() {
        if (this.autoRefresh) {
            setInterval(() => {
                this.refreshDashboard();
            }, this.refreshInterval);
        }
    }

    setupEventListeners() {
        // Manual refresh button
        const refreshBtn = document.querySelector('.auto-refresh');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.refreshDashboard();
            });
        }

        // Toggle auto-refresh
        document.addEventListener('keydown', (e) => {
            if (e.key === 'r' && e.ctrlKey) {
                e.preventDefault();
                this.refreshDashboard();
            }
            if (e.key === 'p' && e.ctrlKey) {
                e.preventDefault();
                this.toggleAutoRefresh();
            }
        });

        // Card interactions
        this.setupCardInteractions();
    }

    setupCardInteractions() {
        document.querySelectorAll('.card').forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-5px)';
                this.style.boxShadow = '0 8px 25px rgba(0,0,0,0.15)';
            });
            
            card.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0)';
                this.style.boxShadow = '0 2px 10px rgba(0,0,0,0.1)';
            });
        });

        // Alert interactions
        document.querySelectorAll('.alert').forEach(alert => {
            alert.addEventListener('click', function() {
                this.style.transform = 'scale(1.02)';
                setTimeout(() => {
                    this.style.transform = 'scale(1)';
                }, 200);
            });
        });
    }

    refreshDashboard() {
        // Show loading indicator
        this.showLoadingIndicator();

        // Fetch fresh data
        Promise.all([
            this.fetchDashboardData(),
            this.fetchTokenUsage(),
            this.fetchRequestStats(),
            this.fetchThreats()
        ]).then(() => {
            this.hideLoadingIndicator();
            this.updateTimestamps();
        }).catch(error => {
            console.error('Failed to refresh dashboard:', error);
            this.hideLoadingIndicator();
            this.showError('Failed to refresh dashboard data');
        });
    }

    async fetchDashboardData() {
        try {
            const response = await fetch('/api/llm/dashboard');
            const data = await response.json();
            this.updateDashboardMetrics(data);
            return data;
        } catch (error) {
            console.error('Error fetching dashboard data:', error);
            throw error;
        }
    }

    async fetchTokenUsage() {
        try {
            const response = await fetch('/api/llm/tokens');
            const data = await response.json();
            this.updateTokenCharts(data);
            return data;
        } catch (error) {
            console.error('Error fetching token usage:', error);
            throw error;
        }
    }

    async fetchRequestStats() {
        try {
            const response = await fetch('/api/llm/stats');
            const data = await response.json();
            this.updateRequestCharts(data);
            return data;
        } catch (error) {
            console.error('Error fetching request stats:', error);
            throw error;
        }
    }

    async fetchThreats() {
        try {
            const response = await fetch('/api/llm/threats');
            const data = await response.json();
            this.updateThreatDisplay(data);
            return data;
        } catch (error) {
            console.error('Error fetching threats:', error);
            throw error;
        }
    }

    updateDashboardMetrics(data) {
        // Update main metrics
        const totalRequests = document.querySelector('[data-metric="total-requests"]');
        if (totalRequests) {
            this.animateNumber(totalRequests, data.request_stats.total_requests);
        }

        const blockedRequests = document.querySelector('[data-metric="blocked-requests"]');
        if (blockedRequests) {
            this.animateNumber(blockedRequests, data.request_stats.blocked_requests);
        }

        const successRate = document.querySelector('[data-metric="success-rate"]');
        if (successRate) {
            this.animateNumber(successRate, data.request_stats.success_rate, '%');
        }

        const totalTokens = document.querySelector('[data-metric="total-tokens"]');
        if (totalTokens) {
            this.animateNumber(totalTokens, data.token_usage.total_tokens);
        }
    }

    updateTokenCharts(data) {
        // Create or update token usage charts
        this.createTokensByModelChart(data.tokens_by_model);
        this.createTokensByHourChart(data.tokens_by_hour);
    }

    updateRequestCharts(data) {
        // Create or update request statistics charts
        this.createRequestsOverTimeChart(data.hourly_stats);
        this.createThreatsByCategoryChart(data.threats_by_category);
    }

    updateThreatDisplay(threats) {
        const threatContainer = document.querySelector('.threat-list');
        if (!threatContainer) return;

        threatContainer.innerHTML = '';
        
        if (threats.length === 0) {
            threatContainer.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">🛡️</div>
                    <p>No threats detected</p>
                </div>
            `;
            return;
        }

        threats.forEach(threat => {
            const threatElement = document.createElement('div');
            threatElement.className = 'threat-item';
            threatElement.innerHTML = `
                <div class="threat-header">
                    <span class="threat-name">${threat.category}</span>
                    <span class="threat-count">${threat.count}</span>
                </div>
                <p class="alert-description">${threat.description}</p>
                <p class="alert-time">Last seen: ${new Date(threat.last_seen).toLocaleTimeString()}</p>
            `;
            threatContainer.appendChild(threatElement);
        });
    }

    createTokensByModelChart(data) {
        // Simple bar chart for tokens by model
        const container = document.querySelector('#tokens-by-model-chart');
        if (!container) return;

        const models = Object.keys(data);
        const values = Object.values(data);
        const maxValue = Math.max(...values);

        container.innerHTML = '';
        
        models.forEach((model, index) => {
            const percentage = (values[index] / maxValue) * 100;
            const bar = document.createElement('div');
            bar.className = 'chart-bar';
            bar.innerHTML = `
                <div class="chart-label">${model}</div>
                <div class="chart-progress">
                    <div class="chart-fill" style="width: ${percentage}%"></div>
                </div>
                <div class="chart-value">${this.formatNumber(values[index])}</div>
            `;
            container.appendChild(bar);
        });
    }

    createTokensByHourChart(data) {
        // Simple line chart for tokens by hour
        const container = document.querySelector('#tokens-by-hour-chart');
        if (!container) return;

        // Implementation would depend on preferred charting library
        // For now, just show the data in a simple format
        const hours = Object.keys(data).sort();
        const values = hours.map(hour => data[hour]);

        container.innerHTML = `
            <div class="simple-chart">
                ${hours.map((hour, index) => `
                    <div class="chart-point" style="height: ${(values[index] / Math.max(...values)) * 100}%">
                        <div class="chart-tooltip">${hour}: ${this.formatNumber(values[index])}</div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    createRequestsOverTimeChart(data) {
        // Implementation for requests over time chart
        console.log('Requests over time data:', data);
    }

    createThreatsByCategoryChart(data) {
        // Implementation for threats by category chart
        console.log('Threats by category data:', data);
    }

    animateNumber(element, targetValue, suffix = '') {
        const startValue = parseInt(element.textContent.replace(/[^\d]/g, '')) || 0;
        const duration = 1000; // 1 second
        const startTime = performance.now();

        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function (ease-out)
            const easeOut = 1 - Math.pow(1 - progress, 3);
            
            const currentValue = Math.round(startValue + (targetValue - startValue) * easeOut);
            element.textContent = this.formatNumber(currentValue) + suffix;

            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };

        requestAnimationFrame(animate);
    }

    formatNumber(num) {
        if (num >= 1000000) {
            return (num / 1000000).toFixed(1) + 'M';
        } else if (num >= 1000) {
            return (num / 1000).toFixed(1) + 'K';
        }
        return num.toLocaleString();
    }

    showLoadingIndicator() {
        const indicator = document.createElement('div');
        indicator.id = 'loading-indicator';
        indicator.className = 'loading-indicator';
        indicator.innerHTML = `
            <div class="loading-spinner"></div>
            <span>Refreshing...</span>
        `;
        document.body.appendChild(indicator);
    }

    hideLoadingIndicator() {
        const indicator = document.querySelector('#loading-indicator');
        if (indicator) {
            indicator.remove();
        }
    }

    showError(message) {
        const error = document.createElement('div');
        error.className = 'error-toast';
        error.textContent = message;
        document.body.appendChild(error);

        setTimeout(() => {
            error.remove();
        }, 5000);
    }

    toggleAutoRefresh() {
        this.autoRefresh = !this.autoRefresh;
        const indicator = document.querySelector('.auto-refresh');
        if (indicator) {
            indicator.style.opacity = this.autoRefresh ? '1' : '0.5';
            indicator.title = this.autoRefresh ? 'Auto-refresh enabled' : 'Auto-refresh disabled';
        }
    }

    updateTimestamps() {
        document.querySelectorAll('[data-timestamp]').forEach(element => {
            const timestamp = element.getAttribute('data-timestamp');
            const date = new Date(timestamp);
            element.textContent = date.toLocaleTimeString();
        });
    }

    loadCharts() {
        // Initialize any chart libraries here
        // For now, we'll use simple CSS-based charts
        this.setupSimpleCharts();
    }

    setupSimpleCharts() {
        // Add CSS for simple charts
        const style = document.createElement('style');
        style.textContent = `
            .chart-bar {
                margin: 10px 0;
                padding: 8px;
                background: rgba(52, 73, 94, 0.05);
                border-radius: 6px;
            }
            
            .chart-label {
                font-weight: 500;
                margin-bottom: 4px;
                color: var(--primary-color);
            }
            
            .chart-progress {
                background: var(--background-color);
                height: 20px;
                border-radius: 10px;
                overflow: hidden;
                position: relative;
            }
            
            .chart-fill {
                height: 100%;
                background: linear-gradient(90deg, var(--accent-color), var(--info-color));
                border-radius: 10px;
                transition: width 0.8s ease;
            }
            
            .chart-value {
                text-align: right;
                font-weight: bold;
                color: var(--primary-color);
                margin-top: 4px;
            }
            
            .simple-chart {
                display: flex;
                align-items: end;
                height: 100px;
                gap: 4px;
                padding: 10px;
                background: rgba(52, 73, 94, 0.05);
                border-radius: 6px;
            }
            
            .chart-point {
                flex: 1;
                background: linear-gradient(to top, var(--accent-color), var(--info-color));
                border-radius: 2px 2px 0 0;
                position: relative;
                min-height: 5px;
                transition: all 0.3s ease;
            }
            
            .chart-point:hover {
                background: var(--primary-color);
            }
            
            .chart-tooltip {
                position: absolute;
                bottom: 100%;
                left: 50%;
                transform: translateX(-50%);
                background: var(--primary-color);
                color: white;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 0.8rem;
                opacity: 0;
                transition: opacity 0.3s ease;
                pointer-events: none;
                white-space: nowrap;
            }
            
            .chart-point:hover .chart-tooltip {
                opacity: 1;
            }
            
            .loading-indicator {
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: var(--shadow);
                display: flex;
                align-items: center;
                gap: 15px;
                z-index: 1000;
            }
            
            .loading-spinner {
                width: 24px;
                height: 24px;
                border: 3px solid var(--background-color);
                border-top: 3px solid var(--accent-color);
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }
            
            @keyframes spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }
            
            .error-toast {
                position: fixed;
                top: 20px;
                right: 20px;
                background: var(--danger-color);
                color: white;
                padding: 15px 20px;
                border-radius: 6px;
                box-shadow: var(--shadow);
                z-index: 1000;
                animation: slideIn 0.3s ease;
            }
            
            @keyframes slideIn {
                from { transform: translateX(100%); }
                to { transform: translateX(0); }
            }
        `;
        document.head.appendChild(style);
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.llmDashboard = new LLMDashboard();
});

// Export for testing or external use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LLMDashboard;
}