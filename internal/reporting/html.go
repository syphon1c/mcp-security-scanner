// Copyright (c) 2025 Gareth Phillips/syphon1c
// Licensed under the MIT License - see LICENSE file for details

package reporting

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Security Scanner Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #2563eb;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --critical-color: #dc2626;
            --info-color: #06b6d4;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-300: #d1d5db;
            --gray-400: #9ca3af;
            --gray-500: #6b7280;
            --gray-600: #4b5563;
            --gray-700: #374151;
            --gray-800: #1f2937;
            --gray-900: #111827;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
            --border-radius: 0.75rem;
            --transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--gray-800);
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .header {
            background: white;
            border: 1px solid var(--gray-200);
            color: var(--gray-800);
            padding: 3rem 2rem;
            border-radius: var(--border-radius);
            margin-bottom: 2rem;
            box-shadow: var(--shadow-lg);
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--primary-color);
        }
        
        .header h1 {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            color: var(--gray-900);
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .header p {
            font-size: 1.25rem;
            color: var(--gray-600);
            font-weight: 500;
        }

        .stats-banner {
            display: flex;
            gap: 2rem;
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid var(--gray-200);
        }

        .stat-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 0.875rem;
            color: var(--gray-600);
        }

        .stat-icon {
            width: 2rem;
            height: 2rem;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--gray-100);
            color: var(--gray-600);
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .summary-card {
            background: white;
            padding: 2rem 1.5rem;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            border: 1px solid var(--gray-200);
            position: relative;
            transition: var(--transition);
            overflow: hidden;
        }

        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--primary-color);
            transition: var(--transition);
        }

        .summary-card:hover {
            box-shadow: var(--shadow-lg);
            transform: translateY(-2px);
        }
        
        .summary-card h3 {
            color: var(--gray-700);
            margin-bottom: 1rem;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .summary-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }

        .summary-card .description {
            font-size: 0.875rem;
            color: var(--gray-500);
        }
        
        .risk-critical { --card-color: var(--critical-color); }
        .risk-critical::before { background: var(--critical-color); }
        .risk-critical .value { color: var(--critical-color); }
        
        .risk-high { --card-color: var(--danger-color); }
        .risk-high::before { background: var(--danger-color); }
        .risk-high .value { color: var(--danger-color); }
        
        .risk-medium { --card-color: var(--warning-color); }
        .risk-medium::before { background: var(--warning-color); }
        .risk-medium .value { color: var(--warning-color); }
        
        .risk-low { --card-color: var(--success-color); }
        .risk-low::before { background: var(--success-color); }
        .risk-low .value { color: var(--success-color); }

        .risk-minimal { --card-color: var(--gray-400); }
        .risk-minimal::before { background: var(--gray-400); }
        .risk-minimal .value { color: var(--gray-400); }
        
        .section {
            background: white;
            margin-bottom: 2rem;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            border: 1px solid var(--gray-200);
            overflow: hidden;
            transition: var(--transition);
        }

        .section:hover {
            box-shadow: var(--shadow-md);
        }
        
        .section-header {
            background: white;
            color: #1f2937;
            padding: 1.5rem 2rem;
            font-size: 1.25rem;
            font-weight: 600;
            border-bottom: 1px solid var(--gray-200);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            cursor: pointer;
            position: relative;
        }

        .section-header:hover {
            background: var(--gray-50);
            color: #edededff;
        }

        .section-header .toggle-icon {
            margin-left: auto;
            transition: var(--transition);
            color: var(--gray-400);
        }

        .section.collapsed .section-content {
            display: none;
        }

        .section.collapsed .toggle-icon {
            transform: rotate(180deg);
        }
        
        .section-content {
            padding: 2rem;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .info-item {
            display: flex;
            align-items: flex-start;
            padding: 1rem;
            background: var(--gray-50);
            border-radius: 0.5rem;
            border-left: 4px solid var(--primary-color);
        }
        
        .info-label {
            font-weight: 600;
            color: var(--gray-700);
            min-width: 140px;
            flex-shrink: 0;
        }
        
        .info-value {
            color: var(--gray-600);
            font-weight: 500;
        }
        
        .findings-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            margin-top: 1rem;
            border-radius: var(--border-radius);
            overflow: hidden;
            box-shadow: var(--shadow-sm);
        }
        
        .findings-table th,
        .findings-table td {
            padding: 1rem 1.5rem;
            text-align: left;
            border-bottom: 1px solid var(--gray-200);
        }
        
        .findings-table th {
            background: var(--gray-50);
            font-weight: 600;
            color: var(--gray-700);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            position: sticky;
            top: 0;
        }
        
        .findings-table tbody tr {
            transition: var(--transition);
        }

        .findings-table tbody tr:hover {
            background: var(--gray-50);
        }

        .findings-table tbody tr:last-child td {
            border-bottom: none;
        }
        
        .severity-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            padding: 0.375rem 0.875rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.025em;
            border: 1px solid transparent;
        }
        
        .severity-critical {
            background: var(--critical-color);
            color: white;
            box-shadow: 0 2px 4px rgba(220, 38, 38, 0.3);
        }
        
        .severity-high {
            background: var(--danger-color);
            color: white;
            box-shadow: 0 2px 4px rgba(239, 68, 68, 0.3);
        }
        
        .severity-medium {
            background: var(--warning-color);
            color: white;
            box-shadow: 0 2px 4px rgba(245, 158, 11, 0.3);
        }
        
        .severity-low {
            background: var(--success-color);
            color: white;
            box-shadow: 0 2px 4px rgba(16, 185, 129, 0.3);
        }
        
        .finding-details {
            background: white;
            padding: 2rem;
            margin: 1rem 0;
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-sm);
        }
        
        .finding-details h4 {
            color: #1f2937;
            margin-bottom: 1rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 1.1rem;
        }
        
        .finding-details p {
            margin-bottom: 1rem;
            color: #374151;
            line-height: 1.7;
            font-weight: 500;
        }
        
        .evidence {
            font-family: 'JetBrains Mono', 'SF Mono', 'Monaco', 'Cascadia Code', 'Roboto Mono', monospace;
            background: #fffbeb;
            color: #1f2937;
            padding: 1.5rem;
            border-radius: var(--border-radius);
            white-space: pre-wrap;
            word-wrap: break-word;
            border: 2px solid #f59e0b;
            border-left: 6px solid #f59e0b;
            box-shadow: var(--shadow-sm);
            position: relative;
            overflow-x: auto;
            font-weight: 600;
            font-size: 0.95rem;
        }

        .evidence::before {
            content: 'EVIDENCE';
            position: absolute;
            top: 0.5rem;
            right: 1rem;
            font-size: 0.75rem;
            color: #f59e0b;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            font-weight: 700;
            background: white;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
        }
        
        .code-line {
            font-family: 'JetBrains Mono', 'SF Mono', 'Monaco', 'Cascadia Code', 'Roboto Mono', monospace;
            background: #eff6ff;
            color: #1e293b;
            padding: 1rem 1.5rem;
            border-radius: var(--border-radius);
            border: 1px solid #bfdbfe;
            border-left: 4px solid var(--primary-color);
            margin: 1rem 0;
            font-weight: 500;
            box-shadow: var(--shadow-sm);
            overflow-x: auto;
        }
        
        .code-context {
            font-family: 'JetBrains Mono', 'SF Mono', 'Monaco', 'Cascadia Code', 'Roboto Mono', monospace;
            background: var(--gray-50);
            color: var(--gray-700);
            padding: 1.5rem;
            border-radius: var(--border-radius);
            white-space: pre-line;
            border: 1px solid var(--gray-200);
            margin: 1rem 0;
            font-size: 0.875rem;
            box-shadow: var(--shadow-sm);
            overflow-x: auto;
        }
        
        .line-number {
            color: var(--danger-color);
            font-weight: 700;
            font-family: 'JetBrains Mono', 'SF Mono', 'Monaco', 'Cascadia Code', 'Roboto Mono', monospace;
            background: var(--gray-100);
            padding: 0.25rem 0.5rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
        }        .remediation {
            background: #ecfdf5;
            border: 2px solid #10b981;
            color: #1f2937;
            padding: 1.5rem;
            border-radius: var(--border-radius);
            margin: 1rem 0;
            border-left: 6px solid #10b981;
            box-shadow: var(--shadow-sm);
            font-weight: 600;
            font-size: 0.95rem;
        }

        .remediation::before {
            content: '💡 SOLUTION: ';
            font-size: 1rem;
            margin-right: 0.5rem;
            font-weight: 700;
            color: #059669;
        }
        
        .no-findings {
            text-align: center;
            padding: 4rem 2rem;
            background: #f0fdf4;
            border-radius: var(--border-radius);
            border: 2px dashed var(--success-color);
        }

        .no-findings .icon {
            font-size: 4rem;
            color: var(--success-color);
            margin-bottom: 1rem;
        }

        .no-findings h3 {
            color: var(--gray-800);
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
        }

        .no-findings p {
            color: var(--gray-600);
            font-size: 1.125rem;
        }
        
        .footer {
            background: linear-gradient(135deg, var(--gray-800) 0%, var(--gray-900) 100%);
            color: var(--gray-200);
            text-align: center;
            padding: 2rem;
            margin-top: 3rem;
            border-radius: var(--border-radius);
            border-top: 4px solid var(--primary-color);
        }

        .footer p {
            margin-bottom: 0.5rem;
        }

        .footer .footer-links {
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--gray-700);
            display: flex;
            justify-content: center;
            gap: 2rem;
            flex-wrap: wrap;
        }

        .footer .footer-links a {
            color: var(--gray-400);
            text-decoration: none;
            font-size: 0.875rem;
            transition: var(--transition);
        }

        .footer .footer-links a:hover {
            color: var(--primary-color);
        }
        
        .risk-gauge {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .gauge-bar {
            flex: 1;
            height: 0.75rem;
            background: var(--gray-200);
            border-radius: 9999px;
            overflow: hidden;
            position: relative;
            box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.1);
        }
        
        .gauge-fill {
            height: 100%;
            border-radius: 9999px;
            transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .gauge-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            animation: shimmer 2s infinite;
        }

        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
        
        .gauge-critical { background: linear-gradient(90deg, var(--critical-color), #dc2626); }
        .gauge-high { background: linear-gradient(90deg, var(--danger-color), #dc2626); }
        .gauge-medium { background: linear-gradient(90deg, var(--warning-color), #d97706); }
        .gauge-low { background: linear-gradient(90deg, var(--success-color), #059669); }
        .gauge-minimal { background: linear-gradient(90deg, var(--gray-400), var(--gray-500)); }

        .gauge-score {
            font-weight: 700;
            font-size: 0.875rem;
            color: var(--gray-700);
            min-width: fit-content;
        }

        .tools-resources-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
        }

        .tool-card, .resource-card {
            background: white;
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius);
            padding: 1.5rem;
            transition: var(--transition);
            box-shadow: var(--shadow-sm);
        }

        .tool-card:hover, .resource-card:hover {
            box-shadow: var(--shadow-md);
            transform: translateY(-1px);
        }

        .tool-card {
            border-left: 4px solid var(--primary-color);
        }

        .resource-card {
            border-left: 4px solid var(--info-color);
        }

        .card-title {
            font-weight: 600;
            color: var(--gray-800);
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .card-description {
            color: var(--gray-600);
            font-size: 0.875rem;
            line-height: 1.5;
        }

        .card-meta {
            font-size: 0.75rem;
            color: var(--gray-500);
            margin-top: 0.5rem;
            font-family: 'JetBrains Mono', monospace;
        }

        .expandable-section {
            margin-top: 1.5rem;
        }

        .expand-toggle {
            background: var(--gray-100);
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius);
            padding: 1rem 1.5rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: between;
            gap: 1rem;
            transition: var(--transition);
            font-weight: 500;
            color: var(--gray-700);
        }

        .expand-toggle:hover {
            background: var(--gray-200);
        }

        .expand-toggle .icon {
            margin-left: auto;
            transition: var(--transition);
        }

        .expand-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }

        .expand-content.expanded {
            max-height: 2000px;
            transition: max-height 0.5s ease-in;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .header {
                padding: 2rem 1.5rem;
            }

            .header h1 {
                font-size: 2rem;
            }

            .stats-banner {
                flex-direction: column;
                gap: 1rem;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }

            .info-grid {
                grid-template-columns: 1fr;
            }

            .tools-resources-grid {
                grid-template-columns: 1fr;
            }
            
            .findings-table {
                font-size: 0.875rem;
            }
            
            .findings-table th,
            .findings-table td {
                padding: 0.75rem 0.5rem;
            }

            .finding-details {
                padding: 1.5rem;
            }

            .section-content {
                padding: 1.5rem;
            }
        }

        @media (max-width: 480px) {
            .header h1 {
                font-size: 1.75rem;
            }

            .summary-card .value {
                font-size: 2rem;
            }

            .findings-table th,
            .findings-table td {
                padding: 0.5rem 0.25rem;
            }
        }
        
        @media print {
            body {
                background: white;
            }
            
            .container {
                max-width: none;
                margin: 0;
                padding: 0;
            }
            
            .section {
                box-shadow: none;
                border: 1px solid var(--gray-300);
                break-inside: avoid;
                margin-bottom: 1rem;
            }

            .header {
                background: white;
                color: var(--gray-800);
                border: 2px solid var(--gray-300);
            }

            .summary-card {
                box-shadow: none;
                border: 1px solid var(--gray-300);
            }

            .expand-content {
                max-height: none !important;
            }

            .section-header .toggle-icon {
                display: none;
            }
        }

        /* Dark mode support */
        @media (prefers-color-scheme: dark) {
            :root {
                --gray-50: #1f2937;
                --gray-100: #374151;
                --gray-200: #4b5563;
                --gray-300: #6b7280;
                --gray-400: #9ca3af;
                --gray-500: #d1d5db;
                --gray-600: #e5e7eb;
                --gray-700: #f3f4f6;
                --gray-800: #f9fafb;
                --gray-900: #ffffff;
            }

            body {
                background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
            }

            .summary-card, .section, .tool-card, .resource-card {
                background: var(--gray-100);
                border-color: var(--gray-200);
            }

            .header {
                background: linear-gradient(135deg, rgba(31,41,55,0.95) 0%, rgba(17,24,39,0.9) 100%);
                color: var(--gray-800);
                border-color: var(--gray-200);
            }
        }

        /* Accessibility improvements */
        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            white-space: nowrap;
            border: 0;
        }

        /* Focus styles for keyboard navigation */
        .section-header:focus,
        .expand-toggle:focus {
            outline: 2px solid var(--primary-color);
            outline-offset: 2px;
        }

        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .summary-card {
            animation: fadeIn 0.6s ease-out forwards;
        }

        .summary-card:nth-child(2) { animation-delay: 0.1s; }
        .summary-card:nth-child(3) { animation-delay: 0.2s; }
        .summary-card:nth-child(4) { animation-delay: 0.3s; }

        .section {
            animation: fadeIn 0.6s ease-out forwards;
        }

        .section:nth-child(2) { animation-delay: 0.4s; }
        .section:nth-child(3) { animation-delay: 0.5s; }
        .section:nth-child(4) { animation-delay: 0.6s; }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Toggle section collapse/expand
            const sectionHeaders = document.querySelectorAll('.section-header');
            sectionHeaders.forEach(header => {
                header.addEventListener('click', function() {
                    const section = this.parentElement;
                    section.classList.toggle('collapsed');
                });
            });

            // Toggle expandable content
            const expandToggles = document.querySelectorAll('.expand-toggle');
            expandToggles.forEach(toggle => {
                toggle.addEventListener('click', function() {
                    const content = this.nextElementSibling;
                    const icon = this.querySelector('.icon');
                    
                    if (content.classList.contains('expanded')) {
                        content.classList.remove('expanded');
                        icon.style.transform = 'rotate(0deg)';
                    } else {
                        content.classList.add('expanded');
                        icon.style.transform = 'rotate(180deg)';
                    }
                });
            });

            // Animate progress bars on load
            const progressBars = document.querySelectorAll('.gauge-fill');
            progressBars.forEach(bar => {
                const targetWidth = bar.style.width;
                bar.style.width = '0%';
                setTimeout(() => {
                    bar.style.width = targetWidth;
                }, 500);
            });

            // Smooth scroll for anchor links
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {
                        target.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                });
            });
        });
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> MCP Security Scanner Report</h1>
            <p>Comprehensive Security Assessment for {{.Target}}</p>
            <div class="stats-banner">
                <div class="stat-item">
                    <div class="stat-icon"><i class="fas fa-calendar"></i></div>
                    <span>{{.Timestamp.Format "January 2, 2006 at 3:04 PM"}}</span>
                </div>
                <div class="stat-item">
                    <div class="stat-icon"><i class="fas fa-cog"></i></div>
                    <span>Policy: {{.PolicyUsed}}</span>
                </div>
                <div class="stat-item">
                    <div class="stat-icon"><i class="fas fa-clock"></i></div>
                    <span>Scan Completed</span>
                </div>
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <h3><i class="fas fa-target"></i> Scan Target</h3>
                <div class="value" style="font-size: 1.25rem; word-break: break-all;">{{.Target}}</div>
                <div class="description">Primary assessment target</div>
            </div>
            <div class="summary-card">
                <h3><i class="fas fa-bug"></i> Total Findings</h3>
                <div class="value">{{.Summary.TotalFindings}}</div>
                <div class="description">Security issues detected</div>
            </div>
            <div class="summary-card">
                <h3><i class="fas fa-tools"></i> Components Scanned</h3>
                <div class="value">{{add (len .MCPServer.Tools) (len .MCPServer.Resources)}}</div>
                <div class="description">Tools and resources analyzed</div>
            </div>
            <div class="summary-card risk-{{.OverallRisk | lower}}">
                <h3><i class="fas fa-exclamation-triangle"></i> Risk Level</h3>
                <div class="value">{{.OverallRisk}}</div>
                <div class="risk-gauge">
                    <div class="gauge-bar">
                        <div class="gauge-fill gauge-{{.OverallRisk | lower}}" style="width: {{.RiskPercentage}}%;"></div>
                    </div>
                    <span class="gauge-score">{{.RiskScore}}/100</span>
                </div>
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card risk-critical">
                <h3><i class="fas fa-radiation"></i> Critical</h3>
                <div class="value">{{.Summary.CriticalFindings}}</div>
                <div class="description">Immediate attention required</div>
            </div>
            <div class="summary-card risk-high">
                <h3><i class="fas fa-fire"></i> High</h3>
                <div class="value">{{.Summary.HighFindings}}</div>
                <div class="description">High-priority vulnerabilities</div>
            </div>
            <div class="summary-card risk-medium">
                <h3><i class="fas fa-exclamation"></i> Medium</h3>
                <div class="value">{{.Summary.MediumFindings}}</div>
                <div class="description">Moderate-risk issues</div>
            </div>
            <div class="summary-card risk-low">
                <h3><i class="fas fa-info-circle"></i> Low</h3>
                <div class="value">{{.Summary.LowFindings}}</div>
                <div class="description">Low-impact findings</div>
            </div>
        </div>

        {{if .MCPServer.Name}}
        <div class="section">
            <div class="section-header" tabindex="0" role="button" aria-expanded="true">
                <i class="fas fa-server"></i> MCP Server Information
                <i class="fas fa-chevron-up toggle-icon"></i>
            </div>
            <div class="section-content">
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label"><i class="fas fa-tag"></i> Server Name:</span>
                        <span class="info-value">{{.MCPServer.Name}}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label"><i class="fas fa-code-branch"></i> Version:</span>
                        <span class="info-value">{{.MCPServer.Version}}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label"><i class="fas fa-network-wired"></i> Protocol:</span>
                        <span class="info-value">{{.MCPServer.Protocol}}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label"><i class="fas fa-wrench"></i> Available Tools:</span>
                        <span class="info-value">{{len .MCPServer.Tools}}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label"><i class="fas fa-database"></i> Available Resources:</span>
                        <span class="info-value">{{len .MCPServer.Resources}}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label"><i class="fas fa-puzzle-piece"></i> Capabilities:</span>
                        <span class="info-value">{{join .MCPServer.Capabilities ", "}}</span>
                    </div>
                </div>
                
                {{if .MCPServer.Tools}}
                <div class="expandable-section">
                    <div class="expand-toggle">
                        <i class="fas fa-tools"></i>
                        <span><strong>Discovered Tools ({{len .MCPServer.Tools}})</strong></span>
                        <i class="fas fa-chevron-down icon"></i>
                    </div>
                    <div class="expand-content">
                        <div class="tools-resources-grid">
                            {{range .MCPServer.Tools}}
                            <div class="tool-card">
                                <div class="card-title">
                                    <i class="fas fa-cog"></i>
                                    {{.Name}}
                                </div>
                                <div class="card-description">{{.Description}}</div>
                                {{if .InputSchema}}
                                <div class="card-meta">Schema: Available</div>
                                {{end}}
                            </div>
                            {{end}}
                        </div>
                    </div>
                </div>
                {{end}}
                
                {{if .MCPServer.Resources}}
                <div class="expandable-section">
                    <div class="expand-toggle">
                        <i class="fas fa-database"></i>
                        <span><strong>Discovered Resources ({{len .MCPServer.Resources}})</strong></span>
                        <i class="fas fa-chevron-down icon"></i>
                    </div>
                    <div class="expand-content">
                        <div class="tools-resources-grid">
                            {{range .MCPServer.Resources}}
                            <div class="resource-card">
                                <div class="card-title">
                                    <i class="fas fa-file"></i>
                                    {{.Name}}
                                </div>
                                <div class="card-description">{{.Description}}</div>
                                <div class="card-meta">{{.URI}}</div>
                            </div>
                            {{end}}
                        </div>
                    </div>
                </div>
                {{end}}
            </div>
        </div>
        {{end}}

        <div class="section">
            <div class="section-header" tabindex="0" role="button" aria-expanded="true">
                <i class="fas fa-search"></i> Security Findings
                {{if .Findings}}
                <span style="margin-left: auto; margin-right: 1rem; font-size: 0.875rem; opacity: 0.8;">{{len .Findings}} findings</span>
                {{end}}
                <i class="fas fa-chevron-up toggle-icon"></i>
            </div>
            <div class="section-content">
                {{if .Findings}}
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th><i class="fas fa-flag"></i> Severity</th>
                            <th><i class="fas fa-text-width"></i> Title</th>
                            <th><i class="fas fa-tags"></i> Category</th>
                            <th><i class="fas fa-map-marker-alt"></i> Location</th>
                            <th><i class="fas fa-sort-numeric-up"></i> Line</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Findings}}
                        <tr>
                            <td>
                                <span class="severity-badge severity-{{.Severity | lower}}">
                                    {{if eq .Severity "Critical"}}<i class="fas fa-radiation"></i>{{else if eq .Severity "High"}}<i class="fas fa-fire"></i>{{else if eq .Severity "Medium"}}<i class="fas fa-exclamation"></i>{{else}}<i class="fas fa-info"></i>{{end}}
                                    {{.Severity}}
                                </span>
                            </td>
                            <td><strong>{{.Title}}</strong></td>
                            <td>
                                <span style="display: inline-flex; align-items: center; gap: 0.375rem;">
                                    <i class="fas fa-tag"></i>
                                    {{.Category}}
                                </span>
                            </td>
                            <td>
                                <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.875rem;">{{.Location}}</span>
                            </td>
                            <td>
                                {{if gt .LineNumber 0}}
                                <span class="line-number">{{.LineNumber}}</span>
                                {{else}}
                                <span style="color: var(--gray-400);">-</span>
                                {{end}}
                            </td>
                        </tr>
                        <tr>
                            <td colspan="5">
                                <div class="finding-details">
                                    <h4><i class="fas fa-file-alt"></i> Description</h4>
                                    <p>{{.Description}}</p>
                                    
                                    {{if .Evidence}}
                                    <h4><i class="fas fa-search"></i> Evidence</h4>
                                    <div class="evidence">{{.Evidence}}</div>
                                    {{end}}
                                    
                                    {{if .CodeLine}}
                                    <h4><i class="fas fa-code"></i> Code Line {{if gt .LineNumber 0}}(Line {{.LineNumber}}){{end}}</h4>
                                    <div class="code-line">{{.CodeLine}}</div>
                                    {{end}}
                                    
                                    {{if .CodeContext}}
                                    <h4><i class="fas fa-align-left"></i> Code Context</h4>
                                    <div class="code-context">{{range .CodeContext}}{{.}}
{{end}}</div>
                                    {{end}}
                                    
                                    {{if .Remediation}}
                                    <h4><i class="fas fa-tools"></i> Remediation</h4>
                                    <div class="remediation">{{.Remediation}}</div>
                                    {{end}}
                                </div>
                            </td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
                {{else}}
                <div class="no-findings">
                    <div class="icon">
                        <i class="fas fa-shield-check"></i>
                    </div>
                    <h3>All Clear!</h3>
                    <p>No security findings detected. Your MCP server appears to be secure according to the selected policy.</p>
                </div>
                {{end}}
            </div>
        </div>

        <div class="footer">
            <p><strong>Generated by MCP Security Scanner v1.0</strong></p>
            <p>Report generated on {{.Timestamp.Format "February 15, 1982 at 3:04:05 PM MST"}}</p>
            <p>This assessment analyzed {{.Summary.TotalFindings}} findings across {{len .MCPServer.Tools}} tools and {{len .MCPServer.Resources}} resources</p>
            
            <div class="footer-links">
                <a href="https://github.com/syphon1c/mcp-security-scanner/" target="_blankr">
                    <i class="fab fa-github"></i> GitHub Repository
                </a>
                <a href="https://github.com/syphon1c/mcp-security-scanner/tree/main/docs" target="_blankd">
                    <i class="fas fa-book"></i> Documentation
                </a>
                <a href="https://github.com/syphon1c/mcp-security-scanner/issues" target="_blanki">
                    <i class="fas fa-life-ring"></i> Support
                </a>
            </div>
        </div>
    </div>

    <script>
        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {
            initializeExpandableSections();
            initializeSectionToggles();
            addKeyboardNavigation();
            animateElements();
        });

        // Expandable sections functionality
        function initializeExpandableSections() {
            const toggles = document.querySelectorAll('.expand-toggle');
            toggles.forEach(toggle => {
                toggle.addEventListener('click', function() {
                    const content = this.nextElementSibling;
                    const icon = this.querySelector('.icon');
                    
                    if (content.style.display === 'block') {
                        content.style.display = 'none';
                        icon.style.transform = 'rotate(0deg)';
                        this.classList.remove('expanded');
                    } else {
                        content.style.display = 'block';
                        icon.style.transform = 'rotate(180deg)';
                        this.classList.add('expanded');
                    }
                });
            });
        }

        // Section header toggles
        function initializeSectionToggles() {
            const headers = document.querySelectorAll('.section-header[role="button"]');
            headers.forEach(header => {
                header.addEventListener('click', function() {
                    const content = this.nextElementSibling;
                    const icon = this.querySelector('.toggle-icon');
                    const isExpanded = this.getAttribute('aria-expanded') === 'true';
                    
                    // Toggle visibility
                    if (isExpanded) {
                        content.style.display = 'none';
                        icon.classList.remove('fa-chevron-up');
                        icon.classList.add('fa-chevron-down');
                        this.setAttribute('aria-expanded', 'false');
                    } else {
                        content.style.display = 'block';
                        icon.classList.remove('fa-chevron-down');
                        icon.classList.add('fa-chevron-up');
                        this.setAttribute('aria-expanded', 'true');
                    }
                });
            });
        }

        // Keyboard navigation support
        function addKeyboardNavigation() {
            const toggles = document.querySelectorAll('[tabindex="0"]');
            toggles.forEach(toggle => {
                toggle.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        this.click();
                    }
                });
            });
        }

        // Animate elements on load
        function animateElements() {
            const cards = document.querySelectorAll('.summary-card');
            cards.forEach((card, index) => {
                setTimeout(() => {
                    card.style.animation = 'slideInUp 0.5s ease-out forwards';
                }, index * 100);
            });

            const sections = document.querySelectorAll('.section');
            sections.forEach((section, index) => {
                setTimeout(() => {
                    section.style.animation = 'fadeInUp 0.6s ease-out forwards';
                }, 200 + (index * 150));
            });
        }

        // Copy to clipboard functionality for code blocks
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                // Could show a toast notification here
                console.log('Code copied to clipboard');
            });
        }

        // Add copy buttons to code blocks
        document.querySelectorAll('.code-line, .code-context, .evidence').forEach(codeBlock => {
            const copyBtn = document.createElement('button');
            copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
            copyBtn.className = 'copy-btn';
            copyBtn.style.cssText = ` + "`" + `
                position: absolute;
                top: 8px;
                right: 8px;
                background: var(--background-primary);
                border: 1px solid var(--border-color);
                border-radius: 4px;
                padding: 4px 8px;
                cursor: pointer;
                opacity: 0;
                transition: opacity 0.2s ease;
            ` + "`" + `;
            
            codeBlock.style.position = 'relative';
            codeBlock.appendChild(copyBtn);
            
            codeBlock.addEventListener('mouseenter', () => copyBtn.style.opacity = '1');
            codeBlock.addEventListener('mouseleave', () => copyBtn.style.opacity = '0');
            
            copyBtn.addEventListener('click', () => {
                copyToClipboard(codeBlock.textContent);
                copyBtn.innerHTML = '<i class="fas fa-check"></i>';
                setTimeout(() => copyBtn.innerHTML = '<i class="fas fa-copy"></i>', 1000);
            });
        });

        // Smooth scrolling for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    </script>
</body>
</html>`

// HTMLReporter generates HTML reports for scan results
type HTMLReporter struct {
	template *template.Template
}

// NewHTMLReporter creates a new HTML reporter
func NewHTMLReporter() (*HTMLReporter, error) {
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"join":  strings.Join,
		"add": func(a, b int) int {
			return a + b
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML template: %w", err)
	}

	return &HTMLReporter{
		template: tmpl,
	}, nil
}

// GenerateReport generates an HTML report and saves it to the specified file
func (r *HTMLReporter) GenerateReport(result *types.ScanResult, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Add calculated fields for template
	reportData := struct {
		*types.ScanResult
		RiskPercentage int
	}{
		ScanResult:     result,
		RiskPercentage: calculateRiskPercentage(result.RiskScore),
	}

	// Generate HTML content
	var buf bytes.Buffer
	if err := r.template.Execute(&buf, reportData); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, buf.Bytes(), 0o600); err != nil { // Fix G306: use 0o600 permissions
		return fmt.Errorf("failed to write HTML report: %w", err)
	}

	return nil
}

// GenerateHTMLString generates HTML content as a string
func (r *HTMLReporter) GenerateHTMLString(result *types.ScanResult) (string, error) {
	reportData := struct {
		*types.ScanResult
		RiskPercentage int
	}{
		ScanResult:     result,
		RiskPercentage: calculateRiskPercentage(result.RiskScore),
	}

	var buf bytes.Buffer
	if err := r.template.Execute(&buf, reportData); err != nil {
		return "", fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return buf.String(), nil
}

// calculateRiskPercentage converts risk score to percentage for progress bar
func calculateRiskPercentage(riskScore int) int {
	// Risk scores typically range from 0-100, but we cap at 100%
	if riskScore > 100 {
		return 100
	}
	if riskScore < 0 {
		return 0
	}
	return riskScore
}

// GenerateHTMLReportWithTimestamp generates an HTML report with timestamp in filename
func GenerateHTMLReportWithTimestamp(result *types.ScanResult, baseDir string) (string, error) {
	reporter, err := NewHTMLReporter()
	if err != nil {
		return "", err
	}

	// Create timestamped filename
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("mcp_security_report_%s.html", timestamp)
	outputPath := filepath.Join(baseDir, filename)

	err = reporter.GenerateReport(result, outputPath)
	if err != nil {
		return "", err
	}

	return outputPath, nil
}
