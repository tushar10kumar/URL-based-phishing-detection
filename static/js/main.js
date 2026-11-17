document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const btnText = document.getElementById('btnText');
    const loadingSection = document.getElementById('loadingSection');
    const resultsSection = document.getElementById('resultsSection');

    // UI elements for results
    const verdictBadge = document.getElementById('verdictBadge');
    const verdictTitle = document.getElementById('verdictTitle');
    const targetUrlDisplay = document.getElementById('targetUrlDisplay');
    const degreeBadgeBox = document.getElementById('degreeBadgeBox');
    const riskDegreeBadge = document.getElementById('riskDegreeBadge');
    const riskFactorsList = document.getElementById('riskFactorsList');
    const featuresTableBody = document.getElementById('featuresTableBody');

    // Sample chips
    document.querySelectorAll('.sample-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            urlInput.value = chip.dataset.url;
            scanForm.dispatchEvent(new Event('submit'));
        });
    });

    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) return;

        // Start loading
        resultsSection.classList.add('hidden');
        loadingSection.classList.remove('hidden');
        scanBtn.disabled = true;
        btnText.textContent = "Analyzing...";

        try {
            const response = await fetch('/api/predict', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Server error');
            }

            const data = await response.json();
            renderResults(data);
        } catch (err) {
            alert('Error scanning URL: ' + err.message);
        } finally {
            loadingSection.classList.add('hidden');
            scanBtn.disabled = false;
            btnText.textContent = "Assess Risk";
        }
    });

    function renderResults(data) {
        resultsSection.classList.remove('hidden');

        targetUrlDisplay.textContent = data.url;
        const riskLevel = data.risk_level || 'Moderate';
        const riskLabel = data.risk_label || 'MODERATE RISK';
        const statusColor = data.status_color || 'warning';
        const isPhishing = data.is_phishing;

        // Top Verdict Pill
        if (isPhishing) {
            verdictBadge.textContent = "SUSPICIOUS / PHISHING";
            verdictBadge.className = "verdict-pill " + (riskLevel === 'Critical' ? 'danger' : 'warning');
            verdictTitle.textContent = "Threat Detected";
        } else {
            verdictBadge.textContent = "SAFE / LEGITIMATE";
            verdictBadge.className = "verdict-pill safe";
            verdictTitle.textContent = "Legitimate Website";
        }

        // Risk Degree Badge
        riskDegreeBadge.textContent = riskLabel;
        riskDegreeBadge.className = `degree-badge ${riskLevel.toLowerCase()}`;

        // Degree Box Border Color
        degreeBadgeBox.style.borderColor = 
            riskLevel === 'Critical' || riskLevel === 'High' ? 'var(--danger-red)' :
            riskLevel === 'Moderate' ? 'var(--warning-orange)' :
            riskLevel === 'Low' ? 'var(--warning-yellow)' : 'var(--success-green)';

        // Update Risk Ladder Steps
        const ladderLevels = ['Safe', 'Low', 'Moderate', 'High', 'Critical'];
        ladderLevels.forEach(lvl => {
            const stepEl = document.getElementById(`step-${lvl}`);
            if (stepEl) {
                stepEl.classList.remove('active');
            }
        });

        const activeStep = document.getElementById(`step-${riskLevel}`);
        if (activeStep) {
            activeStep.classList.add('active');
        }

        // Render Risk Factors
        riskFactorsList.innerHTML = '';
        if (data.risk_factors && data.risk_factors.length > 0) {
            data.risk_factors.forEach(f => {
                const item = document.createElement('div');
                item.className = `factor-item ${f.severity || 'warning'}`;
                item.innerHTML = `
                    <div class="factor-title">${f.title}</div>
                    <div class="factor-desc">${f.desc}</div>
                `;
                riskFactorsList.appendChild(item);
            });
        } else {
            riskFactorsList.innerHTML = `
                <div class="factor-item safe" style="grid-column: 1/-1;">
                    <div class="factor-title">No Threat Indicators Identified</div>
                    <div class="factor-desc">The URL matches normal lexical patterns and exhibits no deceptive traits.</div>
                </div>
            `;
        }

        // Render Features Table (without raw weights/percentages)
        featuresTableBody.innerHTML = '';
        const features = data.features || {};
        const labelsMap = {
            'brand_spoofed': 'Brand Impersonation',
            'is_trusted_domain': 'Trusted Root Authority',
            'suspicious_tld': 'High-Risk TLD (.tk/.xyz/etc.)',
            'having_ip': 'Direct IP Address Used',
            'shortening_service': 'URL Shortening Service',
            'having_at': '@ Symbol in URL',
            'prefix_suffix': 'Hyphen in Hostname',
            'subdomains_count': 'Subdomain Level Count',
            'has_excessive_subdomains': 'Excessive Subdomains (>=2)',
            'has_keywords_in_domain': 'Security Keywords in Domain',
            'keywords_in_path': 'Security Keywords in Path',
            'double_slash': 'Double Slash (//) in Path',
            'domain_length': 'Domain Name Length',
            'url_entropy': 'String Entropy (Randomness)',
            'num_special_chars': 'Special Characters Count',
            'digit_ratio': 'Digit-to-Character Ratio'
        };

        for (const [key, label] of Object.entries(labelsMap)) {
            if (!(key in features)) continue;
            const value = features[key];
            const tr = document.createElement('tr');

            let evalBadge = '<span style="color: #9ca3af;">Normal</span>';
            if (key === 'brand_spoofed' && value === 1) {
                evalBadge = '<span style="color: #ef4444; font-weight:700;">Critical Threat</span>';
            } else if (key === 'is_trusted_domain' && value === 1) {
                evalBadge = '<span style="color: #10b981; font-weight:700;">Trusted Authority</span>';
            } else if ((key === 'having_ip' || key === 'suspicious_tld' || key === 'having_at') && value === 1) {
                evalBadge = '<span style="color: #ef4444; font-weight:600;">Suspicious</span>';
            } else if ((key === 'shortening_service' || key === 'has_keywords_in_domain' || key === 'prefix_suffix' || key === 'has_excessive_subdomains') && value === 1) {
                evalBadge = '<span style="color: #f97316; font-weight:600;">Elevated Risk</span>';
            }

            let displayValue = value;
            if (value === 1 && (key.startsWith('has_') || key.startsWith('is_') || key === 'brand_spoofed' || key === 'having_ip' || key === 'having_at' || key === 'shortening_service' || key === 'suspicious_tld' || key === 'prefix_suffix' || key === 'double_slash')) {
                displayValue = 'Yes';
            } else if (value === 0 && (key.startsWith('has_') || key.startsWith('is_') || key === 'brand_spoofed' || key === 'having_ip' || key === 'having_at' || key === 'shortening_service' || key === 'suspicious_tld' || key === 'prefix_suffix' || key === 'double_slash')) {
                displayValue = 'No';
            }

            tr.innerHTML = `
                <td>${label}</td>
                <td><strong>${displayValue}</strong></td>
                <td>${evalBadge}</td>
            `;
            featuresTableBody.appendChild(tr);
        }

        // Smooth scroll to results
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
});
