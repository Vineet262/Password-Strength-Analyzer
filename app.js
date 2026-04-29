/* ==========================================
   CipherGuard — Password Strength Analyzer
   Core Application Logic
   ========================================== */

// =====================================
// Common Password Database (Top 500+)
// =====================================
const COMMON_PASSWORDS = new Set([
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
    'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
    'ashley', 'bailey', 'shadow', '123123', '654321', 'superman', 'qazwsx',
    'michael', 'football', 'password1', 'password123', 'batman', 'login',
    'princess', 'admin', 'welcome', 'hello', 'charlie', 'donald', 'starwars',
    'access', 'flower', 'hottie', 'loveme', 'zaq1zaq1', 'password1!', 'qwerty123',
    '111111', '1234', '12345', '123456789', '1234567890', '0987654321',
    'abcdef', 'abcd1234', 'qwerty1', 'pass1234', 'pass123', 'changeme',
    'secret', 'test', 'guest', 'root', 'toor', 'administrator', '1q2w3e4r',
    '1qaz2wsx', 'qwer1234', 'zxcvbnm', 'asdfghjkl', 'poiuytrewq',
    'computer', 'internet', 'samsung', 'google', 'facebook', 'twitter',
    'linkedin', 'youtube', 'amazon', 'apple', 'microsoft', 'iphone',
    'summer', 'winter', 'spring', 'autumn', 'monday', 'friday',
    'january', 'february', 'march', 'love', 'money', 'freedom',
    'soccer', 'hockey', 'yankees', 'rangers', 'lakers', 'cowboys',
    'jordan', 'robert', 'thomas', 'jessica', 'jennifer', 'matthew',
    'whatever', 'nothing', 'mustang', 'harley', 'cheese', 'pepper',
    'ginger', 'killer', 'george', 'jack', 'oliver', 'harry', 'charlie1',
    'passw0rd', 'p@ssword', 'p@ssw0rd', 'pa$$word', 'letmein!',
    'welcome1', 'welcome123', 'admin123', 'admin1', 'root123',
    'test123', 'test1234', 'guest123', 'user', 'user123',
]);

// =====================================
// Sequential & Repeated patterns
// =====================================
const KEYBOARD_SEQUENCES = [
    'qwerty', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'qwer', 'asdf', 'zxcv',
    '1234', '2345', '3456', '4567', '5678', '6789', '7890',
    'abcd', 'bcde', 'cdef', 'defg', 'efgh', 'fghi', 'ghij',
    'hijk', 'ijkl', 'jklm', 'klmn', 'lmno', 'mnop', 'nopq',
    'opqr', 'pqrs', 'qrst', 'rstu', 'stuv', 'tuvw', 'uvwx', 'vwxy', 'wxyz',
    '!@#$', '@#$%', '#$%^', '$%^&',
];

// =====================================
// Utility: Hash a password (simple SHA-like for storage comparison)
// =====================================
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// =====================================
// Password Analysis Engine
// =====================================
class PasswordAnalyzer {
    constructor(password) {
        this.password = password;
        this.length = password.length;
    }

    // --- Character class checks ---
    hasLowercase() { return /[a-z]/.test(this.password); }
    hasUppercase() { return /[A-Z]/.test(this.password); }
    hasNumbers() { return /[0-9]/.test(this.password); }
    hasSpecial() { return /[^a-zA-Z0-9]/.test(this.password); }

    // --- Charset size ---
    getCharsetSize() {
        let size = 0;
        if (this.hasLowercase()) size += 26;
        if (this.hasUppercase()) size += 26;
        if (this.hasNumbers()) size += 10;
        if (this.hasSpecial()) size += 33;
        return size;
    }

    // --- Entropy calculation: E = L × log₂(R) ---
    getEntropy() {
        const R = this.getCharsetSize();
        if (R === 0 || this.length === 0) return 0;
        return Math.round(this.length * Math.log2(R) * 100) / 100;
    }

    // --- Uniqueness percentage ---
    getUniqueness() {
        if (this.length === 0) return 0;
        const unique = new Set(this.password).size;
        return Math.round((unique / this.length) * 100);
    }

    // --- Check if it's a common password ---
    isCommon() {
        return COMMON_PASSWORDS.has(this.password.toLowerCase());
    }

    // --- Check for sequential patterns ---
    hasSequentialPattern() {
        const lower = this.password.toLowerCase();
        for (const seq of KEYBOARD_SEQUENCES) {
            if (lower.includes(seq) || lower.includes(seq.split('').reverse().join(''))) {
                return true;
            }
        }
        return false;
    }

    // --- Check for repeated characters (3+) ---
    hasRepeatedChars() {
        return /(.)\1{2,}/.test(this.password);
    }

    // --- Estimated crack time ---
    getCrackTime() {
        const entropy = this.getEntropy();
        // Assuming 10 billion guesses per second (modern GPU)
        const guessesPerSecond = 10e9;
        const totalGuesses = Math.pow(2, entropy);
        const seconds = totalGuesses / guessesPerSecond;

        if (seconds < 0.001) return 'Instantly';
        if (seconds < 1) return 'Less than a second';
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
        if (seconds < 2592000) return `${Math.round(seconds / 86400)} days`;
        if (seconds < 31536000) return `${Math.round(seconds / 2592000)} months`;
        if (seconds < 31536000 * 100) return `${Math.round(seconds / 31536000)} years`;
        if (seconds < 31536000 * 1e6) return `${Math.round(seconds / (31536000 * 1000))}K years`;
        if (seconds < 31536000 * 1e9) return `${Math.round(seconds / (31536000 * 1e6))}M years`;
        if (seconds < 31536000 * 1e12) return `${Math.round(seconds / (31536000 * 1e9))}B years`;
        return '∞ (Heat death of universe)';
    }

    // --- Overall strength score (0-100) ---
    getStrengthScore() {
        let score = 0;

        // Length contribution (max 30 points)
        score += Math.min(30, this.length * 2);

        // Charset diversity (max 20 points)
        let diversity = 0;
        if (this.hasLowercase()) diversity++;
        if (this.hasUppercase()) diversity++;
        if (this.hasNumbers()) diversity++;
        if (this.hasSpecial()) diversity++;
        score += diversity * 5;

        // Entropy contribution (max 25 points)
        const entropy = this.getEntropy();
        score += Math.min(25, entropy / 5);

        // Uniqueness contribution (max 15 points)
        score += Math.min(15, this.getUniqueness() * 0.15);

        // Penalties
        if (this.isCommon()) score -= 40;
        if (this.hasSequentialPattern()) score -= 15;
        if (this.hasRepeatedChars()) score -= 10;
        if (this.length < 8) score -= 15;

        return Math.max(0, Math.min(100, Math.round(score)));
    }

    // --- Strength level ---
    getStrengthLevel() {
        const score = this.getStrengthScore();
        if (score <= 15) return { label: 'Critical', color: 'var(--strength-critical)', class: 'critical' };
        if (score <= 30) return { label: 'Very Weak', color: 'var(--strength-weak)', class: 'weak' };
        if (score <= 50) return { label: 'Weak', color: 'var(--strength-fair)', class: 'fair' };
        if (score <= 70) return { label: 'Moderate', color: 'var(--strength-good)', class: 'good' };
        if (score <= 85) return { label: 'Strong', color: 'var(--strength-strong)', class: 'strong' };
        return { label: 'Excellent', color: 'var(--strength-excellent)', class: 'excellent' };
    }

    // --- Generate suggestions ---
    getSuggestions() {
        const suggestions = [];

        if (this.length === 0) return [];

        if (this.isCommon()) {
            suggestions.push({ type: 'danger', icon: '🚨', text: 'This is a commonly used password found in breach databases. Change it immediately!' });
        }

        if (this.length < 8) {
            suggestions.push({ type: 'danger', icon: '📏', text: 'Too short! Use at least 8 characters, ideally 12 or more.' });
        } else if (this.length < 12) {
            suggestions.push({ type: 'warning', icon: '📏', text: 'Consider increasing to 12+ characters for stronger security.' });
        }

        if (!this.hasUppercase()) {
            suggestions.push({ type: 'warning', icon: '🔠', text: 'Add uppercase letters (A-Z) to increase complexity.' });
        }

        if (!this.hasLowercase()) {
            suggestions.push({ type: 'warning', icon: '🔡', text: 'Add lowercase letters (a-z) to increase complexity.' });
        }

        if (!this.hasNumbers()) {
            suggestions.push({ type: 'warning', icon: '🔢', text: 'Include numbers (0-9) to broaden the character set.' });
        }

        if (!this.hasSpecial()) {
            suggestions.push({ type: 'warning', icon: '✨', text: 'Add special characters (!@#$%^&*) for maximum entropy.' });
        }

        if (this.hasSequentialPattern()) {
            suggestions.push({ type: 'danger', icon: '🔗', text: 'Contains sequential patterns (abc, 123, qwerty). These are easily guessable.' });
        }

        if (this.hasRepeatedChars()) {
            suggestions.push({ type: 'warning', icon: '🔁', text: 'Avoid repeating the same character 3+ times in a row.' });
        }

        if (this.getUniqueness() < 50) {
            suggestions.push({ type: 'warning', icon: '🎯', text: 'Low character diversity. Try using more unique characters.' });
        }

        const score = this.getStrengthScore();
        if (score >= 80) {
            suggestions.push({ type: 'success', icon: '🛡️', text: 'Excellent password! This would take a very long time to crack.' });
        } else if (score >= 60) {
            suggestions.push({ type: 'success', icon: '👍', text: 'Good password, but there is room for improvement.' });
        }

        if (suggestions.length === 0) {
            suggestions.push({ type: 'success', icon: '✅', text: 'Your password meets basic complexity requirements.' });
        }

        return suggestions;
    }
}

// =====================================
// Password Generator
// =====================================
class PasswordGenerator {
    static generate(length = 16, options = {}) {
        const {
            uppercase = true,
            lowercase = true,
            numbers = true,
            symbols = true,
            excludeAmbiguous = false
        } = options;

        let charset = '';
        let required = [];

        const ambiguousChars = 'O0l1I';

        if (lowercase) {
            let chars = 'abcdefghijklmnopqrstuvwxyz';
            if (excludeAmbiguous) chars = chars.replace(/[l]/g, '');
            charset += chars;
            required.push(chars);
        }
        if (uppercase) {
            let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            if (excludeAmbiguous) chars = chars.replace(/[OI]/g, '');
            charset += chars;
            required.push(chars);
        }
        if (numbers) {
            let chars = '0123456789';
            if (excludeAmbiguous) chars = chars.replace(/[01]/g, '');
            charset += chars;
            required.push(chars);
        }
        if (symbols) {
            charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
            required.push('!@#$%^&*()_+-=[]{}|;:,.<>?');
        }

        if (charset.length === 0) {
            charset = 'abcdefghijklmnopqrstuvwxyz';
            required.push(charset);
        }

        let password;
        do {
            password = '';
            const array = new Uint32Array(length);
            crypto.getRandomValues(array);
            for (let i = 0; i < length; i++) {
                password += charset[array[i] % charset.length];
            }
        } while (!required.every(req => [...password].some(c => req.includes(c))) && length >= required.length);

        // Ensure at least one character from each required set
        if (length >= required.length) {
            for (let i = 0; i < required.length; i++) {
                const reqChars = required[i];
                const hasReq = [...password].some(c => reqChars.includes(c));
                if (!hasReq) {
                    const randomArray = new Uint32Array(2);
                    crypto.getRandomValues(randomArray);
                    const pos = randomArray[0] % password.length;
                    const char = reqChars[randomArray[1] % reqChars.length];
                    password = password.substring(0, pos) + char + password.substring(pos + 1);
                }
            }
        }

        return password;
    }
}

// =====================================
// History Manager (localStorage)
// =====================================
class HistoryManager {
    static KEY = 'cipherguard_history';

    static getAll() {
        try {
            return JSON.parse(localStorage.getItem(this.KEY) || '[]');
        } catch {
            return [];
        }
    }

    static async add(password, score, level) {
        const hash = await hashPassword(password);
        const history = this.getAll();
        
        // Don't add duplicates
        if (history.some(h => h.hash === hash)) return;

        const masked = password.length <= 4
            ? '*'.repeat(password.length)
            : password.substring(0, 2) + '*'.repeat(password.length - 4) + password.substring(password.length - 2);

        history.unshift({
            hash,
            masked,
            score,
            level: level.label,
            color: level.color,
            date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }),
            timestamp: Date.now()
        });

        // Keep last 50
        if (history.length > 50) history.pop();

        localStorage.setItem(this.KEY, JSON.stringify(history));
    }

    static async isReused(password) {
        const hash = await hashPassword(password);
        const history = this.getAll();
        return history.some(h => h.hash === hash);
    }

    static remove(index) {
        const history = this.getAll();
        history.splice(index, 1);
        localStorage.setItem(this.KEY, JSON.stringify(history));
    }

    static clear() {
        localStorage.removeItem(this.KEY);
    }
}

// =====================================
// DOM Controller
// =====================================
class App {
    constructor() {
        this.currentSection = 'analyzer';
        this.debounceTimer = null;
        this.init();
    }

    init() {
        this.bindNavigation();
        this.bindAnalyzer();
        this.bindGenerator();
        this.bindHistory();
        this.renderHistory();
    }

    // --- Navigation ---
    bindNavigation() {
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const section = link.dataset.section;
                this.navigateTo(section);
            });
        });
    }

    navigateTo(sectionId) {
        // Update nav
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        document.querySelector(`[data-section="${sectionId}"]`).classList.add('active');

        // Update sections
        document.querySelectorAll('.section').forEach(s => s.classList.remove('section-active'));
        const section = document.getElementById(sectionId);
        section.classList.add('section-active');

        this.currentSection = sectionId;

        // Refresh history when switching to it
        if (sectionId === 'history') this.renderHistory();
    }

    // --- Analyzer ---
    bindAnalyzer() {
        const input = document.getElementById('password-input');
        const toggleBtn = document.getElementById('toggle-visibility');

        input.addEventListener('input', () => {
            clearTimeout(this.debounceTimer);
            this.debounceTimer = setTimeout(() => this.analyzePassword(), 50);
        });

        toggleBtn.addEventListener('click', () => {
            const isPassword = input.type === 'password';
            input.type = isPassword ? 'text' : 'password';
            toggleBtn.querySelector('.eye-open').style.display = isPassword ? 'none' : 'block';
            toggleBtn.querySelector('.eye-closed').style.display = isPassword ? 'block' : 'none';
        });
    }

    async analyzePassword() {
        const password = document.getElementById('password-input').value;

        if (password.length === 0) {
            this.resetAnalysis();
            return;
        }

        const analyzer = new PasswordAnalyzer(password);
        const score = analyzer.getStrengthScore();
        const level = analyzer.getStrengthLevel();
        const entropy = analyzer.getEntropy();
        const charsetSize = analyzer.getCharsetSize();
        const uniqueness = analyzer.getUniqueness();
        const crackTime = analyzer.getCrackTime();
        const suggestions = analyzer.getSuggestions();

        // Update strength bar
        const barFill = document.getElementById('strength-bar-fill');
        barFill.style.width = `${score}%`;
        barFill.style.background = level.color;

        const labelEl = document.getElementById('strength-label');
        labelEl.textContent = level.label;
        labelEl.style.color = level.color;

        document.getElementById('strength-score').textContent = `${score} / 100`;

        // Update crack time
        const crackEl = document.getElementById('crack-time-value');
        crackEl.textContent = crackTime;

        // Update metrics
        this.animateMetric('entropy-value', entropy);
        this.updateBar('entropy-bar', Math.min(100, entropy / 1.28), 'var(--accent-2)');

        this.animateMetric('length-value', password.length);
        this.updateBar('length-bar', Math.min(100, (password.length / 20) * 100), 'var(--accent-3)');

        this.animateMetric('charset-value', charsetSize);
        this.updateBar('charset-bar', Math.min(100, (charsetSize / 95) * 100), 'var(--accent-1)');

        document.getElementById('uniqueness-value').textContent = `${uniqueness}%`;
        this.updateBar('uniqueness-bar', uniqueness, 'var(--strength-good)');

        // Update checklist
        this.updateCheck('check-length', password.length >= 8);
        this.updateCheck('check-uppercase', analyzer.hasUppercase());
        this.updateCheck('check-lowercase', analyzer.hasLowercase());
        this.updateCheck('check-number', analyzer.hasNumbers());
        this.updateCheck('check-special', analyzer.hasSpecial());
        this.updateCheck('check-no-common', !analyzer.isCommon());
        this.updateCheck('check-no-sequence', !analyzer.hasSequentialPattern());
        this.updateCheck('check-no-repeat', !analyzer.hasRepeatedChars());

        // Update suggestions
        this.renderSuggestions(suggestions);

        // Check reuse
        const isReused = await HistoryManager.isReused(password);
        this.updateReuseStatus(isReused);

        // Save to history
        await HistoryManager.add(password, score, level);
    }

    animateMetric(elementId, targetValue) {
        const el = document.getElementById(elementId);
        const current = parseFloat(el.textContent) || 0;
        const diff = targetValue - current;
        const steps = 20;
        let step = 0;

        const animate = () => {
            step++;
            const progress = step / steps;
            const eased = 1 - Math.pow(1 - progress, 3);
            const value = current + diff * eased;
            el.textContent = Number.isInteger(targetValue) ? Math.round(value) : value.toFixed(1);
            if (step < steps) requestAnimationFrame(animate);
        };

        requestAnimationFrame(animate);
    }

    updateBar(barId, percentage, color) {
        const bar = document.getElementById(barId);
        bar.style.width = `${percentage}%`;
        bar.style.background = color;
    }

    updateCheck(elementId, passed) {
        const el = document.getElementById(elementId);
        el.classList.remove('passed', 'failed');
        el.classList.add(passed ? 'passed' : 'failed');
    }

    renderSuggestions(suggestions) {
        const container = document.getElementById('suggestions-list');
        container.innerHTML = suggestions.map(s => `
            <div class="suggestion-item suggestion-${s.type}">
                <span class="suggestion-icon">${s.icon}</span>
                <span>${s.text}</span>
            </div>
        `).join('');
    }

    updateReuseStatus(isReused) {
        const badge = document.getElementById('reuse-badge');
        const text = document.getElementById('reuse-text');

        badge.className = 'reuse-badge';

        if (isReused) {
            badge.classList.add('reuse-danger');
            badge.querySelector('svg').outerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
            text.textContent = 'This password has been used before! Consider using a unique password.';
        } else {
            badge.classList.add('reuse-safe');
            badge.querySelector('svg').outerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
            text.textContent = 'This password has not been used before. Good!';
        }
    }

    resetAnalysis() {
        document.getElementById('strength-bar-fill').style.width = '0%';
        document.getElementById('strength-label').textContent = 'Enter a password';
        document.getElementById('strength-label').style.color = 'var(--text-muted)';
        document.getElementById('strength-score').textContent = '0 / 100';
        document.getElementById('crack-time-value').textContent = '—';

        ['entropy-value', 'length-value', 'charset-value'].forEach(id => {
            document.getElementById(id).textContent = '0';
        });
        document.getElementById('uniqueness-value').textContent = '0%';

        ['entropy-bar', 'length-bar', 'charset-bar', 'uniqueness-bar'].forEach(id => {
            document.getElementById(id).style.width = '0%';
        });

        document.querySelectorAll('.checklist-item').forEach(el => {
            el.classList.remove('passed', 'failed');
        });

        document.getElementById('suggestions-list').innerHTML = `
            <div class="suggestion-item suggestion-neutral">
                <span class="suggestion-icon">💡</span>
                <span>Start typing to get personalized suggestions</span>
            </div>
        `;

        const badge = document.getElementById('reuse-badge');
        badge.className = 'reuse-badge reuse-neutral';
        badge.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <span id="reuse-text">Enter a password to check</span>
        `;
    }

    // --- Generator ---
    bindGenerator() {
        const slider = document.getElementById('gen-length-slider');
        const display = document.getElementById('gen-length-display');
        const generateBtn = document.getElementById('btn-generate');
        const regenerateBtn = document.getElementById('regenerate-btn');
        const copyBtn = document.getElementById('copy-generated');
        const bulkBtn = document.getElementById('btn-bulk-generate');

        slider.addEventListener('input', () => {
            display.textContent = slider.value;
            this.updateSliderBackground(slider);
        });

        this.updateSliderBackground(slider);

        generateBtn.addEventListener('click', () => this.generatePassword());
        regenerateBtn.addEventListener('click', () => this.generatePassword());
        copyBtn.addEventListener('click', () => {
            const password = document.getElementById('generated-password').textContent;
            if (password && password !== 'Click Generate') {
                this.copyToClipboard(password);
            }
        });

        bulkBtn.addEventListener('click', () => this.generateBulk());
    }

    updateSliderBackground(slider) {
        const percent = ((slider.value - slider.min) / (slider.max - slider.min)) * 100;
        slider.style.background = `linear-gradient(90deg, var(--accent-1) 0%, var(--accent-3) ${percent}%, rgba(255,255,255,0.08) ${percent}%)`;
    }

    getGeneratorOptions() {
        return {
            uppercase: document.querySelector('#gen-toggle-upper input').checked,
            lowercase: document.querySelector('#gen-toggle-lower input').checked,
            numbers: document.querySelector('#gen-toggle-numbers input').checked,
            symbols: document.querySelector('#gen-toggle-symbols input').checked,
            excludeAmbiguous: document.querySelector('#gen-toggle-ambiguous input').checked,
        };
    }

    generatePassword() {
        const length = parseInt(document.getElementById('gen-length-slider').value);
        const options = this.getGeneratorOptions();
        const password = PasswordGenerator.generate(length, options);

        const display = document.getElementById('generated-password');
        display.textContent = password;
        display.style.animation = 'none';
        display.offsetHeight; // trigger reflow
        display.style.animation = 'slideIn 0.3s ease';
    }

    generateBulk() {
        const count = parseInt(document.getElementById('bulk-count').value) || 5;
        const length = parseInt(document.getElementById('gen-length-slider').value);
        const options = this.getGeneratorOptions();
        const container = document.getElementById('bulk-results');
        container.innerHTML = '';

        for (let i = 0; i < Math.min(count, 20); i++) {
            const password = PasswordGenerator.generate(length, options);
            const item = document.createElement('div');
            item.className = 'bulk-item';
            item.style.animationDelay = `${i * 0.05}s`;
            item.innerHTML = `
                <span class="bulk-item-password">${password}</span>
                <button class="bulk-item-copy" title="Copy" data-password="${password}">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="9" y="9" width="13" height="13" rx="2"/>
                        <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
                    </svg>
                </button>
            `;
            container.appendChild(item);

            item.querySelector('.bulk-item-copy').addEventListener('click', (e) => {
                this.copyToClipboard(e.currentTarget.dataset.password);
            });
        }
    }

    // --- History ---
    bindHistory() {
        document.getElementById('btn-clear-history').addEventListener('click', () => {
            HistoryManager.clear();
            this.renderHistory();
        });
    }

    renderHistory() {
        const history = HistoryManager.getAll();
        const list = document.getElementById('history-list');
        const empty = document.getElementById('history-empty');

        if (history.length === 0) {
            list.innerHTML = '';
            list.appendChild(empty.cloneNode(true));
            return;
        }

        list.innerHTML = history.map((item, index) => `
            <div class="history-item" style="animation-delay: ${index * 0.03}s">
                <div class="history-strength-dot" style="background: ${item.color}; box-shadow: 0 0 8px ${item.color}"></div>
                <span class="history-password">${item.masked}</span>
                <div class="history-meta">
                    <span class="history-score" style="color: ${item.color}">${item.score}/100</span>
                    <span class="history-date">${item.date}</span>
                </div>
                <button class="history-remove" data-index="${index}" title="Remove">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                </button>
            </div>
        `).join('');

        list.querySelectorAll('.history-remove').forEach(btn => {
            btn.addEventListener('click', () => {
                const index = parseInt(btn.dataset.index);
                HistoryManager.remove(index);
                this.renderHistory();
            });
        });
    }

    // --- Clipboard ---
    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            this.showToast('Copied to clipboard!');
        }).catch(() => {
            // Fallback
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.left = '-9999px';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            this.showToast('Copied to clipboard!');
        });
    }

    showToast(message) {
        const toast = document.getElementById('toast');
        document.getElementById('toast-text').textContent = message;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 2500);
    }
}

// =====================================
// Initialize Application
// =====================================
document.addEventListener('DOMContentLoaded', () => {
    new App();
});
