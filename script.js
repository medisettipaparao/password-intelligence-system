document.addEventListener('DOMContentLoaded', () => {

    const passwordInput = document.getElementById('password-input');
    const strengthMeter = document.getElementById('strength-meter');
    const strengthText = document.getElementById('strength-text');
    const pwnedStatus = document.getElementById('pwned-status');
    const entropyScore = document.getElementById('entropy-score');
    const feedbackSection = document.getElementById('feedback-section');
    const feedbackText = document.getElementById('feedback-text');
    const chartContainer = document.getElementById('chart-container');
    const visibilityToggle = document.getElementById('visibility-toggle');
    const eyeOpen = document.getElementById('eye-open');
    const eyeClosed = document.getElementById('eye-closed');
    const generateButton = document.getElementById('generate-button');
    const infoButton = document.getElementById('info-button');
    const infoModal = document.getElementById('info-modal');
    const closeModalButton = document.getElementById('close-modal-button');

    let typingTimer;
    const DONE_TYPING_INTERVAL = 500;
    const STRENGTH_CONFIG = {
        0: { text: 'Compromised', color: 'bg-red-600', hex: '#dc2626' },
        1: { text: 'Predictable', color: 'bg-orange-500', hex: '#f97316' },
        2: { text: 'Vulnerable', color: 'bg-yellow-400', hex: '#facc15' },
        3: { text: 'Resilient', color: 'bg-blue-500', hex: '#3b82f6' },
        4: { text: 'Fortress', color: 'bg-green-500', hex: '#22c55e' }
    };

    let svg, xScale, yScale, xAxis, yAxis;
    const chartMargin = { top: 20, right: 20, bottom: 40, left: 60 };
    let chartWidth, chartHeight;

    function initChart() {
        const containerRect = chartContainer.getBoundingClientRect();
        chartWidth = containerRect.width - chartMargin.left - chartMargin.right;
        chartHeight = containerRect.height - chartMargin.top - chartMargin.bottom;

        svg = d3.select("#chart-container").append("svg")
            .attr("width", '100%').attr("height", '100%')
            .attr('viewBox', `0 0 ${containerRect.width} ${containerRect.height}`)
            .append("g").attr("transform", `translate(${chartMargin.left},${chartMargin.top})`);

        xScale = d3.scaleBand().range([0, chartWidth]).padding(0.4);
        yScale = d3.scaleLog().range([chartHeight, 0]).base(10);
        xAxis = svg.append("g").attr("class", "x-axis").attr("transform", `translate(0,${chartHeight})`);
        yAxis = svg.append("g").attr("class", "y-axis");
        updateChart([]);
    }

    passwordInput.addEventListener('input', () => {
        clearTimeout(typingTimer);
        const password = passwordInput.value;
        analyzePassword(password);
        if (password) {
            pwnedStatus.innerHTML = `<div class="loader"></div><span class="ml-2 text-gray-400">Checking breach database...</span>`;
            typingTimer = setTimeout(() => checkPwnedPassword(password), DONE_TYPING_INTERVAL);
        }
    });

    visibilityToggle.addEventListener('click', () => {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        eyeOpen.classList.toggle('hidden', !isPassword);
        eyeClosed.classList.toggle('hidden', isPassword);
    });

    generateButton.addEventListener('click', () => {
        const newPassword = generateSecurePassword();
        passwordInput.value = newPassword;
        passwordInput.dispatchEvent(new Event('input'));
    });

    infoButton.addEventListener('click', () => {
        infoModal.classList.remove('opacity-0', 'pointer-events-none', 'scale-95');
    });

    closeModalButton.addEventListener('click', () => {
        infoModal.classList.add('opacity-0', 'pointer-events-none', 'scale-95');
    });

    window.addEventListener('resize', () => {
        d3.select("#chart-container svg").remove();
        initChart();
        analyzePassword(passwordInput.value);
    });

    function analyzePassword(password) {
        if (!password) { resetUI(); return; }

        const zxcvbnResult = zxcvbn(password);
        const score = zxcvbnResult.score;
        const strength = STRENGTH_CONFIG[score];

        strengthMeter.style.width = `${(score + 1) * 20}%`;
        strengthMeter.className = `strength-meter-bar h-2.5 rounded-full ${strength.color}`;
        strengthText.textContent = strength.text;
        strengthText.className = `text-2xl font-bold ${strength.color.replace('bg-', 'text-')}`;

        calculateAndDisplayEntropy(password);
        updateFeedback(zxcvbnResult);

        const crackData = [
            { profile: 'Script Kiddie', timeStr: zxcvbnResult.crack_times_display.online_throttling_100_per_hour, color: strength.hex },
            { profile: 'Cybercriminal', timeStr: zxcvbnResult.crack_times_display.offline_fast_hashing_1e10_per_second, color: strength.hex },
            { profile: 'State Actor', timeStr: zxcvbnResult.crack_times_display.offline_slow_hashing_1e4_per_second, color: strength.hex }
        ];
        updateChart(crackData);
    }

    async function checkPwnedPassword(password) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            const hashBuffer = await crypto.subtle.digest('SHA-1', data);
            const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
            const prefix = hashHex.substring(0, 5);
            const suffix = hashHex.substring(5).toUpperCase();

            const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
            if (!response.ok) throw new Error('API request failed.');
            const text = await response.text();

            const found = text.split('\r\n').find(line => line.split(':')[0] === suffix);
            const count = found ? parseInt(found.split(':')[1]) : 0;

            if (count > 0) {
                pwnedStatus.innerHTML = `<div class="status-indicator bg-red-500"></div><span class="text-red-400 font-bold">EXPOSED! Found in ${count.toLocaleString()} breaches.</span>`;
            } else {
                pwnedStatus.innerHTML = `<div class="status-indicator bg-green-500"></div><span class="text-green-400">Clear. Not found in known breaches.</span>`;
            }
        } catch (error) {
            pwnedStatus.innerHTML = `<div class="status-indicator bg-yellow-500"></div><span class="text-yellow-400">Could not check breach status.</span>`;
        }
    }

    function resetUI() {
        strengthMeter.style.width = '0%';
        strengthText.textContent = '-';
        strengthText.className = 'text-2xl font-bold';
        entropyScore.textContent = '0';
        pwnedStatus.innerHTML = `<div class="status-indicator bg-gray-500"></div><span class="text-gray-400">Awaiting input...</span>`;
        feedbackSection.classList.add('hidden');
        updateChart([]);
    }

    function calculateAndDisplayEntropy(password) {
        let charsetSize = 0;
        if (/[a-z]/.test(password)) charsetSize += 26;
        if (/[A-Z]/.test(password)) charsetSize += 26;
        if (/[0-9]/.test(password)) charsetSize += 10;
        if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
        const entropy = (charsetSize === 0) ? 0 : Math.round(password.length * Math.log2(charsetSize));
        entropyScore.textContent = entropy.toLocaleString();
    }

    function updateFeedback(result) {
        const feedback = (result.feedback.warning ? `<strong>${result.feedback.warning}.</strong> ` : '') + result.feedback.suggestions.join(' ');
        if (feedback.trim()) {
            feedbackText.innerHTML = feedback;
            feedbackSection.classList.remove('hidden');
        } else {
            feedbackSection.classList.add('hidden');
        }
    }

    function generateSecurePassword() {
        const length = 16;
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
        let password = "";
        const randomValues = new Uint32Array(length);
        crypto.getRandomValues(randomValues);
        for (let i = 0; i < length; i++) {
            password += charset[randomValues[i] % charset.length];
        }
        return password;
    }

    function updateChart(data) {
        const parseCrackTimeToSeconds = (timeStr) => {
            if (timeStr === 'instant') return 0.01;
            const parts = timeStr.split(' ');
            const value = parseFloat(parts[0]);
            const unit = parts[1] || '';
            const multipliers = { second: 1, minute: 60, hour: 3600, day: 86400, month: 2.628e+6, year: 3.154e+7, century: 3.154e+9 };
            const multiplier = Object.keys(multipliers).find(key => unit.startsWith(key)) || 'second';
            return (multipliers[multiplier] || 1) * value;
        };
        const formatYAxisLabel = (seconds) => {
            if (seconds < 60) return `${seconds.toFixed(0)}s`;
            if (seconds < 3600) return `${(seconds/60).toFixed(0)}m`;
            if (seconds < 86400) return `${(seconds/3600).toFixed(0)}h`;
            if (seconds < 3.154e+7) return `${(seconds/86400).toFixed(0)}d`;
            const years = seconds / 3.154e+7;
            if (years < 1000) return `${years.toFixed(0)}y`;
            if (years < 1e6) return `${(years/1000).toFixed(0)}k y`;
            if (years < 1e9) return `${(years/1e6).toFixed(0)}M y`;
            return `${(years/1e9).toFixed(0)}B y`;
        };

        data.forEach(d => d.timeSec = parseCrackTimeToSeconds(d.timeStr) || 0.1);
        const maxTime = d3.max(data, d => d.timeSec);
        yScale.domain([0.1, Math.max(1e12, maxTime || 1e12)]);
        xScale.domain(data.map(d => d.profile));

        xAxis.transition().duration(300).call(d3.axisBottom(xScale)).selectAll("text").attr("class", "axis-text");
        yAxis.transition().duration(300).call(d3.axisLeft(yScale).ticks(5, d => formatYAxisLabel(d))).selectAll("text").attr("class", "axis-text");

        const bars = svg.selectAll(".bar").data(data, d => d.profile);
        bars.enter().append("rect").attr("class", "bar").attr("x", d => xScale(d.profile)).attr("width", xScale.bandwidth()).attr("y", chartHeight).attr("height", 0)
            .merge(bars).transition().duration(300).attr("x", d => xScale(d.profile)).attr("y", d => yScale(d.timeSec)).attr("height", d => chartHeight - yScale(d.timeSec)).attr("fill", d => d.color);
        bars.exit().remove();

        const labels = svg.selectAll(".bar-label").data(data, d => d.profile);
        labels.enter().append("text").attr("class", "bar-label").attr("text-anchor", "middle")
            .merge(labels).transition().duration(300).attr("x", d => xScale(d.profile) + xScale.bandwidth() / 2).attr("y", d => yScale(d.timeSec) - 5).text(d => d.timeStr);
        labels.exit().remove();
    }

    initChart();
});
