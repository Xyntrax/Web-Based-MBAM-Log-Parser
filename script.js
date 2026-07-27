(function() {
    const TOP_LEVEL_ALLOWLIST = new Set([
        "applicationVersion",
        "componentsUpdatePackageVersion",
        "detectionDateTime",
        "os",
        "sourceDetails",
        "threats",
        "threatsDetected"
    ]);

    const SOURCE_DETAILS_ALLOWLIST = new Set([
        "objectsScanned",
        "scanStartTime",
        "scanEndTime",
        "scanResult",
        "scanOptions"
    ]);

    const SCAN_OPTIONS_ALLOWLIST = new Set([
        "scanType"
    ]);

    const THREAT_ALLOWLIST = new Set([
        "threatName",
        "mainTrace",
        "linkedTraces"
    ]);

    const TRACE_ALLOWLIST = new Set([
        "archiveMember",
        "cleanAction",
        "cleanResult",
        "cleanTime",
        "dateOfCreation",
        "dateOfModification",
        "objectMD5",
        "objectSha256",
        "objectSize",
        "objectType",
        "objectPath"
    ]);

    function filterScanOptions(data) {
        const result = {};
        for (const key of Object.keys(data)) {
            if (SCAN_OPTIONS_ALLOWLIST.has(key)) {
                result[key] = data[key];
            }
        }
        return result;
    }

    function filterSourceDetails(data) {
        const result = {};
        for (const key of Object.keys(data)) {
            if (SOURCE_DETAILS_ALLOWLIST.has(key)) {
                if (key === "scanOptions") {
                    result[key] = filterScanOptions(data[key]);
                } else {
                    result[key] = data[key];
                }
            }
        }
        return result;
    }

    function filterTrace(data) {
        if (typeof data !== "object" || data === null || Array.isArray(data)) {
            return data;
        }
        const result = {};
        for (const key of Object.keys(data)) {
            if (TRACE_ALLOWLIST.has(key)) {
                result[key] = data[key];
            }
        }
        return result;
    }

    function filterLinkedTraces(data) {
        if (!Array.isArray(data)) {
            return data;
        }
        const result = [];
        for (const trace of data) {
            if (typeof trace === "object" && trace !== null && !Array.isArray(trace)) {
                result.push(filterTrace(trace));
            } else {
                result.push(trace);
            }
        }
        return result;
    }

    function filterThreats(data) {
        if (!Array.isArray(data)) {
            return data;
        }
        const result = [];
        for (const threat of data) {
            if (typeof threat !== "object" || threat === null || Array.isArray(threat)) {
                result.push(threat);
                continue;
            }
            const filtered = {};
            for (const key of Object.keys(threat)) {
                if (THREAT_ALLOWLIST.has(key)) {
                    if (key === "mainTrace") {
                        filtered[key] = filterTrace(threat[key]);
                    } else if (key === "linkedTraces") {
                        filtered[key] = filterLinkedTraces(threat[key]);
                    } else {
                        filtered[key] = threat[key];
                    }
                }
            }
            result.push(filtered);
        }
        return result;
    }

    function filterLog(data) {
        if (typeof data !== "object" || data === null || Array.isArray(data)) {
            return data;
        }
        const result = {};
        for (const key of Object.keys(data)) {
            if (TOP_LEVEL_ALLOWLIST.has(key)) {
                if (key === "sourceDetails") {
                    result[key] = filterSourceDetails(data[key]);
                } else if (key === "threats") {
                    result[key] = filterThreats(data[key]);
                } else {
                    result[key] = data[key];
                }
            }
        }
        return result;
    }

    function parseMBAMLog(content) {
        let data;
        try {
            data = JSON.parse(content);
            return filterLog(data);
        } catch (e) {
            const lines = content.split('\n');
            if (lines.length > 1) {
                for (let i = 1; i < Math.min(5, lines.length); i++) {
                    try {
                        const jsonContent = lines.slice(i).join('\n');
                        data = JSON.parse(jsonContent);
                        return filterLog(data);
                    } catch (inner) {
                        continue;
                    }
                }
            }
            throw new Error("Could not parse JSON from the uploaded file.");
        }
    }

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    }

    function generateRandomFilename() {
        const hex = Math.random().toString(16).substring(2, 14);
        return `MBAM_Parsed_${hex}.json`;
    }

    function extractThreatCount(data) {
        if (data && data.threatsDetected !== undefined) {
            return data.threatsDetected;
        }
        if (data && data.threats && Array.isArray(data.threats)) {
            return data.threats.length;
        }
        return 0;
    }

    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const fileList = document.getElementById('fileList');
    const parseBtn = document.getElementById('parseBtn');
    const results = document.getElementById('results');
    const stats = document.getElementById('stats');
    const downloads = document.getElementById('downloads');

    const files = {};

    function addFile(file) {
        const name = file.name;
        if (!name.toLowerCase().endsWith('.json')) {
            alert('Only .json files are supported. Please select MBAM scan logs.');
            return;
        }
        if (files[name]) {
            delete files[name];
        }
        files[name] = { file, name, size: file.size };
        renderFileList();
        updateParseButton();
        results.classList.remove('visible');
    }

    function removeFile(name) {
        delete files[name];
        renderFileList();
        updateParseButton();
        results.classList.remove('visible');
    }

    function renderFileList() {
        const names = Object.keys(files);
        if (names.length === 0) {
            fileList.innerHTML = '';
            return;
        }
        let html = '';
        for (const name of names) {
            const f = files[name];
            html += `
                <div class="file-item">
                    <span style="display:flex;align-items:center;">
                        <span class="file-icon">JSON</span>
                        <span class="name">${escapeHtml(name)}</span>
                        <span class="size">${formatSize(f.size)}</span>
                    </span>
                    <button class="remove-btn" data-name="${escapeHtml(name)}" title="Remove file">&times;</button>
                </div>
            `;
        }
        fileList.innerHTML = html;
        fileList.querySelectorAll('.remove-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const name = this.getAttribute('data-name');
                removeFile(name);
            });
        });
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function updateParseButton() {
        const count = Object.keys(files).length;
        parseBtn.disabled = count === 0;
        parseBtn.textContent = count === 0 ? 'PARSE LOGS' : `PARSE LOGS (${count})`;
    }

    dropZone.addEventListener('dragover', function(e) {
        e.preventDefault();
        this.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', function(e) {
        e.preventDefault();
        this.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', function(e) {
        e.preventDefault();
        this.classList.remove('dragover');
        const dropped = e.dataTransfer.files;
        for (const f of dropped) {
            addFile(f);
        }
    });

    fileInput.addEventListener('change', function() {
        if (this.files && this.files.length > 0) {
            for (const f of this.files) {
                addFile(f);
            }
        }
        this.value = '';
    });

    dropZone.addEventListener('click', function(e) {
        if (e.target.tagName !== 'INPUT') {
            fileInput.click();
        }
    });

    parseBtn.addEventListener('click', async function() {
        const fileNames = Object.keys(files);
        if (fileNames.length === 0) return;

        this.disabled = true;
        this.textContent = 'PROCESSING...';

        const resultsData = {};
        let totalProcessed = 0;
        let totalFailed = 0;
        let totalThreats = 0;

        try {
            for (const name of fileNames) {
                const f = files[name];
                try {
                    const content = await f.file.text();
                    const parsed = parseMBAMLog(content);
                    resultsData[name] = parsed;
                    totalProcessed++;
                    totalThreats += extractThreatCount(parsed);
                } catch (err) {
                    resultsData[name] = { error: err.message };
                    totalFailed++;
                }
            }

            const totalFiles = fileNames.length;

            stats.innerHTML = `
                <div class="stat-item">
                    <div class="label">Parsed</div>
                    <div class="value green">${totalProcessed}</div>
                </div>
                <div class="stat-item">
                    <div class="label">Errors</div>
                    <div class="value red">${totalFailed}</div>
                </div>
                <div class="stat-item">
                    <div class="label">Threats</div>
                    <div class="value blue">${totalThreats}</div>
                </div>
            `;

            let downloadHtml = '';
            let hasSuccess = false;
            for (const name of fileNames) {
                const data = resultsData[name];
                if (data.error) {
                    continue;
                }
                hasSuccess = true;
                const outputFilename = generateRandomFilename();
                const jsonStr = JSON.stringify(data, null, 4);
                const blob = new Blob([jsonStr], { type: 'application/json' });
                const url = URL.createObjectURL(blob);

                downloadHtml += `
                    <a href="${url}" download="${outputFilename}" class="download-btn">
                        <span class="icon">&#x1F4C4;</span> ${outputFilename}
                        <span class="meta">from ${escapeHtml(name)}</span>
                    </a>
                `;
            }

            if (!hasSuccess) {
                downloadHtml = '<p style="color:#ff3333; padding:10px; font-family: monospace;">No logs were successfully parsed.</p>';
            }

            downloads.innerHTML = downloadHtml;
            results.classList.add('visible');

        } catch (err) {
            alert('Error processing files: ' + err.message);
            console.error(err);
        } finally {
            this.disabled = false;
            const count = Object.keys(files).length;
            this.textContent = count === 0 ? 'PARSE LOGS' : `PARSE LOGS (${count})`;
        }
    });

    updateParseButton();
})();