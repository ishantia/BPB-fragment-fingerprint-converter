document.addEventListener('DOMContentLoaded', () => {
    const convertBtn = document.getElementById('convertBtn');
    const copyBtn = document.getElementById('copyBtn');
    const subUrlInput = document.getElementById('subUrl');
    const statusMessage = document.getElementById('statusMessage');
    const outputGroup = document.getElementById('outputGroup');
    const outputResult = document.getElementById('outputResult');

    const FM_JSON = '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}]}';
    const CS_STR = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256';

    function showStatus(message, type) {
        statusMessage.textContent = message;
        statusMessage.className = type;
        statusMessage.classList.remove('hidden');
    }

    function hideStatus() {
        statusMessage.classList.add('hidden');
    }

    async function fetchWithFallback(url) {
        // Strip the hash fragment from the URL before fetching to prevent 400/408 errors from proxies or the origin server
        let cleanUrl = url;
        try {
            const parsed = new URL(url);
            cleanUrl = parsed.origin + parsed.pathname + parsed.search;
        } catch (e) {
            console.warn("Could not parse URL, using raw input.");
        }

        const proxies = [
            '', // Direct fetch
            'https://corsproxy.io/?',
            'https://api.allorigins.win/raw?url=',
            'https://api.codetabs.com/v1/proxy?quest='
        ];

        let lastError = null;

        for (const proxy of proxies) {
            try {
                // If using a proxy, encode the clean URL
                const targetUrl = proxy ? proxy + encodeURIComponent(cleanUrl) : cleanUrl;
                console.log("Attempting fetch via:", proxy ? "Proxy (" + proxy + ")" : "Direct");
                
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 30000); // Increased timeout to 30 seconds
                
                const response = await fetch(targetUrl, { 
                    signal: controller.signal,
                    headers: { 'Accept': 'text/plain, */*' }
                });
                
                clearTimeout(timeoutId);

                if (response.ok) {
                    return await response.text();
                } else {
                    // Treat 408 as a timeout to try the next proxy
                    throw new Error(`HTTP error ${response.status}`);
                }
            } catch (error) {
                console.warn(`Fetch failed via ${proxy ? "Proxy" : "Direct"}:`, error.message);
                lastError = error;
            }
        }
        
        throw new Error("All fetch attempts failed. The server might be blocking requests or taking too long. Last error: " + (lastError?.message || "Unknown error"));
    }

    function parseSubscription(text) {
        text = text.trim();
        if (!text) return [];
        
        let lines = text.split(/\r?\n/).map(l => l.trim()).filter(l => l);
        
        // If it looks like plain text configs, return as is
        if (lines.length > 0 && lines[0].includes('://')) {
            return lines;
        }
        
        // Otherwise attempt base64 decoding
        try {
            // Remove any whitespace (newlines, spaces) that might break atob
            let cleanB64 = text.replace(/\s+/g, '');
            let b64 = cleanB64.replace(/-/g, '+').replace(/_/g, '/');
            while (b64.length % 4) b64 += '=';
            
            // Handle utf-8 encoded base64 gracefully
            let decoded = decodeURIComponent(atob(b64).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
            
            return decoded.split(/\r?\n/).map(l => l.trim()).filter(l => l);
        } catch(e) {
            console.warn("Base64 decode failed, treating as plain text.", e);
            return lines;
        }
    }

    function processLines(lines) {
        return lines.map(line => {
            try {
                if (line.startsWith('vless://') || line.startsWith('trojan://')) {
                    const url = new URL(line);
                    
                    // Add the requested parameters
                    url.searchParams.set('fm', FM_JSON);
                    url.searchParams.set('cs', CS_STR);
                    url.searchParams.set('fp', 'unsafe');
                    
                    // URL searchParams.set automatically handles correct URL encoding,
                    // BUT it encodes spaces as '+' which breaks some V2Ray clients' JSON parsers.
                    // We must replace '+' with standard '%20'
                    return url.toString().replace(/\+/g, '%20');
                }
            } catch(e) {
                console.warn("Could not parse URL:", line, e);
            }
            return line; // Leave untouched if not vless/trojan or on error
        });
    }

    convertBtn.addEventListener('click', async () => {
        const inputVal = subUrlInput.value.trim();
        if (!inputVal) {
            showStatus("Please enter a valid subscription URL or raw config text.", "error");
            return;
        }

        hideStatus();
        outputGroup.classList.add('hidden');
        convertBtn.disabled = true;

        try {
            let rawText = "";
            
            // Check if it's a URL or raw text
            if (inputVal.startsWith('http://') || inputVal.startsWith('https://')) {
                showStatus("Fetching subscription...", "loading");
                rawText = await fetchWithFallback(inputVal);
            } else {
                showStatus("Processing raw text...", "loading");
                rawText = inputVal;
            }

            const lines = parseSubscription(rawText);
            
            if (rawText.toLowerCase().includes('<html')) {
                throw new Error("Server returned an HTML page (likely a Cloudflare block). Please open the link manually, copy the text, and paste it here directly.");
            }
            if (lines.length === 0) {
                throw new Error("Subscription is empty or invalid. Check your link or text.");
            }

            const modifiedLines = processLines(lines);
            
            // Join and display
            outputResult.value = modifiedLines.join('\n');
            outputGroup.classList.remove('hidden');
            showStatus(`Successfully converted ${modifiedLines.length} configurations!`, "success");
            
        } catch (error) {
            console.error(error);
            showStatus("Error: " + error.message, "error");
        } finally {
            convertBtn.disabled = false;
        }
    });

    copyBtn.addEventListener('click', () => {
        outputResult.select();
        outputResult.setSelectionRange(0, 99999); // For mobile devices
        try {
            navigator.clipboard.writeText(outputResult.value);
            const originalText = copyBtn.textContent;
            copyBtn.textContent = "Copied!";
            setTimeout(() => {
                copyBtn.textContent = originalText;
            }, 2000);
        } catch (err) {
            console.error('Failed to copy text: ', err);
            showStatus("Failed to copy text.", "error");
        }
    });
});
