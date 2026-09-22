const PDXSecurity = (function() {
    const _KEY = "pdx_sec_shield_2026_x89a";

    function _sha256Raw(str) {
        function rightRotate(value, amount) { return (value >>> amount) | (value << (32 - amount)); }
        const mathPow = Math.pow;
        const maxWord = mathPow(2, 32);
        let i, j;
        const words = [];
        const asciiBitLength = str.length * 8;
        let hash = [], k = [], primeCounter = 0;
        const isPrime = {};
        for (let candidate = 2; primeCounter < 64; candidate++) {
            if (!isPrime[candidate]) {
                for (i = 0; i < 313; i += candidate) isPrime[i] = candidate;
                hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
                k[primeCounter++] = (mathPow(candidate, 1/3) * maxWord) | 0;
            }
        }
        str += '\x80';
        while (str.length % 64 - 56) str += '\x00';
        for (i = 0; i < str.length; i++) {
            j = str.charCodeAt(i);
            words[i >> 2] |= j << ((3 - i) % 4) * 8;
        }
        words[words.length] = ((asciiBitLength / maxWord) | 0);
        words[words.length] = (asciiBitLength) | 0;
        for (j = 0; j < words.length;) {
            const w = words.slice(j, j += 16);
            const oldHash = hash;
            hash = hash.slice(0, 8);
            for (i = 0; i < 64; i++) {
                const w15 = w[i - 15], w2 = w[i - 2];
                const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
                const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
                w[i] = (i < 16) ? w[i] : (w[i - 16] + s0 + w[i - 7] + s1) | 0;
                const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
                const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
                const temp1 = (hash[7] + (rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25)) + ch + k[i] + w[i]) | 0;
                const temp2 = ((rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22)) + maj) | 0;
                hash = [(temp1 + temp2) | 0].concat(hash);
                hash[4] = (hash[4] + temp1) | 0;
                hash.pop();
            }
            for (i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
        }
        let raw = '';
        for (i = 0; i < 8; i++) {
            for (let b = 3; b >= 0; b--) {
                raw += String.fromCharCode((hash[i] >> (b * 8)) & 255);
            }
        }
        return raw;
    }

    function _calcHmac(message, secret) {
        let key = secret;
        if (key.length > 64) key = _sha256Raw(key);
        while (key.length < 64) key += '\x00';
        let oKeyPad = '', iKeyPad = '';
        for (let i = 0; i < 64; i++) {
            oKeyPad += String.fromCharCode(key.charCodeAt(i) ^ 0x5c);
            iKeyPad += String.fromCharCode(key.charCodeAt(i) ^ 0x36);
        }
        const innerRaw = _sha256Raw(iKeyPad + message);
        const outerRaw = _sha256Raw(oKeyPad + innerRaw);
        let hex = '';
        for (let i = 0; i < outerRaw.length; i++) {
            const byte = outerRaw.charCodeAt(i);
            hex += (byte < 16 ? '0' : '') + byte.toString(16);
        }
        return hex;
    }

    async function sign(urlPath, existingHeaders = {}) {
        let pathOnly = urlPath || '';
        try {
            if (pathOnly.startsWith('http://') || pathOnly.startsWith('https://')) {
                pathOnly = new URL(pathOnly).pathname;
            } else {
                pathOnly = pathOnly.split('?')[0];
            }
        } catch(e) {
            pathOnly = pathOnly.split('?')[0];
        }

        const ts = Date.now().toString();
        const nonce = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
        const msg = `${pathOnly}:${ts}:${nonce}`;
        const signHash = _calcHmac(msg, _KEY);
        return {
            ...existingHeaders,
            'X-PDX-Timestamp': ts,
            'X-PDX-Nonce': nonce,
            'X-PDX-Sign': signHash
        };
    }

    function initGuardian() {
        let lastTime = Date.now();
        setInterval(() => {
            const now = Date.now();
            lastTime = now;
        }, 500);

        try {
            const observer = new MutationObserver((mutations) => {
                for (const m of mutations) {
                    for (const node of m.addedNodes) {
                        if (node && node.tagName === 'SCRIPT' && node.src) {
                            const isAllowed = node.src.includes(window.location.host) || 
                                              node.src.includes('cdnjs.cloudflare.com') || 
                                              node.src.includes('cdn.jsdelivr.net');
                            if (!isAllowed) {
                                node.remove();
                            }
                        }
                    }
                }
            });
            if (document.documentElement) {
                observer.observe(document.documentElement, { childList: true, subtree: true });
            }
        } catch(e) {}
    }

    initGuardian();

    const instance = {
        sign: sign,
        calcHmac: _calcHmac,
        version: "3.0"
    };

    window.PDXSecurity = instance;
    return instance;
})();
