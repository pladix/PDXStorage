const PDXShield = (function() {
    const _tokens = {}; 
    
    function _h(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            let char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; 
        }
        return hash.toString(36);
    }

    function _gF() {
        const d = [
            navigator.hardwareConcurrency || 1,
            window.screen.width,
            window.screen.height,
            new Date().getTimezoneOffset(),
            navigator.userAgent
        ].join('|');
        return _h(d);
    }

    async function _signHMAC(message, secret) {
        if (window.PDXSecurity && typeof window.PDXSecurity.calcHmac === 'function') {
            return window.PDXSecurity.calcHmac(message, secret);
        }
        if (window.CryptoJS && window.CryptoJS.HmacSHA256) {
            try {
                return window.CryptoJS.HmacSHA256(message, secret).toString();
            } catch(e) {}
        }
        return "fallback";
    }

    function initWidget(containerId, submitButtonId) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        _tokens[containerId] = null;
        let _sT = 0;

        const trackId = `${containerId}_track`;
        const handleId = `${containerId}_handle`;
        const labelId = `${containerId}_label`;

        container.innerHTML = `
            <div class="pdx-slider-track" id="${containerId}_container">
                <div class="pdx-slider-progress" id="${trackId}"></div>
                <div class="pdx-slider-handle" id="${handleId}">
                    <i class="fas fa-chevron-right"></i>
                </div>
                <div class="pdx-slider-label" id="${labelId}">
                    Deslize para verificar
                </div>
            </div>
        `;

        const btn = document.getElementById(handleId);
        const track = document.getElementById(trackId);
        const label = document.getElementById(labelId);
        const submitBtn = document.getElementById(submitButtonId);

        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.style.opacity = '0.55';
            submitBtn.style.cursor = 'not-allowed';
        }

        let dragging = false;
        let startX = 0;

        const onStart = (clientX) => {
            dragging = true;
            _sT = Date.now();
            startX = clientX;
            btn.style.transition = 'none';
            label.style.opacity = '0.3';
        };

        const onMove = (clientX) => {
            if (!dragging) return;
            const rect = container.getBoundingClientRect();
            let x = clientX - rect.left - 22;
            const max = rect.width - 44;
            
            if (x < 0) x = 0;
            if (x > max) x = max;
            
            btn.style.left = x + 'px';
            track.style.width = (x + 22) + 'px';
        };

        const onEnd = async () => {
            if (!dragging) return;
            dragging = false;
            btn.style.transition = 'left 0.25s ease';
            track.style.transition = 'width 0.25s ease';
            
            const max = container.offsetWidth - 44;
            const current = parseInt(btn.style.left) || 0;
            
            if (current >= max * 0.88) {
                const _k2 = Math.max(80, Date.now() - _sT);
                const _v90x = _gF();
                const _ts = Date.now();
                const secret = window.PDX_CSRF_TOKEN || "fallback";
                const message = `${_ts}:${_v90x}:${_k2}`;
                
                label.textContent = "Verificando...";
                
                const _sig = await _signHMAC(message, secret);
                
                let reqHeaders = { 'Content-Type': 'application/json' };
                if (window.PDXSecurity && typeof window.PDXSecurity.sign === 'function') {
                    reqHeaders = await window.PDXSecurity.sign('/api/core/_hx99_auth', reqHeaders);
                }
                
                try {
                    const res = await fetch('/api/core/_hx99_auth', {
                        method: 'POST',
                        credentials: 'include',
                        headers: reqHeaders,
                        body: JSON.stringify({
                            _v90x,
                            _k2,
                            _ts,
                            _sig,
                            _csrf: window.PDX_CSRF_TOKEN || ''
                        })
                    });
                    
                    const data = await res.json();
                    
                    if (res.ok && data._htk) {
                        _tokens[containerId] = data._htk;
                        container.innerHTML = `
                            <div class="pdx-verified-badge">
                                <i class="fas fa-circle-check"></i> Verificação concluída
                            </div>
                        `;
                        if (submitBtn) {
                            submitBtn.disabled = false;
                            submitBtn.style.opacity = '1';
                            submitBtn.style.cursor = 'pointer';
                        }
                    } else {
                        throw new Error(data.detail || "Falha na verificação");
                    }
                } catch(e) {
                    btn.style.left = '0px';
                    track.style.width = '0%';
                    label.textContent = "Deslize para verificar";
                    label.style.opacity = '1';
                    if (window.toastr) {
                        toastr.warning(e.message || "Repita o movimento suavemente para validar.", "Atenção");
                    }
                }
            } else {
                btn.style.left = '0px';
                track.style.width = '0%';
                label.style.opacity = '1';
            }
        };

        btn.addEventListener('mousedown', (e) => onStart(e.clientX));
        window.addEventListener('mousemove', (e) => onMove(e.clientX));
        window.addEventListener('mouseup', onEnd);

        btn.addEventListener('touchstart', (e) => {
            if (e.touches && e.touches.length > 0) {
                onStart(e.touches[0].clientX);
            }
        }, { passive: true });

        window.addEventListener('touchmove', (e) => {
            if (dragging && e.touches && e.touches.length > 0) {
                onMove(e.touches[0].clientX);
            }
        }, { passive: true });

        window.addEventListener('touchend', onEnd);
    }

    function initAll() {
        if (document.getElementById('login-pdx-shield-container')) {
            initWidget('login-pdx-shield-container', 'btn-login');
        }
        if (document.getElementById('register-pdx-shield-container')) {
            initWidget('register-pdx-shield-container', 'btn-register');
        }
    }

    document.addEventListener('DOMContentLoaded', initAll);

    const module = {
        init: initWidget,
        initAll: initAll,
        getToken: (containerId) => {
            if (containerId) return _tokens[containerId];
            return _tokens['login-pdx-shield-container'] || _tokens['register-pdx-shield-container'] || null;
        }
    };
    
    window.PDXShield = module;
    return module;
})();
