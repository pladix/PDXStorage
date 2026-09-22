const API_URL = '';
const WS_PROTOCOL = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const WS_URL = (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + window.location.host + '/ws';
const CHUNK_SIZE = 1024 * 1024;

if (window.toastr) {
    toastr.options = {
        closeButton: true,
        progressBar: true,
        positionClass: "toast-top-right",
        timeOut: "3500",
        extendedTimeOut: "1000",
        showMethod: "fadeIn",
        hideMethod: "fadeOut"
    };
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, (m) => map[m]);
}

function getMediaInfo(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const images = ['png', 'jpg', 'jpeg', 'webp', 'gif', 'svg', 'bmp'];
    const videos = ['mp4', 'webm', 'ogg', 'mov', 'mkv', 'm4v'];
    const audios = ['mp3', 'wav', 'ogg', 'aac', 'flac', 'm4a'];
    const docs = ['txt', 'md', 'json', 'csv', 'log', 'js', 'html', 'css', 'py'];
    const pdfs = ['pdf'];

    if (images.includes(ext)) {
        const mime = ext === 'svg' ? 'image/svg+xml' : (ext === 'jpg' ? 'image/jpeg' : `image/${ext}`);
        return { type: 'image', icon: 'fa-image', color: '#10b981', mime, label: 'Foto', action: 'Visualizar', canPreview: true };
    }
    if (videos.includes(ext)) {
        const mime = ext === 'mov' ? 'video/quicktime' : `video/${ext}`;
        return { type: 'video', icon: 'fa-film', color: '#a855f7', mime, label: 'Vídeo', action: 'Assistir', canPreview: true };
    }
    if (audios.includes(ext)) {
        const mime = ext === 'mp3' ? 'audio/mpeg' : `audio/${ext}`;
        return { type: 'audio', icon: 'fa-headphones', color: '#f59e0b', mime, label: 'Áudio', action: 'Ouvir', canPreview: true };
    }
    if (docs.includes(ext)) {
        return { type: 'text', icon: 'fa-file-lines', color: '#38bdf8', mime: 'text/plain', label: 'Nota', action: 'Ler Nota', canPreview: true };
    }
    if (pdfs.includes(ext)) {
        return { type: 'pdf', icon: 'fa-file-pdf', color: '#ef4444', mime: 'application/pdf', label: 'PDF', action: 'Visualizar', canPreview: true };
    }
    return { type: 'other', icon: 'fa-file', color: '#94a3b8', mime: 'application/octet-stream', label: 'Arquivo', action: '', canPreview: false };
}

document.addEventListener('DOMContentLoaded', () => {
    let token = localStorage.getItem('pdx_token');
    if (!token && !window.location.pathname.includes('/login')) {
        window.location.href = '/login';
        return;
    }

    function getToken() {
        return localStorage.getItem('pdx_token') || token;
    }

    function setToken(newToken) {
        token = newToken;
        localStorage.setItem('pdx_token', newToken);
    }

    let keepAliveTimer = null;

    let refreshPromise = null;

    async function secureFetch(path, options = {}) {
        let headers = options.headers || {};
        const curToken = getToken();
        if (curToken && !headers['Authorization']) {
            headers['Authorization'] = `Bearer ${curToken}`;
        }
        if (window.PDXSecurity && window.PDXSecurity.sign) {
            headers = await window.PDXSecurity.sign(path, headers);
        }
        return fetch(`${API_URL}${path}`, {
            ...options,
            headers: headers
        });
    }

    async function extendUserSession() {
        const isKeepAlive = localStorage.getItem('pdx_keep_alive') === 'true';
        if (!isKeepAlive) return false;
        
        const curToken = getToken();
        if (!curToken) return false;

        if (refreshPromise) {
            return refreshPromise;
        }

        refreshPromise = (async () => {
            try {
                const res = await secureFetch('/api/refresh-token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                if (res.ok) {
                    const data = await res.json();
                    if (data.access_token) {
                        setToken(data.access_token);
                        return true;
                    }
                }
            } catch (e) {
            } finally {
                refreshPromise = null;
            }
            return false;
        })();

        return refreshPromise;
    }

    function initSessionKeepAlive() {
        const isKeepAlive = localStorage.getItem('pdx_keep_alive') === 'true';
        if (!isKeepAlive) return;

        extendUserSession();

        if (keepAliveTimer) clearInterval(keepAliveTimer);
        keepAliveTimer = setInterval(() => {
            extendUserSession();
        }, 10 * 60 * 1000);

        window.addEventListener('focus', () => extendUserSession());
        window.addEventListener('online', () => {
            if (window.toastr) {
                toastr.info("Conexão restabelecida. Sessão sincronizada.", "Online");
            }
            extendUserSession();
        });
    }

    initSessionKeepAlive();

    let activePreviewBlobUrl = null;

    document.getElementById('btn-logout')?.addEventListener('click', () => {
        if (window.Swal) {
            Swal.fire({
                title: 'Encerrar Sessão?',
                text: 'Sua chave de acesso temporária será removida deste dispositivo.',
                icon: 'question',
                showCancelButton: true,
                confirmButtonColor: '#ef4444',
                cancelButtonColor: '#334155',
                confirmButtonText: 'Sim, desconectar',
                cancelButtonText: 'Cancelar',
                background: '#0f172a',
                color: '#f8fafc'
            }).then(async (result) => {
                if (result.isConfirmed) {
                    if (keepAliveTimer) clearInterval(keepAliveTimer);
                    try {
                        await secureFetch('/api/logout', { method: 'POST' });
                    } catch(e) {}
                    localStorage.removeItem('pdx_token');
                    window.location.href = '/login';
                }
            });
        } else {
            if (keepAliveTimer) clearInterval(keepAliveTimer);
            localStorage.removeItem('pdx_token');
            window.location.href = '/login';
        }
    });

    loadStorageQuota();
    initFileFiltersAndSelection();
    loadFiles();

    async function loadStorageQuota() {
        try {
            const res = await secureFetch('/api/user/storage-quota');
            if (res.status === 401) {
                localStorage.removeItem('pdx_token');
                window.location.href = '/login';
                return;
            }
            const data = await res.json();
            
            const badge = document.getElementById('quota-percent-badge');
            const bar = document.getElementById('quota-meter-bar');
            const usageText = document.getElementById('quota-usage-text');
            const remText = document.getElementById('quota-remaining-text');

            if (badge && bar && usageText && remText) {
                const percent = data.used_percent;
                badge.textContent = `${percent}%`;
                bar.style.width = `${percent}%`;

                bar.className = 'quota-meter-fill';
                if (percent >= 90) {
                    bar.classList.add('danger');
                } else if (percent >= 70) {
                    bar.classList.add('warning');
                }

                const usedGb = (data.used_bytes / (1024 ** 3)).toFixed(2);
                const freeGb = (data.free_bytes / (1024 ** 3)).toFixed(2);
                usageText.textContent = `${usedGb} GB usados de 20.00 GB`;
                remText.textContent = `${freeGb} GB livres`;
            }

            const toggle = document.getElementById('cyclic-toggle');
            const cyclicLabel = document.getElementById('cyclic-status-label');
            if (toggle && cyclicLabel) {
                toggle.checked = Boolean(data.cyclic_storage);
                cyclicLabel.textContent = data.cyclic_storage ? 'Modo Cíclico: Ativado' : 'Modo Cíclico: Desativado';
                cyclicLabel.style.color = data.cyclic_storage ? '#10b981' : 'var(--text-muted)';
            }
        } catch (e) {
            console.error("Erro ao carregar cota de armazenamento:", e);
        }
    }

    document.getElementById('cyclic-toggle')?.addEventListener('change', async (e) => {
        const isChecked = e.target.checked;
        const cyclicLabel = document.getElementById('cyclic-status-label');
        try {
            const res = await secureFetch('/api/user/cyclic-storage', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cyclic_storage: isChecked })
            });
            const data = await res.json();
            if (res.ok) {
                if (window.toastr) {
                    toastr.success(data.message, "Armazenamento Cíclico");
                }
                if (cyclicLabel) {
                    cyclicLabel.textContent = isChecked ? 'Modo Cíclico: Ativado' : 'Modo Cíclico: Desativado';
                    cyclicLabel.style.color = isChecked ? '#10b981' : 'var(--text-muted)';
                }
            } else {
                e.target.checked = !isChecked;
                if (window.toastr) toastr.error("Não foi possível atualizar o modo cíclico.", "Erro");
            }
        } catch (err) {
            e.target.checked = !isChecked;
            if (window.toastr) toastr.error("Falha de conexão com o servidor.", "Erro");
        }
    });

    const profileModal = document.getElementById('profile-modal');
    const btnOpenProfile = document.getElementById('btn-open-profile');
    const btnCloseProfile = document.getElementById('btn-close-profile');

    const openProfile = async () => {
        try {
            const res = await secureFetch('/api/user/profile');
            if (res.status === 401) {
                localStorage.removeItem('pdx_token');
                window.location.href = '/login';
                return;
            }
            const data = await res.json();
            
            document.getElementById('prof-stat-user').textContent = data.username || '-';
            document.getElementById('prof-stat-files').textContent = data.total_files ?? 0;
            
            const mb = ((data.total_storage_bytes || 0) / (1024 * 1024)).toFixed(2);
            document.getElementById('prof-stat-size').textContent = `${mb} MB`;
            
            const badge2fa = document.getElementById('prof-stat-2fa');
            if (data.has_2fa) {
                badge2fa.innerHTML = '<span style="color: #10b981;"><i class="fas fa-shield-halved"></i> Ativa</span>';
            } else {
                badge2fa.innerHTML = '<span style="color: #94a3b8;"><i class="fas fa-shield-halved"></i> Inativa</span>';
            }

            const select = document.getElementById('retention-select');
            if (select) {
                select.value = String(data.retention_days || 0);
            }

            const toggle = document.getElementById('cyclic-toggle');
            const cyclicLabel = document.getElementById('cyclic-status-label');
            if (toggle && cyclicLabel) {
                toggle.checked = Boolean(data.cyclic_storage);
                cyclicLabel.textContent = data.cyclic_storage ? 'Modo Cíclico: Ativado' : 'Modo Cíclico: Desativado';
                cyclicLabel.style.color = data.cyclic_storage ? '#10b981' : 'var(--text-muted)';
            }

            profileModal.classList.remove('hidden');
        } catch (e) {
            if (window.toastr) {
                toastr.error("Não foi possível carregar as informações do perfil.", "Erro");
            }
        }
    };

    btnOpenProfile?.addEventListener('click', openProfile);
    btnCloseProfile?.addEventListener('click', () => profileModal.classList.add('hidden'));
    
    profileModal?.addEventListener('click', (e) => {
        if (e.target === profileModal) {
            profileModal.classList.add('hidden');
        }
    });

    document.getElementById('btn-save-retention')?.addEventListener('click', async () => {
        const days = parseInt(document.getElementById('retention-select').value) || 0;
        try {
            const res = await secureFetch('/api/user/retention', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ retention_days: days })
            });
            const data = await res.json();
            if (res.ok) {
                if (window.toastr) {
                    toastr.success(data.message || "Política atualizada!", "Auto-Limpeza");
                }
                loadFiles();
                loadStorageQuota();
            } else {
                if (window.toastr) {
                    toastr.error(data.detail || "Erro ao atualizar retenção.", "Aviso");
                }
            }
        } catch (e) {
            if (window.toastr) toastr.error("Falha ao comunicar com o servidor.", "Erro");
        }
    });

    document.getElementById('btn-change-password')?.addEventListener('click', async () => {
        const currentPassword = document.getElementById('pwd-current').value;
        const newPassword = document.getElementById('pwd-new').value;
        const confirmPassword = document.getElementById('pwd-confirm').value;

        if (!currentPassword || !newPassword || !confirmPassword) {
            if (window.toastr) toastr.warning("Preencha todos os campos de senha.", "Atenção");
            return;
        }

        if (newPassword !== confirmPassword) {
            if (window.toastr) toastr.error("A nova senha e a confirmação não coincidem.", "Divergência");
            return;
        }

        try {
            const res = await secureFetch('/api/user/change-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword
                })
            });
            const data = await res.json();
            if (res.ok) {
                document.getElementById('pwd-current').value = '';
                document.getElementById('pwd-new').value = '';
                document.getElementById('pwd-confirm').value = '';
                if (window.Swal) {
                    Swal.fire({
                        icon: 'success',
                        title: 'Senha Atualizada!',
                        text: 'Sua credencial de acesso foi modificada com sucesso.',
                        confirmButtonColor: '#3b82f6',
                        background: '#0f172a',
                        color: '#f8fafc'
                    });
                } else if (window.toastr) {
                    toastr.success("Senha alterada com sucesso!");
                }
            } else {
                if (window.toastr) {
                    toastr.error(data.detail || "Erro ao alterar senha.", "Falha");
                }
            }
        } catch (e) {
            if (window.toastr) toastr.error("Falha ao comunicar com o servidor.", "Erro");
        }
    });

    document.getElementById('btn-wipe-files')?.addEventListener('click', () => {
        if (!window.Swal) return;
        Swal.fire({
            title: 'Limpar Todos os Arquivos?',
            text: 'Todos os seus arquivos serão excluídos permanentemente do cofre. Esta ação não tem volta!',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#ef4444',
            cancelButtonColor: '#334155',
            confirmButtonText: 'Sim, limpar tudo',
            cancelButtonText: 'Cancelar',
            background: '#0f172a',
            color: '#f8fafc'
        }).then(async (result) => {
            if (result.isConfirmed) {
                try {
                    const res = await secureFetch('/api/user/files/wipe', {
                        method: 'DELETE'
                    });
                    const data = await res.json();
                    if (res.ok) {
                        if (window.toastr) toastr.success(data.message || "Arquivos excluídos com sucesso!", "Cofre Limpo");
                        openProfile();
                        loadFiles();
                        loadStorageQuota();
                    } else {
                        if (window.toastr) toastr.error(data.detail || "Erro ao limpar arquivos.", "Erro");
                    }
                } catch (e) {
                    if (window.toastr) toastr.error("Falha na solicitação.", "Erro");
                }
            }
        });
    });

    document.getElementById('btn-delete-account')?.addEventListener('click', () => {
        if (!window.Swal) return;
        Swal.fire({
            title: 'Excluir Conta Definitivamente?',
            text: 'Digite sua senha para confirmar a exclusão imediata de sua conta e de todos os seus dados.',
            input: 'password',
            inputPlaceholder: 'Digite sua senha atual',
            icon: 'error',
            showCancelButton: true,
            confirmButtonColor: '#ef4444',
            cancelButtonColor: '#334155',
            confirmButtonText: 'Excluir Permanentemente',
            cancelButtonText: 'Cancelar',
            background: '#0f172a',
            color: '#f8fafc'
        }).then(async (result) => {
            if (result.isConfirmed) {
                const password = result.value;
                if (!password) {
                    toastr.warning("Senha obrigatória para exclusão de conta.");
                    return;
                }
                try {
                    const res = await secureFetch('/api/user/delete-account', {
                        method: 'DELETE',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password })
                    });
                    const data = await res.json();
                    if (res.ok) {
                        localStorage.removeItem('pdx_token');
                        Swal.fire({
                            icon: 'success',
                            title: 'Conta Excluída',
                            text: 'Sua conta e seus dados foram apagados com sucesso.',
                            confirmButtonColor: '#3b82f6',
                            background: '#0f172a',
                            color: '#f8fafc'
                        }).then(() => {
                            window.location.href = '/login';
                        });
                    } else {
                        toastr.error(data.detail || "Senha incorreta ou erro ao excluir conta.", "Erro");
                    }
                } catch (e) {
                    toastr.error("Falha na comunicação com o servidor.", "Erro");
                }
            }
        });
    });

    const previewModal = document.getElementById('preview-modal');
    const btnClosePreview = document.getElementById('btn-close-preview');
    const mediaViewerBox = document.getElementById('media-viewer-box');
    const previewTitle = document.getElementById('preview-title');
    const previewFilesize = document.getElementById('preview-filesize');
    const btnPreviewDownload = document.getElementById('btn-preview-download');

    function closePreview() {
        if (previewModal) {
            previewModal.classList.add('hidden');
            const mediaEls = mediaViewerBox?.querySelectorAll('video, audio');
            mediaEls?.forEach(m => m.pause());
            if (mediaViewerBox) mediaViewerBox.innerHTML = '';
            if (activePreviewBlobUrl) {
                URL.revokeObjectURL(activePreviewBlobUrl);
                activePreviewBlobUrl = null;
            }
        }
    }

    btnClosePreview?.addEventListener('click', closePreview);
    previewModal?.addEventListener('click', (e) => {
        if (e.target === previewModal) closePreview();
    });

    window.openPreview = function(fileId, encodedFilename, totalSize) {
        const filename = decodeURIComponent(encodedFilename);
        const mediaInfo = getMediaInfo(filename);
        const safeName = escapeHtml(filename);
        const formattedSize = (Number(totalSize) / (1024 * 1024)).toFixed(2);

        previewTitle.innerHTML = `<i class="fas ${mediaInfo.icon}" style="color: ${mediaInfo.color};"></i> ${safeName}`;
        previewFilesize.textContent = `Tamanho: ${formattedSize} MB &bull; Criptografia AES-256`;
        btnPreviewDownload.onclick = () => downloadFile(fileId, encodedFilename, btnPreviewDownload);

        mediaViewerBox.innerHTML = `
            <div style="padding: 2.5rem 1rem; text-align: center; max-width: 360px; margin: 0 auto;">
                <i class="fas fa-circle-notch fa-spin fa-2x" style="color: #60a5fa; margin-bottom: 1rem;"></i>
                <p style="font-size: 0.95rem; font-weight: 500; color: #f1f5f9; margin-bottom: 0.5rem;">Carregando mídia protegida...</p>
                <div style="width: 100%; height: 8px; background: rgba(255,255,255,0.08); border-radius: 4px; overflow: hidden; margin: 0.75rem 0;">
                    <div id="preview-load-bar" style="width: 0%; height: 100%; background: linear-gradient(90deg, #3b82f6, #10b981); transition: width 0.1s ease;"></div>
                </div>
                <span id="preview-load-percent" style="font-size: 0.8rem; color: #94a3b8;">0%</span>
            </div>
        `;
        previewModal.classList.remove('hidden');

        const ws = new WebSocket(`${WS_URL}/download`);
        let receivedBytes = 0;
        const chunks = [];

        ws.onopen = () => {
            ws.send(JSON.stringify({ token: getToken(), file_id: fileId }));
        };

        ws.onmessage = (event) => {
            if (typeof event.data === 'string') {
                const data = JSON.parse(event.data);
                if (data.error) {
                    mediaViewerBox.innerHTML = `<p style="color: #ef4444; padding: 2rem;">Não foi possível carregar a pré-visualização: ${escapeHtml(data.error)}</p>`;
                    ws.close();
                }
            } else {
                chunks.push(event.data);
                receivedBytes += event.data.size;
                const percent = Math.min(100, Math.round((receivedBytes / totalSize) * 100));
                const loadedMb = (receivedBytes / (1024 * 1024)).toFixed(1);
                const progressEl = document.getElementById('preview-load-percent');
                const progressBarEl = document.getElementById('preview-load-bar');
                if (progressEl) progressEl.textContent = `${percent}% (${loadedMb} MB / ${formattedSize} MB)`;
                if (progressBarEl) progressBarEl.style.width = `${percent}%`;
            }
        };

        ws.onclose = () => {
            if (receivedBytes > 0) {
                if (activePreviewBlobUrl) {
                    URL.revokeObjectURL(activePreviewBlobUrl);
                }
                const blob = new Blob(chunks, { type: mediaInfo.mime });
                activePreviewBlobUrl = URL.createObjectURL(blob);

                if (mediaInfo.type === 'image') {
                    mediaViewerBox.innerHTML = `<img src="${activePreviewBlobUrl}" alt="${safeName}">`;
                } else if (mediaInfo.type === 'video') {
                    mediaViewerBox.innerHTML = `
                        <video src="${activePreviewBlobUrl}" controls autoplay playsinline class="preview-video">
                            Seu navegador não suporta reprodução direta deste formato de vídeo.
                        </video>
                    `;
                } else if (mediaInfo.type === 'audio') {
                    mediaViewerBox.innerHTML = `
                        <div class="media-audio-card">
                            <i class="fas fa-music fa-3x" style="color: #f59e0b;"></i>
                            <audio src="${activePreviewBlobUrl}" controls autoplay></audio>
                            <span style="font-size: 0.95rem; font-weight: 600; color: #f1f5f9;">${safeName}</span>
                        </div>
                    `;
                } else if (mediaInfo.type === 'text') {
                    const isTruncated = blob.size > 1024 * 1024;
                    const previewSlice = isTruncated ? blob.slice(0, 1024 * 1024) : blob;
                    previewSlice.text().then(text => {
                        const notice = isTruncated ? '\n\n[... Pré-visualização limitada aos primeiros 1MB. Baixe o arquivo completo para visualizá-lo na íntegra ...]' : '';
                        mediaViewerBox.innerHTML = `<pre class="media-text-viewer"><code>${escapeHtml(text + notice)}</code></pre>`;
                    }).catch(() => {
                        mediaViewerBox.innerHTML = `<p style="color: var(--text-muted); padding: 2rem;">Não foi possível ler o arquivo de texto.</p>`;
                    });
                } else if (mediaInfo.type === 'pdf') {
                    mediaViewerBox.innerHTML = `<iframe src="${activePreviewBlobUrl}" style="width:100%; height:65vh; border:none; border-radius: 8px;"></iframe>`;
                } else {
                    mediaViewerBox.innerHTML = `<p style="color: var(--text-muted); padding: 2rem;">Visualização indisponível para este tipo de arquivo. Utilize o botão abaixo para baixá-lo.</p>`;
                }
            }
        };

        ws.onerror = () => {
            mediaViewerBox.innerHTML = `<p style="color: #ef4444; padding: 2rem;">Falha na conexão de transferência de mídia.</p>`;
        };
    };

    const dropZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');

    if (dropZone) {
        dropZone.addEventListener('click', () => fileInput.click());
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                uploadFile(e.dataTransfer.files[0]);
            }
        });
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length) {
                uploadFile(fileInput.files[0]);
            }
        });
    }

    let allUserFiles = [];
    let currentFilterCategory = 'all';
    let currentSearchQuery = '';
    const selectedFileIds = new Set();

    function getFileCategory(filename) {
        const ext = (filename || '').split('.').pop().toLowerCase();
        const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico'];
        const videoExts = ['mp4', 'webm', 'mkv', 'avi', 'mov', 'wmv', 'flv'];
        const audioExts = ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a', 'wma'];
        const docExts = ['pdf', 'doc', 'docx', 'txt', 'log', 'md', 'json', 'csv', 'xml', 'rtf', 'odt'];
        const archiveExts = ['zip', 'rar', '7z', 'tar', 'gz', 'bz2'];

        if (imageExts.includes(ext)) return 'image';
        if (videoExts.includes(ext)) return 'video';
        if (audioExts.includes(ext)) return 'audio';
        if (docExts.includes(ext)) return 'doc';
        if (archiveExts.includes(ext)) return 'archive';
        return 'other';
    }

    function updateCategoryCounts() {
        let counts = { all: allUserFiles.length, image: 0, video: 0, audio: 0, doc: 0, archive: 0 };
        allUserFiles.forEach(f => {
            const cat = getFileCategory(f.filename);
            if (cat === 'image') counts.image++;
            else if (cat === 'video') counts.video++;
            else if (cat === 'audio') counts.audio++;
            else if (cat === 'doc') counts.doc++;
            else counts.archive++;
        });

        const setVal = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = String(val);
        };
        setVal('count-all', counts.all);
        setVal('count-image', counts.image);
        setVal('count-video', counts.video);
        setVal('count-audio', counts.audio);
        setVal('count-doc', counts.doc);
        setVal('count-archive', counts.archive);
    }

    function getFilteredFiles() {
        return allUserFiles.filter(f => {
            if (currentFilterCategory !== 'all') {
                const cat = getFileCategory(f.filename);
                if (currentFilterCategory === 'archive') {
                    if (cat !== 'archive' && cat !== 'other') return false;
                } else if (cat !== currentFilterCategory) {
                    return false;
                }
            }
            if (currentSearchQuery.trim() !== '') {
                const q = currentSearchQuery.toLowerCase().trim();
                const name = String(f.filename || '').toLowerCase();
                if (!name.includes(q)) return false;
            }
            return true;
        });
    }

    function updateSelectionToolbar(visibleFiles) {
        const selCount = selectedFileIds.size;
        const counterBadge = document.getElementById('selected-counter-badge');
        const btnDlSel = document.getElementById('btn-download-selected');
        const btnDelSel = document.getElementById('btn-delete-selected');
        const selectAllCb = document.getElementById('select-all-checkbox');

        if (counterBadge) {
            if (selCount > 0) {
                counterBadge.textContent = `${selCount} selecionado${selCount > 1 ? 's' : ''}`;
                counterBadge.classList.remove('hidden');
            } else {
                counterBadge.classList.add('hidden');
            }
        }

        if (btnDlSel) {
            if (selCount > 0) btnDlSel.classList.remove('hidden');
            else btnDlSel.classList.add('hidden');
        }

        if (btnDelSel) {
            if (selCount > 0) btnDelSel.classList.remove('hidden');
            else btnDelSel.classList.add('hidden');
        }

        if (selectAllCb) {
            const visCount = visibleFiles.length;
            if (visCount === 0) {
                selectAllCb.checked = false;
                selectAllCb.indeterminate = false;
            } else {
                const visibleSelectedCount = visibleFiles.filter(f => selectedFileIds.has(Number(f.id))).length;
                if (visibleSelectedCount === visCount) {
                    selectAllCb.checked = true;
                    selectAllCb.indeterminate = false;
                } else if (visibleSelectedCount > 0) {
                    selectAllCb.checked = false;
                    selectAllCb.indeterminate = true;
                } else {
                    selectAllCb.checked = false;
                    selectAllCb.indeterminate = false;
                }
            }
        }
    }

    function renderFileList() {
        const list = document.getElementById('file-list');
        if (!list) return;
        list.innerHTML = '';

        if (allUserFiles.length === 0) {
            list.innerHTML = `
                <div style="text-align: center; color: var(--text-muted); padding: 2.5rem 1rem;">
                    <i class="fas fa-folder-open" style="font-size: 2.5rem; opacity: 0.3; margin-bottom: 0.75rem; display: block;"></i>
                    <p style="font-size: 0.95rem;">Nenhum arquivo armazenado ainda.</p>
                    <span style="font-size: 0.8rem; opacity: 0.7;">Envie fotos, vídeos, músicas ou notas para protegê-los.</span>
                </div>
            `;
            updateSelectionToolbar([]);
            return;
        }

        const visibleFiles = getFilteredFiles();
        if (visibleFiles.length === 0) {
            list.innerHTML = `
                <div style="text-align: center; color: var(--text-muted); padding: 2.5rem 1rem;">
                    <i class="fas fa-magnifying-glass" style="font-size: 2.5rem; opacity: 0.3; margin-bottom: 0.75rem; display: block;"></i>
                    <p style="font-size: 0.95rem;">Nenhum arquivo encontrado.</p>
                    <span style="font-size: 0.8rem; opacity: 0.7;">Tente mudar o filtro de categoria ou o termo de pesquisa.</span>
                </div>
            `;
            updateSelectionToolbar([]);
            return;
        }

        visibleFiles.forEach(f => {
            const item = document.createElement('div');
            const fileId = Number(f.id);
            const isSelected = selectedFileIds.has(fileId);
            item.className = `file-item ${isSelected ? 'selected' : ''}`;
            const fileSize = Number(f.size) || 0;
            const filename = String(f.filename || '');
            const formattedSize = (fileSize / 1024 / 1024).toFixed(2);
            const dateStr = f.created_at ? new Date(f.created_at).toLocaleDateString() : '-';
            const safeName = escapeHtml(filename);
            const mediaInfo = getMediaInfo(filename);

            item.innerHTML = `
                <div class="file-main">
                    <label class="custom-check-label" style="margin: 0; padding: 0.2rem;" onclick="event.stopPropagation()">
                        <input type="checkbox" class="file-item-checkbox" data-file-id="${fileId}" ${isSelected ? 'checked' : ''}>
                        <span class="check-box-custom"></span>
                    </label>
                    <div class="file-info">
                        <h4>
                            <i class="fas ${mediaInfo.icon}" style="color: ${mediaInfo.color}; margin-right: 2px;"></i>
                            ${safeName}
                        </h4>
                        <p>${formattedSize} MB &bull; ${mediaInfo.label} &bull; Armazenado em ${dateStr}</p>
                    </div>
                </div>
                <div class="file-actions"></div>
            `;

            const cb = item.querySelector('.file-item-checkbox');
            cb.addEventListener('change', (e) => {
                if (e.target.checked) {
                    selectedFileIds.add(fileId);
                    item.classList.add('selected');
                } else {
                    selectedFileIds.delete(fileId);
                    item.classList.remove('selected');
                }
                updateSelectionToolbar(visibleFiles);
            });

            const actions = item.querySelector('.file-actions');

            if (mediaInfo.canPreview) {
                const btnPrev = document.createElement('button');
                btnPrev.className = 'btn-preview';
                btnPrev.innerHTML = `<i class="fas ${mediaInfo.icon}"></i> ${mediaInfo.action}`;
                btnPrev.addEventListener('click', (e) => {
                    e.stopPropagation();
                    openPreview(fileId, filename, fileSize);
                });
                actions.appendChild(btnPrev);
            }

            const btnDl = document.createElement('button');
            btnDl.className = `btn-primary btn-sm btn-dl-${fileId}`;
            btnDl.innerHTML = `<i class="fas fa-download"></i> Baixar`;
            btnDl.addEventListener('click', (e) => {
                e.stopPropagation();
                downloadFile(fileId, filename, btnDl);
            });
            actions.appendChild(btnDl);

            const btnDel = document.createElement('button');
            btnDel.className = 'btn-icon-danger';
            btnDel.title = 'Excluir Arquivo';
            btnDel.innerHTML = `<i class="fas fa-trash"></i>`;
            btnDel.addEventListener('click', (e) => {
                e.stopPropagation();
                deleteFile(fileId, filename);
            });
            actions.appendChild(btnDel);

            list.appendChild(item);
        });

        updateSelectionToolbar(visibleFiles);
    }

    function initFileFiltersAndSelection() {
        const searchInput = document.getElementById('file-search-input');
        const clearBtn = document.getElementById('btn-clear-search');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                currentSearchQuery = e.target.value;
                if (clearBtn) {
                    if (currentSearchQuery.length > 0) clearBtn.classList.remove('hidden');
                    else clearBtn.classList.add('hidden');
                }
                renderFileList();
            });
        }
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                if (searchInput) searchInput.value = '';
                currentSearchQuery = '';
                clearBtn.classList.add('hidden');
                renderFileList();
            });
        }

        const filterChips = document.querySelectorAll('.filter-chip');
        filterChips.forEach(chip => {
            chip.addEventListener('click', () => {
                filterChips.forEach(c => c.classList.remove('active'));
                chip.classList.add('active');
                currentFilterCategory = chip.dataset.category || 'all';
                renderFileList();
            });
        });

        const selectAllCb = document.getElementById('select-all-checkbox');
        if (selectAllCb) {
            selectAllCb.addEventListener('change', (e) => {
                const visibleFiles = getFilteredFiles();
                if (e.target.checked) {
                    visibleFiles.forEach(f => selectedFileIds.add(Number(f.id)));
                } else {
                    visibleFiles.forEach(f => selectedFileIds.delete(Number(f.id)));
                }
                renderFileList();
            });
        }

        const btnDlAll = document.getElementById('btn-download-all-zip');
        if (btnDlAll) {
            btnDlAll.addEventListener('click', () => {
                downloadAllZip(btnDlAll);
            });
        }

        const btnDlSel = document.getElementById('btn-download-selected');
        if (btnDlSel) {
            btnDlSel.addEventListener('click', () => {
                downloadSelectedFiles(btnDlSel);
            });
        }

        const btnDelSel = document.getElementById('btn-delete-selected');
        if (btnDelSel) {
            btnDelSel.addEventListener('click', () => {
                deleteSelectedFiles();
            });
        }
    }

    function downloadAllZip(btnEl) {
        if (allUserFiles.length === 0) {
            if (window.toastr) toastr.info("Nenhum arquivo armazenado para compactar.", "Aviso");
            return;
        }

        const btn = btnEl || document.getElementById('btn-download-all-zip');
        const originalHtml = btn ? btn.innerHTML : null;
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Compactando cofre...';
            btn.style.opacity = '0.85';
        }

        if (window.toastr) {
            toastr.info("Compactando todos os seus arquivos em um único .ZIP...", "Backup Completo", { timeOut: 3500 });
        }

        const curToken = getToken();
        const downloadUrl = `${API_URL}/api/files/download-zip?token=${encodeURIComponent(curToken)}`;

        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = `pdxstorage_backup_${Date.now()}.zip`;
        document.body.appendChild(link);
        link.click();
        link.remove();

        setTimeout(() => {
            if (btn) {
                btn.innerHTML = '<i class="fas fa-check"></i> Baixando!';
                setTimeout(() => {
                    btn.innerHTML = originalHtml || '<i class="fas fa-file-zipper"></i> Baixar Tudo (.ZIP)';
                    btn.disabled = false;
                    btn.style.opacity = '1';
                }, 1800);
            }
        }, 1200);
    }

    function downloadSelectedFiles(btnEl) {
        if (selectedFileIds.size === 0) return;

        if (selectedFileIds.size === 1) {
            const singleId = Array.from(selectedFileIds)[0];
            const file = allUserFiles.find(f => Number(f.id) === singleId);
            if (file) {
                downloadFile(file.id, file.filename);
            }
            return;
        }

        const idsArray = Array.from(selectedFileIds);
        const count = idsArray.length;

        if (window.Swal) {
            Swal.fire({
                title: 'Baixar Selecionados',
                text: `Deseja compactar os ${count} arquivos selecionados em um único .ZIP ou baixar individualmente?`,
                icon: 'question',
                showCancelButton: true,
                showDenyButton: true,
                confirmButtonColor: '#3b82f6',
                denyButtonColor: '#10b981',
                cancelButtonColor: '#334155',
                confirmButtonText: '<i class="fas fa-file-zipper"></i> Compactar (.ZIP)',
                denyButtonText: '<i class="fas fa-download"></i> Baixar Individuais',
                cancelButtonText: 'Cancelar',
                background: '#0f172a',
                color: '#f8fafc'
            }).then((result) => {
                if (result.isConfirmed) {
                    triggerZipDownload(idsArray, btnEl);
                } else if (result.isDenied) {
                    idsArray.forEach((fid, index) => {
                        const f = allUserFiles.find(item => Number(item.id) === fid);
                        if (f) {
                            setTimeout(() => {
                                downloadFile(f.id, f.filename);
                            }, index * 400);
                        }
                    });
                }
            });
        } else {
            triggerZipDownload(idsArray, btnEl);
        }
    }

    function triggerZipDownload(idsArray, btnEl) {
        const btn = btnEl || document.getElementById('btn-download-selected');
        const originalHtml = btn ? btn.innerHTML : null;
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Compactando...';
        }

        if (window.toastr) {
            toastr.info(`Compactando ${idsArray.length} arquivos selecionados...`, "Download ZIP", { timeOut: 3000 });
        }

        const curToken = getToken();
        const idsParam = idsArray.join(',');
        const downloadUrl = `${API_URL}/api/files/download-zip?ids=${encodeURIComponent(idsParam)}&token=${encodeURIComponent(curToken)}`;

        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = `pdx_selecionados_${Date.now()}.zip`;
        document.body.appendChild(link);
        link.click();
        link.remove();

        setTimeout(() => {
            if (btn) {
                btn.innerHTML = '<i class="fas fa-check"></i> Baixando!';
                setTimeout(() => {
                    btn.innerHTML = originalHtml || '<i class="fas fa-download"></i> Baixar Selecionados';
                    btn.disabled = false;
                }, 1800);
            }
        }, 1200);
    }

    function deleteSelectedFiles() {
        const idsArray = Array.from(selectedFileIds);
        if (idsArray.length === 0) return;

        if (!window.Swal) return;
        Swal.fire({
            title: `Excluir ${idsArray.length} arquivo${idsArray.length > 1 ? 's' : ''}?`,
            text: 'Os arquivos selecionados serão excluídos permanentemente do cofre.',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#ef4444',
            cancelButtonColor: '#334155',
            confirmButtonText: 'Sim, excluir todos',
            cancelButtonText: 'Cancelar',
            background: '#0f172a',
            color: '#f8fafc'
        }).then(async (result) => {
            if (result.isConfirmed) {
                try {
                    const res = await secureFetch('/api/files/batch-delete', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ file_ids: idsArray })
                    });
                    const data = await res.json();
                    if (res.ok) {
                        if (window.toastr) {
                            toastr.success(data.message || "Arquivos excluídos com sucesso!", "Exclusão em Lote");
                        }
                        selectedFileIds.clear();
                        loadFiles();
                        loadStorageQuota();
                    } else {
                        if (window.toastr) {
                            toastr.error(data.detail || "Erro ao excluir arquivos selecionados.", "Erro");
                        }
                    }
                } catch (e) {
                    if (window.toastr) toastr.error("Falha na comunicação com o servidor.", "Erro");
                }
            }
        });
    }

    async function loadFiles() {
        if (!document.getElementById('file-list')) return;
        try {
            const res = await secureFetch('/api/files');
            if (res.status === 401) {
                localStorage.removeItem('pdx_token');
                window.location.href = '/login';
                return;
            }
            allUserFiles = await res.json();
            const currentValidIds = new Set(allUserFiles.map(f => Number(f.id)));
            for (const id of Array.from(selectedFileIds)) {
                if (!currentValidIds.has(id)) selectedFileIds.delete(id);
            }
            updateCategoryCounts();
            renderFileList();
        } catch (e) {
            console.error("Erro ao carregar arquivos:", e);
        }
    }

    window.deleteFile = function(fileId, filename) {
        const safeName = filename && filename.includes('%') ? decodeURIComponent(filename) : filename;
        if (!window.Swal) return;
        Swal.fire({
            title: 'Excluir Arquivo?',
            text: `Deseja apagar permanentemente o arquivo "${escapeHtml(safeName)}" do cofre?`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#ef4444',
            cancelButtonColor: '#334155',
            confirmButtonText: 'Sim, excluir',
            cancelButtonText: 'Cancelar',
            background: '#0f172a',
            color: '#f8fafc'
        }).then(async (result) => {
            if (result.isConfirmed) {
                try {
                    const res = await secureFetch(`/api/files/${fileId}`, {
                        method: 'DELETE'
                    });
                    const data = await res.json();
                    if (res.ok) {
                        if (window.toastr) toastr.success("Arquivo excluído com sucesso!", "Excluído");
                        loadFiles();
                        loadStorageQuota();
                    } else {
                        if (window.toastr) toastr.error(data.detail || "Erro ao excluir arquivo.", "Erro");
                    }
                } catch (e) {
                    if (window.toastr) toastr.error("Falha ao comunicar com o servidor.", "Erro");
                }
            }
        });
    };

    window.uploadFile = async function(file) {
        const MAX_SIZE = 250 * 1024 * 1024;
        if (file.size > MAX_SIZE) {
            if (window.toastr) {
                toastr.error("O arquivo ultrapassa o limite máximo individual permitido de 250MB.", "Arquivo Muito Grande");
            }
            return;
        }

        await extendUserSession();

        const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
        const ws = new WebSocket(`${WS_URL}/upload`);

        document.getElementById('upload-progress-container').classList.remove('hidden');
        document.getElementById('upload-filename').textContent = file.name;
        const progressBar = document.getElementById('upload-progress-bar');
        const progressText = document.getElementById('upload-percentage');
        
        progressBar.style.width = '0%';
        progressText.textContent = '0%';

        if (window.toastr) {
            toastr.info(`Iniciando transferência segura de ${file.name}...`, "Upload");
        }

        ws.onopen = () => {
            ws.send(JSON.stringify({ token: getToken() }));
            ws.send(JSON.stringify({
                filename: file.name,
                total_size: file.size,
                total_chunks: totalChunks
            }));

            let currentChunk = 0;
            const sendNextChunk = () => {
                if (currentChunk >= totalChunks) return;
                if (ws.readyState !== WebSocket.OPEN) return;
                if (ws.bufferedAmount > 2 * 1024 * 1024) {
                    setTimeout(sendNextChunk, 50);
                    return;
                }
                const start = currentChunk * CHUNK_SIZE;
                const end = Math.min(start + CHUNK_SIZE, file.size);
                const chunk = file.slice(start, end);
                
                const reader = new FileReader();
                reader.onload = (e) => {
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(e.target.result);
                        currentChunk++;
                    }
                };
                reader.readAsArrayBuffer(chunk);
            };

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.error) {
                    if (window.toastr) {
                        toastr.error(data.error, "Falha no Envio");
                    }
                    if (window.Swal && data.error.includes("20GB")) {
                        Swal.fire({
                            icon: 'warning',
                            title: 'Limite de 20GB Atingido',
                            text: data.error,
                            confirmButtonText: 'Abrir Meu Perfil',
                            showCancelButton: true,
                            cancelButtonText: 'Fechar',
                            confirmButtonColor: '#3b82f6',
                            background: '#0f172a',
                            color: '#f8fafc'
                        }).then((res) => {
                            if (res.isConfirmed) openProfile();
                        });
                    }
                    document.getElementById('upload-progress-container').classList.add('hidden');
                    ws.close();
                } else if (data.progress) {
                    const percent = Math.round(data.progress * 100);
                    progressBar.style.width = percent + '%';
                    progressText.textContent = percent + '%';
                    sendNextChunk(); 
                } else if (data.status === 'completed') {
                    progressBar.style.width = '100%';
                    progressText.textContent = '100%';
                    if (window.toastr) {
                        toastr.success("Arquivo protegido e armazenado com sucesso!", "Upload Concluído");
                    }
                    setTimeout(() => {
                        document.getElementById('upload-progress-container').classList.add('hidden');
                        loadFiles();
                        loadStorageQuota();
                    }, 1200);
                }
            };

            sendNextChunk();
        };
        
        ws.onerror = () => {
            if (window.toastr) {
                toastr.error("Conexão interrompida durante o envio.", "Erro de Comunicação");
            }
            document.getElementById('upload-progress-container').classList.add('hidden');
        };
    };

    window.addEventListener('beforeunload', () => {
        if (keepAliveTimer) clearInterval(keepAliveTimer);
    });

    window.downloadFile = function(fileId, encodedFilename, btnEl) {
        const filename = decodeURIComponent(encodedFilename);
        const btn = btnEl || document.querySelector(`.btn-dl-${fileId}`);
        const originalHtml = btn ? btn.innerHTML : null;

        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Localizando...';
            btn.style.opacity = '0.85';
            btn.style.pointerEvents = 'none';
        }

        if (window.toastr) {
            toastr.info(`Localizando e iniciando download de ${filename}...`, "Download Rápido", { timeOut: 2500 });
        }

        const curToken = getToken();
        const downloadUrl = `${API_URL}/api/files/${fileId}/download?token=${encodeURIComponent(curToken)}`;

        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();

        setTimeout(() => {
            if (btn) {
                btn.innerHTML = '<i class="fas fa-check"></i> Iniciado!';
                setTimeout(() => {
                    btn.innerHTML = originalHtml || '<i class="fas fa-download"></i> Baixar';
                    btn.disabled = false;
                    btn.style.opacity = '1';
                    btn.style.pointerEvents = 'auto';
                }, 1400);
            }
        }, 800);
    };
});