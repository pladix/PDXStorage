document.addEventListener('DOMContentLoaded', () => {
    const API_URL = '';
    let adminToken = sessionStorage.getItem('pdx_admin_token') || localStorage.getItem('pdx_admin_token');
    let cachedUsers = [];
    let currentSelectedUserId = null;
    let currentSelectedUsername = '';

    const lockscreen = document.getElementById('admin-lockscreen');
    const dashboardContainer = document.getElementById('admin-dashboard-container');
    const loginForm = document.getElementById('admin-login-form');
    const passwordInput = document.getElementById('admin-password-input');
    const togglePwdBtn = document.getElementById('btn-toggle-admin-pwd');
    const searchInput = document.getElementById('admin-search-users');
    const refreshBtn = document.getElementById('btn-admin-refresh');
    const logoutBtn = document.getElementById('btn-admin-logout');

    const filesModal = document.getElementById('admin-files-modal');
    const closeFilesModalBtn = document.getElementById('btn-close-files-modal');
    const quotaModal = document.getElementById('admin-quota-modal');
    const closeQuotaModalBtn = document.getElementById('btn-close-quota-modal');
    const saveQuotaBtn = document.getElementById('btn-save-quota');
    const quotaGbInput = document.getElementById('input-custom-gb');

    function getAdminToken() {
        return adminToken || sessionStorage.getItem('pdx_admin_token') || localStorage.getItem('pdx_admin_token');
    }

    function setAdminToken(token) {
        adminToken = token;
        sessionStorage.setItem('pdx_admin_token', token);
    }

    function clearAdminToken() {
        adminToken = null;
        sessionStorage.removeItem('pdx_admin_token');
        localStorage.removeItem('pdx_admin_token');
    }

    async function secureAdminFetch(url, options = {}) {
        const opts = { ...options };
        opts.headers = opts.headers ? { ...opts.headers } : {};
        const token = getAdminToken();
        if (token && !opts.headers['Authorization']) {
            opts.headers['Authorization'] = `Bearer ${token}`;
        }
        if (window.PDXSecurity && typeof window.PDXSecurity.sign === 'function') {
            const urlObj = new URL(url, window.location.origin);
            opts.headers = await window.PDXSecurity.sign(urlObj.pathname, opts.headers);
        }
        return fetch(url, opts);
    }

    function formatBytes(bytes) {
        const b = Number(bytes) || 0;
        if (b === 0) return '0.00 MB';
        const mb = b / (1024 * 1024);
        if (mb < 1024) {
            return `${mb.toFixed(2)} MB`;
        }
        const gb = mb / 1024;
        return `${gb.toFixed(2)} GB`;
    }

    function escapeHtml(text) {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
        return String(text).replace(/[&<>"']/g, (m) => map[m]);
    }

    if (togglePwdBtn) {
        togglePwdBtn.addEventListener('click', () => {
            const isPwd = passwordInput.type === 'password';
            passwordInput.type = isPwd ? 'text' : 'password';
            togglePwdBtn.innerHTML = isPwd ? '<i class="fas fa-eye-slash"></i>' : '<i class="fas fa-eye"></i>';
        });
    }

    async function checkAuthOnLoad() {
        const token = getAdminToken();
        if (!token) {
            showLockscreen();
            return;
        }
        try {
            const res = await secureAdminFetch(`${API_URL}/api/admin/stats`);
            if (res.ok) {
                showDashboard();
                loadAdminData();
            } else {
                clearAdminToken();
                showLockscreen();
            }
        } catch (e) {
            clearAdminToken();
            showLockscreen();
        }
    }

    function showLockscreen() {
        lockscreen.classList.remove('hidden');
        dashboardContainer.classList.add('hidden');
        if (passwordInput) {
            passwordInput.value = '';
            passwordInput.focus();
        }
    }

    function showDashboard() {
        lockscreen.classList.add('hidden');
        dashboardContainer.classList.remove('hidden');
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = passwordInput.value.trim();
            if (!password) {
                if (window.toastr) toastr.warning("Informe a chave de segurança mestre.");
                return;
            }

            const submitBtn = document.getElementById('btn-admin-submit');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Validando...';
            }

            try {
                const res = await secureAdminFetch(`${API_URL}/api/admin/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });

                const data = await res.json();
                if (res.ok && data.access_token) {
                    setAdminToken(data.access_token);
                    if (window.toastr) {
                        toastr.success("Acesso administrativo autorizado!", "Console Master");
                    }
                    showDashboard();
                    loadAdminData();
                } else {
                    if (window.toastr) {
                        toastr.error(data.detail || "Chave de segurança incorreta.", "Acesso Negado");
                    }
                    passwordInput.value = '';
                    passwordInput.focus();
                }
            } catch (err) {
                if (window.toastr) {
                    toastr.error("Falha ao comunicar com o servidor.", "Erro");
                }
            } finally {
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="fas fa-unlock"></i> Desbloquear Painel';
                }
            }
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            try {
                await secureAdminFetch(`${API_URL}/api/logout`, { method: 'POST' });
            } catch (e) {}
            clearAdminToken();
            if (window.toastr) toastr.info("Sessão administrativa encerrada.");
            showLockscreen();
        });
    }

    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            loadAdminData();
            if (window.toastr) toastr.info("Dados do servidor atualizados.");
        });
    }

    async function loadAdminData() {
        await Promise.all([loadStats(), loadUsers()]);
    }

    async function loadStats() {
        const token = getAdminToken();
        if (!token) return;
        try {
            const res = await secureAdminFetch(`${API_URL}/api/admin/stats`);
            if (res.status === 401 || res.status === 403) {
                clearAdminToken();
                showLockscreen();
                return;
            }
            const stats = await res.json();
            document.getElementById('stat-total-users').textContent = stats.total_users || 0;
            document.getElementById('stat-storage-used').textContent = formatBytes(stats.total_used_bytes || 0);
            document.getElementById('stat-total-files').textContent = stats.total_files || 0;
            document.getElementById('stat-users-status').textContent = `${stats.active_users || 0} / ${stats.blocked_users || 0}`;
        } catch (e) {
            console.error(e);
        }
    }

    async function loadUsers() {
        const token = getAdminToken();
        if (!token) return;
        const tbody = document.getElementById('admin-users-tbody');
        try {
            const res = await secureAdminFetch(`${API_URL}/api/admin/users`);
            if (res.status === 401 || res.status === 403) {
                clearAdminToken();
                showLockscreen();
                return;
            }
            cachedUsers = await res.json();
            renderUsersTable(getFilteredUsers());
        } catch (e) {
            if (tbody) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="7" style="text-align: center; color: #f87171; padding: 2rem;">
                            <i class="fas fa-triangle-exclamation"></i> Falha ao carregar lista de usuários.
                        </td>
                    </tr>
                `;
            }
        }
    }

    function getFilteredUsers() {
        const term = (searchInput ? searchInput.value : '').toLowerCase().trim();
        if (!term) return cachedUsers;
        return cachedUsers.filter(u => String(u.username || '').toLowerCase().includes(term));
    }

    if (searchInput) {
        searchInput.addEventListener('input', () => {
            renderUsersTable(getFilteredUsers());
        });
    }

    function renderUsersTable(users) {
        const tbody = document.getElementById('admin-users-tbody');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (!users || users.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2.5rem;">
                        <i class="fas fa-user-slash" style="font-size: 2rem; opacity: 0.3; margin-bottom: 0.5rem; display: block;"></i>
                        Nenhum usuário encontrado.
                    </td>
                </tr>
            `;
            return;
        }

        users.forEach(u => {
            const tr = document.createElement('tr');
            const uid = Number(u.id);
            const username = String(u.username || '');
            const safeUsername = escapeHtml(username);
            const dateStr = u.created_at ? new Date(u.created_at).toLocaleDateString() : '-';
            const usedStr = formatBytes(u.used_bytes || 0);
            const quotaGb = ((u.quota_bytes || 21474836480) / (1024 * 1024 * 1024)).toFixed(0);
            const usedPercent = Math.min(100, (((u.used_bytes || 0) / (u.quota_bytes || 21474836480)) * 100)).toFixed(1);
            const isBlocked = Boolean(u.is_blocked);
            const filesCount = Number(u.files_count) || 0;

            tr.innerHTML = `
                <td><strong style="color: #94a3b8;">#${uid}</strong></td>
                <td>
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <i class="fas fa-circle-user" style="color: ${isBlocked ? '#f87171' : '#60a5fa'}; font-size: 1.1rem;"></i>
                        <span style="font-weight: 600; color: #fff;">${safeUsername}</span>
                    </div>
                </td>
                <td style="color: var(--text-muted); font-size: 0.85rem;">${dateStr}</td>
                <td>
                    <div style="display: flex; flex-direction: column; gap: 0.25rem;">
                        <div style="font-size: 0.85rem; font-weight: 500;">
                            ${usedStr} <span style="color: var(--text-muted);">/ ${quotaGb} GB</span>
                        </div>
                        <div class="admin-mini-meter">
                            <div class="admin-mini-fill" style="width: ${usedPercent}%; background: ${usedPercent > 90 ? '#ef4444' : '#3b82f6'};"></div>
                        </div>
                    </div>
                </td>
                <td>
                    <span class="admin-pill-badge">${filesCount} arquivo${filesCount !== 1 ? 's' : ''}</span>
                </td>
                <td>
                    ${isBlocked 
                        ? '<span class="status-badge status-blocked"><i class="fas fa-ban"></i> Bloqueado</span>' 
                        : '<span class="status-badge status-active"><i class="fas fa-check-circle"></i> Ativo</span>'
                    }
                </td>
                <td style="text-align: right;">
                    <div class="admin-actions-cell"></div>
                </td>
            `;

            const actionsCell = tr.querySelector('.admin-actions-cell');

            const btnFiles = document.createElement('button');
            btnFiles.className = 'btn-admin-action btn-admin-files';
            btnFiles.title = 'Ver Arquivos';
            btnFiles.innerHTML = `<i class="fas fa-folder-open"></i> Arquivos`;
            btnFiles.addEventListener('click', () => openUserFilesModal(uid, username));
            actionsCell.appendChild(btnFiles);

            const btnQuota = document.createElement('button');
            btnQuota.className = 'btn-admin-action btn-admin-quota';
            btnQuota.title = 'Ajustar Cota (+ GB)';
            btnQuota.innerHTML = `<i class="fas fa-database"></i> Cota`;
            btnQuota.addEventListener('click', () => openQuotaModal(uid, username, quotaGb));
            actionsCell.appendChild(btnQuota);

            const btnBlock = document.createElement('button');
            btnBlock.className = `btn-admin-action ${isBlocked ? 'btn-admin-unblock' : 'btn-admin-block'}`;
            btnBlock.title = isBlocked ? 'Desbloquear Usuário' : 'Bloquear Usuário';
            btnBlock.innerHTML = isBlocked ? `<i class="fas fa-unlock"></i> Desbloquear` : `<i class="fas fa-ban"></i> Bloquear`;
            btnBlock.addEventListener('click', () => toggleBlockUser(uid, username, isBlocked));
            actionsCell.appendChild(btnBlock);

            const btnDelete = document.createElement('button');
            btnDelete.className = 'btn-admin-action btn-admin-delete';
            btnDelete.title = 'Excluir Usuário e Arquivos';
            btnDelete.innerHTML = `<i class="fas fa-trash-can"></i>`;
            btnDelete.addEventListener('click', () => deleteUser(uid, username));
            actionsCell.appendChild(btnDelete);

            tbody.appendChild(tr);
        });
    }

    async function toggleBlockUser(userId, username, isCurrentlyBlocked) {
        const actionText = isCurrentlyBlocked ? 'desbloquear' : 'bloquear';
        if (!window.Swal) return;
        Swal.fire({
            title: `${isCurrentlyBlocked ? 'Desbloquear' : 'Bloquear'} Usuário?`,
            text: `Deseja realmente ${actionText} a conta de "${username}"?`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: isCurrentlyBlocked ? '#10b981' : '#ef4444',
            cancelButtonColor: '#334155',
            confirmButtonText: `Sim, ${actionText}`,
            cancelButtonText: 'Cancelar',
            background: '#0f172a',
            color: '#f8fafc'
        }).then(async (result) => {
            if (result.isConfirmed) {
                try {
                    const res = await secureAdminFetch(`${API_URL}/api/admin/users/${userId}/toggle-block`, {
                        method: 'POST'
                    });
                    const data = await res.json();
                    if (res.ok) {
                        if (window.toastr) toastr.success(data.message, "Status Atualizado");
                        loadAdminData();
                    } else {
                        if (window.toastr) toastr.error(data.detail || "Erro ao alterar status.", "Aviso");
                    }
                } catch (e) {
                    if (window.toastr) toastr.error("Falha na comunicação com o servidor.", "Erro");
                }
            }
        });
    }

    function openQuotaModal(userId, username, currentGb) {
        currentSelectedUserId = userId;
        currentSelectedUsername = username;
        document.getElementById('quota-modal-user').textContent = username;
        quotaGbInput.value = currentGb;
        quotaModal.classList.remove('hidden');
    }

    if (closeQuotaModalBtn) {
        closeQuotaModalBtn.addEventListener('click', () => {
            quotaModal.classList.add('hidden');
        });
    }

    document.querySelectorAll('.btn-quota-preset').forEach(btn => {
        btn.addEventListener('click', () => {
            quotaGbInput.value = btn.dataset.gb;
        });
    });

    if (saveQuotaBtn) {
        saveQuotaBtn.addEventListener('click', async () => {
            const gb = parseFloat(quotaGbInput.value);
            if (!gb || gb <= 0) {
                if (window.toastr) toastr.warning("Informe um valor válido em Gigabytes.");
                return;
            }
            try {
                saveQuotaBtn.disabled = true;
                saveQuotaBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Salvando...';
                const res = await secureAdminFetch(`${API_URL}/api/admin/users/${currentSelectedUserId}/quota`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ quota_gb: gb })
                });
                const data = await res.json();
                if (res.ok) {
                    if (window.toastr) toastr.success(data.message, "Cota Atualizada");
                    quotaModal.classList.add('hidden');
                    loadAdminData();
                } else {
                    if (window.toastr) toastr.error(data.detail || "Erro ao atualizar cota.", "Erro");
                }
            } catch (e) {
                if (window.toastr) toastr.error("Falha ao comunicar com o servidor.", "Erro");
            } finally {
                saveQuotaBtn.disabled = false;
                saveQuotaBtn.innerHTML = '<i class="fas fa-floppy-disk"></i> Salvar Nova Cota';
            }
        });
    }

    async function openUserFilesModal(userId, username) {
        currentSelectedUserId = userId;
        currentSelectedUsername = username;
        document.getElementById('modal-target-username').textContent = username;
        const box = document.getElementById('modal-files-list');
        box.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--text-muted);">
                <i class="fas fa-circle-notch fa-spin"></i> Carregando arquivos...
            </div>
        `;
        filesModal.classList.remove('hidden');

        try {
            const res = await secureAdminFetch(`${API_URL}/api/admin/users/${userId}/files`);
            if (!res.ok) {
                box.innerHTML = `<p style="color: #f87171; text-align: center; padding: 1.5rem;">Falha ao obter arquivos.</p>`;
                return;
            }
            const files = await res.json();
            box.innerHTML = '';
            if (files.length === 0) {
                box.innerHTML = `
                    <div style="text-align: center; padding: 2.5rem; color: var(--text-muted);">
                        <i class="fas fa-folder-open" style="font-size: 2rem; opacity: 0.3; margin-bottom: 0.5rem; display: block;"></i>
                        Este usuário ainda não possui nenhum arquivo armazenado.
                    </div>
                `;
                return;
            }

            files.forEach(f => {
                const item = document.createElement('div');
                item.className = 'admin-file-item';
                const fileId = Number(f.id);
                const filename = String(f.filename || '');
                const safeName = escapeHtml(filename);
                const sizeStr = formatBytes(f.size || 0);
                const dateStr = f.created_at ? new Date(f.created_at).toLocaleDateString() : '-';

                item.innerHTML = `
                    <div class="admin-file-info">
                        <div class="admin-file-name" title="${safeName}">
                            <i class="fas fa-file" style="color: #60a5fa; margin-right: 6px;"></i>
                            ${safeName}
                        </div>
                        <div class="admin-file-meta">${sizeStr} &bull; Armazenado em ${dateStr}</div>
                    </div>
                    <div class="admin-file-actions"></div>
                `;

                const actions = item.querySelector('.admin-file-actions');

                const btnDl = document.createElement('button');
                btnDl.className = 'btn-primary btn-sm';
                btnDl.innerHTML = `<i class="fas fa-download"></i> Baixar`;
                btnDl.addEventListener('click', () => adminDownloadFile(fileId, filename));
                actions.appendChild(btnDl);

                const btnDel = document.createElement('button');
                btnDel.className = 'btn-icon-danger';
                btnDel.title = 'Excluir Arquivo';
                btnDel.innerHTML = `<i class="fas fa-trash"></i>`;
                btnDel.addEventListener('click', () => adminDeleteFile(fileId, filename, item));
                actions.appendChild(btnDel);

                box.appendChild(item);
            });
        } catch (e) {
            box.innerHTML = `<p style="color: #f87171; text-align: center; padding: 1.5rem;">Erro de conexão.</p>`;
        }
    }

    if (closeFilesModalBtn) {
        closeFilesModalBtn.addEventListener('click', () => {
            filesModal.classList.add('hidden');
        });
    }

    function adminDownloadFile(fileId, filename) {
        const token = getAdminToken();
        const url = `${API_URL}/api/admin/files/${fileId}/download?token=${encodeURIComponent(token)}`;
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        if (window.toastr) toastr.info(`Iniciando download de ${filename}...`, "Download Admin");
    }

    async function adminDeleteFile(fileId, filename, itemEl) {
        if (!window.Swal) return;
        Swal.fire({
            title: 'Excluir Arquivo?',
            text: `Deseja apagar o arquivo "${filename}" do usuário definitivamente?`,
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
                    const res = await secureAdminFetch(`${API_URL}/api/admin/files/${fileId}`, {
                        method: 'DELETE'
                    });
                    const data = await res.json();
                    if (res.ok) {
                        if (window.toastr) toastr.success(data.message, "Arquivo Removido");
                        if (itemEl) itemEl.remove();
                        loadAdminData();
                    } else {
                        if (window.toastr) toastr.error(data.detail || "Erro ao excluir arquivo.", "Erro");
                    }
                } catch (e) {
                    if (window.toastr) toastr.error("Falha na comunicação com o servidor.", "Erro");
                }
            }
        });
    }

    async function deleteUser(userId, username) {
        if (!window.Swal) return;
        Swal.fire({
            title: 'Excluir Conta do Usuário?',
            text: `Atenção: A conta "${username}" e TODOS os seus arquivos serão excluídos permanentemente! Esta ação não tem retorno.`,
            icon: 'error',
            showCancelButton: true,
            confirmButtonColor: '#ef4444',
            cancelButtonColor: '#334155',
            confirmButtonText: 'Sim, excluir usuário definitivamente',
            cancelButtonText: 'Cancelar',
            background: '#0f172a',
            color: '#f8fafc'
        }).then(async (result) => {
            if (result.isConfirmed) {
                try {
                    const res = await secureAdminFetch(`${API_URL}/api/admin/users/${userId}`, {
                        method: 'DELETE'
                    });
                    const data = await res.json();
                    if (res.ok) {
                        if (window.toastr) toastr.success(data.message, "Usuário Excluído");
                        loadAdminData();
                    } else {
                        if (window.toastr) toastr.error(data.detail || "Erro ao excluir usuário.", "Erro");
                    }
                } catch (e) {
                    if (window.toastr) toastr.error("Falha na comunicação com o servidor.", "Erro");
                }
            }
        });
    }

    [filesModal, quotaModal].forEach(m => {
        if (m) {
            m.addEventListener('click', (e) => {
                if (e.target === m) m.classList.add('hidden');
            });
        }
    });

    checkAuthOnLoad();
});
