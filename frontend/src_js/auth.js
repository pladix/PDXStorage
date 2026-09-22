const API_URL = '';
let csrfToken = null;
let current2FAChallengeToken = null;

if (window.toastr) {
    toastr.options = {
        closeButton: true,
        progressBar: true,
        positionClass: "toast-top-right",
        timeOut: "4000",
        extendedTimeOut: "1000",
        showMethod: "fadeIn",
        hideMethod: "fadeOut"
    };
}

document.addEventListener('DOMContentLoaded', async () => {
    try {
        const res = await fetch(`${API_URL}/api/csrf-token`, { credentials: 'include' });
        const data = await res.json();
        csrfToken = data.csrf_token;
        window.PDX_CSRF_TOKEN = csrfToken;
    } catch (e) {}

    const token = localStorage.getItem('pdx_token');
    if (token && window.location.pathname.includes('login')) {
        window.location.href = '/dashboard';
        return;
    }

    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const login2faStepForm = document.getElementById('login-2fa-step-form');
    const setup2faForm = document.getElementById('setup-2fa-form');
    const authTitle = document.getElementById('auth-title');
    const authSubtitle = document.getElementById('auth-subtitle');
    
    document.getElementById('show-register')?.addEventListener('click', () => {
        loginForm.classList.add('hidden');
        login2faStepForm?.classList.add('hidden');
        registerForm.classList.remove('hidden');
        authTitle.textContent = "Criar Conta";
        authSubtitle.textContent = "Armazenamento pessoal protegido com criptografia";
        if (window.PDXShield) {
            window.PDXShield.init('register-pdx-shield-container', 'btn-register');
        }
    });

    const switchToLogin = () => {
        registerForm.classList.add('hidden');
        login2faStepForm?.classList.add('hidden');
        setup2faForm?.classList.add('hidden');
        loginForm.classList.remove('hidden');
        authTitle.textContent = "PDXStorage";
        authSubtitle.textContent = "Cofre de Arquivos em Nuvem Privada";
        if (window.PDXShield) {
            window.PDXShield.init('login-pdx-shield-container', 'btn-login');
        }
    };

    document.getElementById('show-login')?.addEventListener('click', switchToLogin);
    document.getElementById('btn-back-login')?.addEventListener('click', switchToLogin);

    document.getElementById('btn-login')?.addEventListener('click', async () => {
        const username = document.getElementById('login-username').value.trim();
        const password = document.getElementById('login-password').value;

        if (!username || !password) {
            if (window.toastr) {
                toastr.warning("Por favor, preencha o nome de usuário e a senha.", "Dados Incompletos");
            }
            return;
        }

        const htk = (window.PDXShield) ? window.PDXShield.getToken('login-pdx-shield-container') : null;
        if (!htk) {
            if (window.toastr) {
                toastr.warning("Por favor, deslize a barra de verificação antes de entrar.", "Verificação Necessária");
            }
            return;
        }

        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);

        let reqHeaders = {
            'X-CSRF-Token': csrfToken || '',
            'X-Human-Token': htk || ''
        };
        if (window.PDXSecurity && window.PDXSecurity.sign) {
            reqHeaders = await window.PDXSecurity.sign('/token', reqHeaders);
        }

        try {
            const res = await fetch(`${API_URL}/token`, {
                method: 'POST',
                credentials: 'include',
                headers: reqHeaders,
                body: formData
            });

            const data = await res.json();

            if (res.ok) {
                if (data.require_2fa) {
                    current2FAChallengeToken = data.challenge_token;
                    loginForm.classList.add('hidden');
                    login2faStepForm.classList.remove('hidden');
                    authTitle.textContent = "Proteção 2FA";
                    authSubtitle.textContent = "Confirmação de identidade em duas etapas";
                    if (window.toastr) {
                        toastr.info("Digite o código gerado pelo seu autenticador.", "2FA Detectado");
                    }
                    setTimeout(() => document.getElementById('step-2fa-code')?.focus(), 200);
                    return;
                }

                const rememberMe = document.getElementById('remember-me')?.checked ?? true;
                localStorage.setItem('pdx_keep_alive', rememberMe ? 'true' : 'false');

                if (window.toastr) {
                    toastr.success("Acesso autorizado com sucesso!", "Bem-vindo");
                }
                localStorage.setItem('pdx_token', data.access_token);
                window.location.href = '/dashboard';
            } else {
                const errorMsg = data.detail || "Nome de usuário ou senha incorretos.";
                if (window.toastr) {
                    toastr.error(errorMsg, "Acesso Negado");
                }
                if (window.PDXShield) {
                    window.PDXShield.init('login-pdx-shield-container', 'btn-login');
                }
            }
        } catch (e) {
            if (window.toastr) {
                toastr.error("Não foi possível conectar ao servidor. Verifique sua conexão.", "Falha de Conexão");
            }
        }
    });

    document.getElementById('btn-submit-step-2fa')?.addEventListener('click', async () => {
        const code = document.getElementById('step-2fa-code').value.trim();

        if (!code || code.length < 6) {
            if (window.toastr) {
                toastr.warning("Digite o código de 6 dígitos do autenticador.", "Código Incompleto");
            }
            return;
        }

        let reqHeaders = { 'Content-Type': 'application/json' };
        if (window.PDXSecurity && window.PDXSecurity.sign) {
            reqHeaders = await window.PDXSecurity.sign('/token/2fa', reqHeaders);
        }

        try {
            const res = await fetch(`${API_URL}/token/2fa`, {
                method: 'POST',
                headers: reqHeaders,
                body: JSON.stringify({
                    challenge_token: current2FAChallengeToken,
                    code: code
                })
            });

            const data = await res.json();

            if (res.ok && data.access_token) {
                const rememberMe = document.getElementById('remember-me')?.checked ?? true;
                localStorage.setItem('pdx_keep_alive', rememberMe ? 'true' : 'false');

                if (window.toastr) {
                    toastr.success("Identidade confirmada com sucesso!", "2FA Válido");
                }
                localStorage.setItem('pdx_token', data.access_token);
                window.location.href = '/dashboard';
            } else {
                if (window.toastr) {
                    toastr.error(data.detail || "Código 2FA incorreto ou expirado.", "Erro de Validação");
                }
            }
        } catch (e) {
            if (window.toastr) {
                toastr.error("Erro ao validar código com o servidor.", "Falha");
            }
        }
    });

    document.getElementById('btn-register')?.addEventListener('click', async () => {
        const username = document.getElementById('reg-username').value.trim();
        const password = document.getElementById('reg-password').value;

        if (!username || !password) {
            if (window.toastr) {
                toastr.warning("Por favor, preencha o usuário e uma senha segura.", "Campos Obrigatórios");
            }
            return;
        }

        const htk = (window.PDXShield) ? window.PDXShield.getToken('register-pdx-shield-container') : null;
        if (!htk) {
            if (window.toastr) {
                toastr.warning("Por favor, conclua a verificação de segurança antes de prosseguir.", "Verificação Necessária");
            }
            return;
        }

        let reqHeaders = {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken || '',
            'X-Human-Token': htk || ''
        };
        if (window.PDXSecurity && window.PDXSecurity.sign) {
            reqHeaders = await window.PDXSecurity.sign('/register', reqHeaders);
        }

        try {
            const res = await fetch(`${API_URL}/register`, {
                method: 'POST',
                credentials: 'include',
                headers: reqHeaders,
                body: JSON.stringify({ username, password })
            });

            const data = await res.json();

            if (res.ok) {
                if (data.access_token) {
                    localStorage.setItem('pdx_token', data.access_token);
                    localStorage.setItem('pdx_keep_alive', 'true');
                    
                    if (window.toastr) {
                        toastr.success("Conta criada e autenticada com sucesso! Acessando cofre...", "Bem-vindo");
                    }
                    if (window.Swal) {
                        Swal.fire({
                            icon: 'success',
                            title: 'Conta Criada com Sucesso!',
                            text: 'Seu cofre seguro de 20GB foi liberado. Entrando automaticamente...',
                            timer: 1600,
                            showConfirmButton: false,
                            background: '#0f172a',
                            color: '#f8fafc'
                        }).then(() => {
                            window.location.href = '/dashboard';
                        });
                    } else {
                        window.location.href = '/dashboard';
                    }
                    return;
                }

                if (window.toastr) {
                    toastr.success(data.message || "Usuário criado com sucesso!", "Cadastro Concluído");
                }
                switchToLogin();
            } else {
                const errorMsg = data.detail || "Não foi possível concluir o cadastro.";
                if (window.toastr) {
                    toastr.error(errorMsg, "Aviso");
                }
                if (window.PDXShield) {
                    window.PDXShield.init('register-pdx-shield-container', 'btn-register');
                }
            }
        } catch (e) {
            if (window.toastr) {
                toastr.error("Falha ao comunicar com o servidor.", "Erro de Rede");
            }
        }
    });

    document.getElementById('skip-2fa')?.addEventListener('click', () => {
        window.location.href = '/dashboard';
    });
});
