# PDXStorage — Nuvem Privada com Deduplicação e Criptografia AES-256-GCM

> **Projeto Open Source distribuído por pladixoficial ([t.me/pladixoficial](https://t.me/pladixoficial))**

O **PDXStorage** é um cofre de armazenamento em nuvem privada de alta performance projetado para oferecer confidencialidade militar, deduplicação em blocos e máxima segurança em aplicações modernas.

---

## 🌟 Principais Recursos

- **Criptografia AES-256-GCM**: Todos os arquivos enviados são fragmentados em blocos (chunks de 1MB) e cifrados individualmente no disco com chave simétrica mestre.
- **Deduplicação Inteligente**: Blocos com o mesmo hash SHA-256 são armazenados apenas uma vez no disco físico, otimizando o consumo de espaço para múltiplos usuários.
- **Console Administrativo (`/admin`)**:
  - Painel de controle mestre com métricas de consumo de disco em tempo real.
  - Gestão de contas: ajuste de cota personalizada (GB), bloqueio/desbloqueio imediato, listagem e download de arquivos de qualquer conta e exclusão total de dados.
- **PDX Security Shield 3.0**:
  - **Assinatura Criptográfica HMAC Dinâmica**: Todas as requisições cliente/servidor são assinadas com tolerância temporal e proteção anti-replay contra bots, automações e scraping (`curl`, Postman).
  - **JavaScript Ofuscado e Anti-Engenharia Reversa**: Código cliente compilado com achatamento de fluxo de controle (Control Flow Flattening), matrizes criptografadas RC4/Base64 e bloqueio contra depuração/DevTools.
  - **Verificação Humana Física (Anti-Bot Slider)**: Desafio de segurança físico com análise de trajetória e temporização.
  - **Autenticação em Duas Etapas (2FA TOTP)**: Compatível com Google Authenticator, Authy e apps padrão RFC 6238.
  - **Revogação Ativa de Sessão (Token Blacklist)**: Encerramento real de tokens JWT ao deslogar ou alterar credenciais.
  - **Isolamento de Processos**: Cabeçalhos HTTP avançados (COOP, CSP, HSTS, Permissions-Policy).

---

## 🚀 Instalação e Execução

### Pré-requisitos
- Python 3.10 ou superior
- Node.js 18 ou superior (para compilação dos scripts clientes)

### 1. Clonar o Repositório
```bash
git clone https://github.com/seu-usuario/PDXStorage.git
cd PDXStorage
```

### 2. Configurar o Ambiente Python
```bash
python -m venv venv

# No Linux/macOS:
source venv/bin/activate

# No Windows (PowerShell):
.\venv\Scripts\Activate.ps1
```

Instale as dependências:
```bash
pip install -r requirements.txt
```

### 3. Compilar os Scripts do Frontend (Opcional se já compilados)
```bash
npm install
node scripts/obfuscate.js
```

### 4. Iniciar o Servidor
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

Acesse o sistema no navegador:
- **Painel Principal**: [http://localhost:8000](http://localhost:8000)
- **Autenticação / Registro**: [http://localhost:8000/login](http://localhost:8000/login)
- **Console Administrativo**: [http://localhost:8000/admin](http://localhost:8000/admin)

---

## 🔐 Configurações Padrão de Administração

- **Rota de Administração**: `/admin`
- **Chave de Segurança Mestre**: `pladixisback2026@` *(Pode ser alterada no arquivo `backend/main.py`)*

---

## 📁 Estrutura do Repositório

```
PDXStorage/
├── backend/
│   ├── antibot.py       # Desafio físico e validação anti-bot
│   ├── auth.py          # Hashing de senhas, JWT e 2FA TOTP
│   ├── database.py      # Modelos SQLAlchemy e conexão SQLite
│   ├── main.py          # API FastAPI, middlewares de segurança e rotas
│   └── storage.py       # Fragmentação em chunks e criptografia AES-256-GCM
├── frontend/
│   ├── admin.html       # Interface do console administrativo
│   ├── index.html       # Dashboard do usuário e cofre de arquivos
│   ├── login.html       # Login e cadastro com anti-bot slider
│   ├── css/             # Folhas de estilo com visual Dark Glassmorphism
│   ├── js/              # Scripts ofuscados para produção
│   └── src_js/          # Código fonte legível dos scripts JavaScript
├── data/                # Banco de dados SQLite e blocos criptografados
├── scripts/
│   ├── obfuscate.js     # Compilador e ofuscador de código cliente
│   └── reset_db.py      # Utilitário para limpeza e inicialização do banco
└── README.md
```

---

## ⚖️ Licença e Créditos

Distribuído pela comunidade **pladixoficial**.
Acompanhe novidades, atualizações e projetos em:
👉 **[t.me/pladixoficial](https://t.me/pladixoficial)**
