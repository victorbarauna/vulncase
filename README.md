# VulnCase

Projeto Integrador - Segurança Aplicada e Privacidade (UFAM)
Trilha 3: Gestão de achados, riscos e correções.

Sistema web simples para registrar vulnerabilidades encontradas em análises de rede, aplicação ou código, acompanhar o status da correção e gerar um relatório por projeto.

## Equipe

- Victor Baraúna
- Renata Modesto
- Giovani Artil
- Sofia Icavino

## Funcionalidades

- Cadastro de usuários com login
- Cadastro de projetos/ativos (aplicação web, API, rede, servidor...)
- Cadastro de achados com origem, severidade, status, responsável, CWE/CVE, evidência e correção proposta
- Filtro de achados por projeto, severidade e status
- Aviso de achado duplicado (mesmo título no mesmo projeto)
- Dashboard com contagem por severidade, status e origem
- Relatório por projeto (dá pra salvar em PDF com Ctrl+P)
- Exportação dos achados em CSV

## Controles de segurança aplicados no próprio sistema

| Risco (OWASP Top 10) | O que foi feito |
|---|---|
| A03 Injection (SQL Injection) | Todas as consultas usam parâmetros (`?`), nunca concatenam entrada do usuário |
| A03 Injection (XSS) | Templates Jinja2 com autoescape; header Content-Security-Policy |
| A01 Broken Access Control | Decorator `login_obrigatorio` em todas as rotas internas |
| A07 Falhas de autenticação | Senha com hash (`werkzeug`, PBKDF2/scrypt), mínimo 8 caracteres, mensagem de erro genérica no login |
| CSRF | Token por sessão validado em todo POST; exclusão e logout só por POST |
| A05 Configuração insegura | `debug=False`, SECRET_KEY por variável de ambiente, cookie HttpOnly + SameSite, headers X-Frame-Options e nosniff |
| CSV Injection | Valores começando com `= + - @` recebem `'` na exportação |
| Validação de entrada | Severidade, status, origem e tipo só aceitam valores da lista |

## Como rodar

Precisa do Python 3.10 ou mais novo.

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

pip install -r requirements.txt
python app.py
```

Abrir http://127.0.0.1:5000, criar uma conta em "Registrar" e fazer login.

O banco `vulncase.db` (SQLite) é criado sozinho na primeira execução. Para zerar o banco: `flask --app app init-db`.

## Estrutura

```
app.py          rotas e lógica
schema.sql      tabelas do banco
templates/      páginas HTML
static/         CSS
```

## Melhorias futuras

- Perfis de usuário (admin / analista)
- Upload de arquivos de evidência (prints)
- Gráficos no dashboard
- Histórico de mudanças de status
