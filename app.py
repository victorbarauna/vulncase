import os
import csv
import io
import secrets
import sqlite3
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, g, abort, Response)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# a chave vem de variavel de ambiente; se nao tiver, gera uma aleatoria
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DB_PATH = os.path.join(os.path.dirname(__file__), "vulncase.db")

SEVERIDADES = ["Crítica", "Alta", "Média", "Baixa"]
STATUS = ["Aberto", "Em correção", "Corrigido", "Risco aceito"]
ORIGENS = ["Rede", "Aplicação", "Código"]
TIPOS_PROJETO = ["Aplicação Web", "API", "Aplicativo Móvel", "Rede", "Servidor"]


# ---------------- banco de dados ----------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def fechar_db(erro):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    with open(os.path.join(os.path.dirname(__file__), "schema.sql"), encoding="utf-8") as f:
        db.executescript(f.read())
    db.commit()
    db.close()


@app.cli.command("init-db")
def init_db_comando():
    """Cria (ou recria) as tabelas do banco."""
    init_db()
    print("Banco criado.")


# ---------------- seguranca: login e csrf ----------------

def login_obrigatorio(f):
    @wraps(f)
    def decorada(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorada


def gerar_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = gerar_csrf


@app.before_request
def verificar_csrf():
    if request.method == "POST":
        token = request.form.get("csrf")
        if not token or token != session.get("csrf"):
            abort(400, "Token CSRF inválido")


# ---------------- autenticacao ----------------

@app.route("/registrar", methods=["GET", "POST"])
def registrar():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")

        if not nome or not email or len(senha) < 8:
            flash("Preencha tudo. A senha precisa ter pelo menos 8 caracteres.")
            return render_template("registrar.html")

        db = get_db()
        try:
            db.execute("INSERT INTO usuarios (nome, email, senha_hash) VALUES (?, ?, ?)",
                       (nome, email, generate_password_hash(senha)))
            db.commit()
        except sqlite3.IntegrityError:
            flash("Esse e-mail já está cadastrado.")
            return render_template("registrar.html")

        flash("Conta criada, agora faça login.")
        return redirect(url_for("login"))
    return render_template("registrar.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        usuario = get_db().execute("SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone()

        # mensagem generica para nao revelar se o email existe
        if usuario is None or not check_password_hash(usuario["senha_hash"], senha):
            flash("E-mail ou senha incorretos.")
            return render_template("login.html")

        session.clear()
        session["usuario_id"] = usuario["id"]
        session["usuario_nome"] = usuario["nome"]
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------- projetos ----------------

@app.route("/projetos")
@login_obrigatorio
def projetos():
    lista = get_db().execute("""
        SELECT p.*, COUNT(a.id) AS total,
               SUM(CASE WHEN a.status IN ('Aberto', 'Em correção') THEN 1 ELSE 0 END) AS pendentes
        FROM projetos p LEFT JOIN achados a ON a.projeto_id = p.id
        GROUP BY p.id ORDER BY p.nome
    """).fetchall()
    return render_template("projetos.html", projetos=lista)


def validar_projeto(form):
    nome = form.get("nome", "").strip()
    tipo = form.get("tipo", "")
    if not nome or tipo not in TIPOS_PROJETO:
        return None
    return {"nome": nome, "tipo": tipo, "descricao": form.get("descricao", "").strip()}


@app.route("/projetos/novo", methods=["GET", "POST"])
@login_obrigatorio
def novo_projeto():
    if request.method == "POST":
        dados = validar_projeto(request.form)
        if dados is None:
            flash("Nome e tipo são obrigatórios.")
        else:
            db = get_db()
            db.execute("INSERT INTO projetos (nome, tipo, descricao) VALUES (?, ?, ?)",
                       (dados["nome"], dados["tipo"], dados["descricao"]))
            db.commit()
            flash("Projeto cadastrado.")
            return redirect(url_for("projetos"))
    return render_template("projeto_form.html", projeto=None, tipos=TIPOS_PROJETO)


@app.route("/projetos/<int:id>/editar", methods=["GET", "POST"])
@login_obrigatorio
def editar_projeto(id):
    db = get_db()
    projeto = db.execute("SELECT * FROM projetos WHERE id = ?", (id,)).fetchone()
    if projeto is None:
        abort(404)
    if request.method == "POST":
        dados = validar_projeto(request.form)
        if dados is None:
            flash("Nome e tipo são obrigatórios.")
        else:
            db.execute("UPDATE projetos SET nome = ?, tipo = ?, descricao = ? WHERE id = ?",
                       (dados["nome"], dados["tipo"], dados["descricao"], id))
            db.commit()
            flash("Projeto atualizado.")
            return redirect(url_for("projetos"))
    return render_template("projeto_form.html", projeto=projeto, tipos=TIPOS_PROJETO)


@app.route("/projetos/<int:id>/excluir", methods=["POST"])
@login_obrigatorio
def excluir_projeto(id):
    db = get_db()
    db.execute("DELETE FROM projetos WHERE id = ?", (id,))
    db.commit()
    flash("Projeto excluído (e os achados dele também).")
    return redirect(url_for("projetos"))


# ---------------- achados ----------------

@app.route("/achados")
@login_obrigatorio
def achados():
    # filtros opcionais pela url, ex: /achados?severidade=Alta
    filtros = []
    valores = []
    projeto_id = request.args.get("projeto", "")
    severidade = request.args.get("severidade", "")
    status = request.args.get("status", "")

    if projeto_id.isdigit():
        filtros.append("a.projeto_id = ?")
        valores.append(int(projeto_id))
    if severidade in SEVERIDADES:
        filtros.append("a.severidade = ?")
        valores.append(severidade)
    if status in STATUS:
        filtros.append("a.status = ?")
        valores.append(status)

    sql = """SELECT a.*, p.nome AS projeto_nome FROM achados a
             JOIN projetos p ON p.id = a.projeto_id"""
    if filtros:
        sql += " WHERE " + " AND ".join(filtros)
    sql += """ ORDER BY CASE a.severidade WHEN 'Crítica' THEN 1 WHEN 'Alta' THEN 2
               WHEN 'Média' THEN 3 ELSE 4 END, a.id DESC"""

    db = get_db()
    lista = db.execute(sql, valores).fetchall()
    lista_projetos = db.execute("SELECT id, nome FROM projetos ORDER BY nome").fetchall()
    return render_template("achados.html", achados=lista, projetos=lista_projetos,
                           severidades=SEVERIDADES, status_lista=STATUS,
                           filtro={"projeto": projeto_id, "severidade": severidade, "status": status})


def validar_achado(form):
    dados = {c: form.get(c, "").strip() for c in
             ["projeto_id", "titulo", "origem", "severidade", "status",
              "responsavel", "cwe", "descricao", "evidencia", "correcao"]}
    if (not dados["titulo"] or not dados["projeto_id"].isdigit()
            or dados["origem"] not in ORIGENS
            or dados["severidade"] not in SEVERIDADES
            or dados["status"] not in STATUS):
        return None
    dados["projeto_id"] = int(dados["projeto_id"])
    return dados


def form_achado(achado):
    projetos = get_db().execute("SELECT id, nome FROM projetos ORDER BY nome").fetchall()
    return render_template("achado_form.html", achado=achado, projetos=projetos,
                           severidades=SEVERIDADES, status_lista=STATUS, origens=ORIGENS)


@app.route("/achados/novo", methods=["GET", "POST"])
@login_obrigatorio
def novo_achado():
    if request.method == "POST":
        d = validar_achado(request.form)
        if d is None:
            flash("Confira os campos obrigatórios (projeto, título, origem, severidade, status).")
            return form_achado(request.form)

        db = get_db()
        # deduplicacao simples: mesmo titulo no mesmo projeto
        repetido = db.execute(
            "SELECT id FROM achados WHERE projeto_id = ? AND LOWER(titulo) = LOWER(?)",
            (d["projeto_id"], d["titulo"])).fetchone()
        if repetido and not request.form.get("forcar"):
            flash(f"Já existe um achado com esse título nesse projeto (#{repetido['id']}). "
                  "Marque 'cadastrar mesmo assim' se não for duplicado.")
            return form_achado(request.form)

        db.execute("""INSERT INTO achados (projeto_id, titulo, origem, severidade, status,
                      responsavel, cwe, descricao, evidencia, correcao)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                   (d["projeto_id"], d["titulo"], d["origem"], d["severidade"], d["status"],
                    d["responsavel"], d["cwe"], d["descricao"], d["evidencia"], d["correcao"]))
        db.commit()
        flash("Achado cadastrado.")
        return redirect(url_for("achados"))
    return form_achado(None)


@app.route("/achados/<int:id>")
@login_obrigatorio
def ver_achado(id):
    achado = get_db().execute("""SELECT a.*, p.nome AS projeto_nome FROM achados a
                                 JOIN projetos p ON p.id = a.projeto_id WHERE a.id = ?""",
                              (id,)).fetchone()
    if achado is None:
        abort(404)
    return render_template("achado_ver.html", achado=achado)


@app.route("/achados/<int:id>/editar", methods=["GET", "POST"])
@login_obrigatorio
def editar_achado(id):
    db = get_db()
    achado = db.execute("SELECT * FROM achados WHERE id = ?", (id,)).fetchone()
    if achado is None:
        abort(404)
    if request.method == "POST":
        d = validar_achado(request.form)
        if d is None:
            flash("Confira os campos obrigatórios.")
            return form_achado(request.form)
        db.execute("""UPDATE achados SET projeto_id = ?, titulo = ?, origem = ?, severidade = ?,
                      status = ?, responsavel = ?, cwe = ?, descricao = ?, evidencia = ?,
                      correcao = ?, atualizado_em = CURRENT_TIMESTAMP WHERE id = ?""",
                   (d["projeto_id"], d["titulo"], d["origem"], d["severidade"], d["status"],
                    d["responsavel"], d["cwe"], d["descricao"], d["evidencia"], d["correcao"], id))
        db.commit()
        flash("Achado atualizado.")
        return redirect(url_for("ver_achado", id=id))
    return form_achado(achado)


@app.route("/achados/<int:id>/excluir", methods=["POST"])
@login_obrigatorio
def excluir_achado(id):
    db = get_db()
    db.execute("DELETE FROM achados WHERE id = ?", (id,))
    db.commit()
    flash("Achado excluído.")
    return redirect(url_for("achados"))


# ---------------- dashboard e relatorio ----------------

def contar(coluna, valores, projeto_id=None):
    # coluna vem sempre do codigo (nunca do usuario), por isso pode ir na string
    sql = f"SELECT {coluna}, COUNT(*) AS n FROM achados"
    params = []
    if projeto_id:
        sql += " WHERE projeto_id = ?"
        params.append(projeto_id)
    sql += f" GROUP BY {coluna}"
    resultado = {v: 0 for v in valores}
    for linha in get_db().execute(sql, params):
        resultado[linha[coluna]] = linha["n"]
    return resultado


@app.route("/")
@login_obrigatorio
def dashboard():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM achados").fetchone()[0]
    total_projetos = db.execute("SELECT COUNT(*) FROM projetos").fetchone()[0]
    por_sev = contar("severidade", SEVERIDADES)
    por_status = contar("status", STATUS)
    por_origem = contar("origem", ORIGENS)
    criticos_abertos = db.execute("""SELECT a.id, a.titulo, a.severidade, a.responsavel,
                                     p.nome AS projeto_nome FROM achados a
                                     JOIN projetos p ON p.id = a.projeto_id
                                     WHERE a.severidade IN ('Crítica', 'Alta')
                                     AND a.status IN ('Aberto', 'Em correção')
                                     ORDER BY a.severidade = 'Crítica' DESC, a.id""").fetchall()
    return render_template("dashboard.html", total=total, total_projetos=total_projetos,
                           por_sev=por_sev, por_status=por_status, por_origem=por_origem,
                           criticos=criticos_abertos)


@app.route("/projetos/<int:id>/relatorio")
@login_obrigatorio
def relatorio(id):
    db = get_db()
    projeto = db.execute("SELECT * FROM projetos WHERE id = ?", (id,)).fetchone()
    if projeto is None:
        abort(404)
    lista = db.execute("""SELECT * FROM achados WHERE projeto_id = ?
                          ORDER BY CASE severidade WHEN 'Crítica' THEN 1 WHEN 'Alta' THEN 2
                          WHEN 'Média' THEN 3 ELSE 4 END""", (id,)).fetchall()
    corrigidos = sum(1 for a in lista if a["status"] == "Corrigido")
    return render_template("relatorio.html", projeto=projeto, achados=lista,
                           por_sev=contar("severidade", SEVERIDADES, id),
                           por_status=contar("status", STATUS, id),
                           corrigidos=corrigidos)


@app.route("/projetos/<int:id>/csv")
@login_obrigatorio
def exportar_csv(id):
    lista = get_db().execute("SELECT * FROM achados WHERE projeto_id = ?", (id,)).fetchall()
    saida = io.StringIO()
    escritor = csv.writer(saida)
    colunas = ["id", "titulo", "origem", "severidade", "status", "responsavel",
               "cwe", "descricao", "evidencia", "correcao", "criado_em"]
    escritor.writerow(colunas)
    for a in lista:
        linha = [a[c] for c in colunas]
        # evita "CSV injection" quando abrir no Excel
        linha = ["'" + str(v) if str(v)[:1] in ("=", "+", "-", "@") else v for v in linha]
        escritor.writerow(linha)
    return Response(saida.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=achados_projeto_{id}.csv"})


@app.after_request
def headers_seguranca(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    return resp


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(debug=False)
