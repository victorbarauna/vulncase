DROP TABLE IF EXISTS achados;
DROP TABLE IF EXISTS projetos;
DROP TABLE IF EXISTS usuarios;

CREATE TABLE usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    senha_hash TEXT NOT NULL
);

CREATE TABLE projetos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    descricao TEXT,
    tipo TEXT NOT NULL,          -- Aplicação Web, API, Rede, Servidor...
    criado_em TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE achados (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    projeto_id INTEGER NOT NULL,
    titulo TEXT NOT NULL,
    origem TEXT NOT NULL,        -- Rede, Aplicação, Código
    severidade TEXT NOT NULL,    -- Crítica, Alta, Média, Baixa
    status TEXT NOT NULL,        -- Aberto, Em correção, Corrigido, Risco aceito
    responsavel TEXT,
    cwe TEXT,
    descricao TEXT,
    evidencia TEXT,
    correcao TEXT,
    criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
    atualizado_em TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (projeto_id) REFERENCES projetos(id) ON DELETE CASCADE
);
