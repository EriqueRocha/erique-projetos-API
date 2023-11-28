CREATE TABLE IF NOT EXISTS public.tab_projeto
(
    id SERIAL PRIMARY KEY,
    descricao_bakc character varying(255),
    descricao_front character varying(255),
    link_bakc character varying(255),
    link_front character varying(255),
    nome character varying(255),
    repositorio_back character varying(255),
    repositorio_front character varying(255)
);

CREATE TABLE IF NOT EXISTS public.projeto_image_paths
(
    projeto_id integer NOT NULL,
    image_paths character varying(255)
);
