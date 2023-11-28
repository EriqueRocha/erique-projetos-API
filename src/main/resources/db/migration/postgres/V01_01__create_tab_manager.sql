CREATE TABLE IF NOT EXISTS public.tab_manager
(
    id SERIAL PRIMARY KEY,
    email character varying(255),
    nome character varying(255),
    password character varying(255),
    role character varying(255)
);