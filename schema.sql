--
-- PostgreSQL database dump
--

\restrict brje9bHyYuTh4FhvUXBu1Ig0OqkDPMM3jfPU940QEpLmT5vGFMt59kKaC8ktxWo

-- Dumped from database version 16.10 (Debian 16.10-1.pgdg13+1)
-- Dumped by pg_dump version 16.10 (Debian 16.10-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: affected; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.affected (
    cve_id character varying NOT NULL,
    product_id integer NOT NULL,
    version_min character varying,
    version_max character varying,
    include_min boolean NOT NULL,
    include_max boolean NOT NULL
);


ALTER TABLE public.affected OWNER TO postgres;

--
-- Name: cve; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.cve (
    cve_id character varying NOT NULL,
    summary text NOT NULL,
    description text,
    published date,
    modified date,
    severity character varying,
    cvss_version character varying,
    cvss_score double precision,
    cvss_vector character varying,
    cwe_id character varying,
    source character varying,
    status character varying NOT NULL
);


ALTER TABLE public.cve OWNER TO postgres;

--
-- Name: cwe; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.cwe (
    cwe_id character varying NOT NULL,
    name character varying NOT NULL
);


ALTER TABLE public.cwe OWNER TO postgres;

--
-- Name: product; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.product (
    product_id integer NOT NULL,
    vendor_id integer NOT NULL,
    name character varying NOT NULL
);


ALTER TABLE public.product OWNER TO postgres;

--
-- Name: product_product_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.product_product_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.product_product_id_seq OWNER TO postgres;

--
-- Name: product_product_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.product_product_id_seq OWNED BY public.product.product_id;


--
-- Name: raw_nvd; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.raw_nvd (
    id integer NOT NULL,
    cve_id character varying NOT NULL,
    payload jsonb NOT NULL,
    ingested_at timestamp without time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.raw_nvd OWNER TO postgres;

--
-- Name: raw_nvd_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.raw_nvd_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.raw_nvd_id_seq OWNER TO postgres;

--
-- Name: raw_nvd_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.raw_nvd_id_seq OWNED BY public.raw_nvd.id;


--
-- Name: reference; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.reference (
    ref_id integer NOT NULL,
    cve_id character varying NOT NULL,
    url text NOT NULL,
    source character varying,
    tags character varying
);


ALTER TABLE public.reference OWNER TO postgres;

--
-- Name: reference_ref_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.reference_ref_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.reference_ref_id_seq OWNER TO postgres;

--
-- Name: reference_ref_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.reference_ref_id_seq OWNED BY public.reference.ref_id;


--
-- Name: status_history; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.status_history (
    id integer NOT NULL,
    cve_id character varying NOT NULL,
    status character varying NOT NULL,
    note text,
    changed_at timestamp without time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.status_history OWNER TO postgres;

--
-- Name: status_history_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.status_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.status_history_id_seq OWNER TO postgres;

--
-- Name: status_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.status_history_id_seq OWNED BY public.status_history.id;


--
-- Name: vendor; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.vendor (
    vendor_id integer NOT NULL,
    name character varying NOT NULL
);


ALTER TABLE public.vendor OWNER TO postgres;

--
-- Name: vendor_vendor_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.vendor_vendor_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.vendor_vendor_id_seq OWNER TO postgres;

--
-- Name: vendor_vendor_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.vendor_vendor_id_seq OWNED BY public.vendor.vendor_id;


--
-- Name: product product_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.product ALTER COLUMN product_id SET DEFAULT nextval('public.product_product_id_seq'::regclass);


--
-- Name: raw_nvd id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.raw_nvd ALTER COLUMN id SET DEFAULT nextval('public.raw_nvd_id_seq'::regclass);


--
-- Name: reference ref_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.reference ALTER COLUMN ref_id SET DEFAULT nextval('public.reference_ref_id_seq'::regclass);


--
-- Name: status_history id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.status_history ALTER COLUMN id SET DEFAULT nextval('public.status_history_id_seq'::regclass);


--
-- Name: vendor vendor_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vendor ALTER COLUMN vendor_id SET DEFAULT nextval('public.vendor_vendor_id_seq'::regclass);


--
-- Name: affected affected_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.affected
    ADD CONSTRAINT affected_pkey PRIMARY KEY (cve_id, product_id);


--
-- Name: cve cve_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cve
    ADD CONSTRAINT cve_pkey PRIMARY KEY (cve_id);


--
-- Name: cwe cwe_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cwe
    ADD CONSTRAINT cwe_pkey PRIMARY KEY (cwe_id);


--
-- Name: product product_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.product
    ADD CONSTRAINT product_pkey PRIMARY KEY (product_id);


--
-- Name: raw_nvd raw_nvd_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.raw_nvd
    ADD CONSTRAINT raw_nvd_pkey PRIMARY KEY (id);


--
-- Name: reference reference_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.reference
    ADD CONSTRAINT reference_pkey PRIMARY KEY (ref_id);


--
-- Name: status_history status_history_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.status_history
    ADD CONSTRAINT status_history_pkey PRIMARY KEY (id);


--
-- Name: product uq_vendor_product; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.product
    ADD CONSTRAINT uq_vendor_product UNIQUE (vendor_id, name);


--
-- Name: vendor vendor_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vendor
    ADD CONSTRAINT vendor_name_key UNIQUE (name);


--
-- Name: vendor vendor_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vendor
    ADD CONSTRAINT vendor_pkey PRIMARY KEY (vendor_id);


--
-- Name: idx_affected_product; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_affected_product ON public.affected USING btree (product_id);


--
-- Name: idx_cve_cwe; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cve_cwe ON public.cve USING btree (cwe_id);


--
-- Name: idx_cve_published; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cve_published ON public.cve USING btree (published);


--
-- Name: idx_cve_severity; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cve_severity ON public.cve USING btree (severity);


--
-- Name: idx_product_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_product_name ON public.product USING btree (name);


--
-- Name: affected affected_cve_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.affected
    ADD CONSTRAINT affected_cve_id_fkey FOREIGN KEY (cve_id) REFERENCES public.cve(cve_id) ON DELETE CASCADE;


--
-- Name: affected affected_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.affected
    ADD CONSTRAINT affected_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.product(product_id) ON DELETE CASCADE;


--
-- Name: cve cve_cwe_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cve
    ADD CONSTRAINT cve_cwe_id_fkey FOREIGN KEY (cwe_id) REFERENCES public.cwe(cwe_id);


--
-- Name: product product_vendor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.product
    ADD CONSTRAINT product_vendor_id_fkey FOREIGN KEY (vendor_id) REFERENCES public.vendor(vendor_id);


--
-- Name: raw_nvd raw_nvd_cve_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.raw_nvd
    ADD CONSTRAINT raw_nvd_cve_id_fkey FOREIGN KEY (cve_id) REFERENCES public.cve(cve_id) ON DELETE CASCADE;


--
-- Name: reference reference_cve_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.reference
    ADD CONSTRAINT reference_cve_id_fkey FOREIGN KEY (cve_id) REFERENCES public.cve(cve_id) ON DELETE CASCADE;


--
-- Name: status_history status_history_cve_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.status_history
    ADD CONSTRAINT status_history_cve_id_fkey FOREIGN KEY (cve_id) REFERENCES public.cve(cve_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict brje9bHyYuTh4FhvUXBu1Ig0OqkDPMM3jfPU940QEpLmT5vGFMt59kKaC8ktxWo

