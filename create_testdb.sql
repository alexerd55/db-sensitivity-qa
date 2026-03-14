-- =============================================================
-- dbqa-testdb: Testna baza za db-sensitivity-qa skener
-- Pokreni kao: psql -U postgres -f create_testdb.sql
-- =============================================================

-- Kreira bazu i konektuje se na nju

-- =============================================================
-- ŠEMA: public  (glavni app podaci)
-- =============================================================

-- -----------------------------------------------------------
-- 1. users — puna PII bomba: email, phone, password, dob, address
-- -----------------------------------------------------------
CREATE TABLE public.users (
    id          SERIAL PRIMARY KEY,
    first_name  VARCHAR(100) NOT NULL,
    last_name   VARCHAR(100) NOT NULL,
    email       VARCHAR(255) UNIQUE NOT NULL,
    phone       VARCHAR(30),
    date_of_birth DATE,
    password    VARCHAR(255),          -- namerno plaintext-ish (detektuje POSSIBLE_PLAINTEXT)
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- -----------------------------------------------------------
-- 2. user_profiles — adresa i gov ID
-- -----------------------------------------------------------
CREATE TABLE public.user_profiles (
    id          SERIAL PRIMARY KEY,
    user_id     INT REFERENCES public.users(id),
    address     TEXT,
    city        VARCHAR(100),
    zip         VARCHAR(20),
    jmbg        VARCHAR(13),           -- srpski matični broj
    passport    VARCHAR(30),
    nationality VARCHAR(50)
);

-- -----------------------------------------------------------
-- 3. payment_methods — IBAN, card
-- -----------------------------------------------------------
CREATE TABLE public.payment_methods (
    id          SERIAL PRIMARY KEY,
    user_id     INT REFERENCES public.users(id),
    iban        VARCHAR(34),
    card        VARCHAR(25),          -- broj kartice (triggeriše PAYMENT + Luhn)
    swift       VARCHAR(11),
    is_default  BOOLEAN DEFAULT FALSE
);

-- -----------------------------------------------------------
-- 4. api_keys — AUTH detekcija
-- -----------------------------------------------------------
CREATE TABLE public.api_keys (
    id          SERIAL PRIMARY KEY,
    user_id     INT REFERENCES public.users(id),
    api_key     VARCHAR(64) NOT NULL,  -- izgledaće kao token/secret
    secret      VARCHAR(128),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ
);

-- -----------------------------------------------------------
-- 5. sessions — JWT token detekcija
-- -----------------------------------------------------------
CREATE TABLE public.sessions (
    id          SERIAL PRIMARY KEY,
    user_id     INT REFERENCES public.users(id),
    token       TEXT NOT NULL,         -- JWT format, triggeriše JWT detektor
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- -----------------------------------------------------------
-- 6. products — bezbedan sadržaj, ne bi trebalo da se flaguje
-- -----------------------------------------------------------
CREATE TABLE public.products (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    price       NUMERIC(10,2),
    stock       INT DEFAULT 0,
    category    VARCHAR(100),
    sku         VARCHAR(50) UNIQUE
);

-- -----------------------------------------------------------
-- 7. orders — mešano, user ref ali bez direktnog PII
-- -----------------------------------------------------------
CREATE TABLE public.orders (
    id              SERIAL PRIMARY KEY,
    user_id         INT REFERENCES public.users(id),
    total_amount    NUMERIC(12,2),
    status          VARCHAR(50) DEFAULT 'pending',
    shipping_address TEXT,            -- adresa flaguje se
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- -----------------------------------------------------------
-- 8. audit_log — log tabela sa PII leakom (visok rizik!)
--    Skener daje +10 score za log/audit tabele
-- -----------------------------------------------------------
CREATE TABLE public.audit_log (
    id          BIGSERIAL PRIMARY KEY,
    event_type  VARCHAR(100),
    user_id     INT,
    email       VARCHAR(255),         -- PII u logu = HIGH finding
    ip_address  VARCHAR(45),
    payload     TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- -----------------------------------------------------------
-- 9. password_reset_tokens — AUTH + token
-- -----------------------------------------------------------
CREATE TABLE public.password_reset_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INT REFERENCES public.users(id),
    token       VARCHAR(128) NOT NULL, -- SHA256 hex hash
    expires_at  TIMESTAMPTZ,
    used        BOOLEAN DEFAULT FALSE
);

-- -----------------------------------------------------------
-- 10. newsletters — email lista
-- -----------------------------------------------------------
CREATE TABLE public.newsletters (
    id          SERIAL PRIMARY KEY,
    email       VARCHAR(255) UNIQUE NOT NULL,
    first_name  VARCHAR(100),
    subscribed  BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================
-- ŠEMA: app  (backend servis tabele)
-- =============================================================

CREATE SCHEMA app;

-- -----------------------------------------------------------
-- 11. app.employees — interna HR tabela
-- -----------------------------------------------------------
CREATE TABLE app.employees (
    id          SERIAL PRIMARY KEY,
    first_name  VARCHAR(100),
    last_name   VARCHAR(100),
    email       VARCHAR(255),
    phone       VARCHAR(30),
    jmbg        VARCHAR(13),
    salary      NUMERIC(12,2),
    position    VARCHAR(100),
    hired_at    DATE
);

-- -----------------------------------------------------------
-- 12. app.oauth_tokens — refresh tokeni, API ključevi
-- -----------------------------------------------------------
CREATE TABLE app.oauth_tokens (
    id              SERIAL PRIMARY KEY,
    user_id         INT,
    access_token    TEXT NOT NULL,    -- JWT
    refresh_token   TEXT NOT NULL,    -- UUID-like
    client_id       VARCHAR(100),
    expires_at      TIMESTAMPTZ
);

-- -----------------------------------------------------------
-- 13. app.config — plaintext secrets (najgori scenario)
-- -----------------------------------------------------------
CREATE TABLE app.config (
    key         VARCHAR(100) PRIMARY KEY,
    value       TEXT,                 -- API keys, secrets, passwords in plaintext
    description TEXT,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================
-- POPULACIJA PODATAKA — realistični uzorci
-- =============================================================

-- -----------------------------------------------------------
-- users (50 redova sa realnim imenima/email/phone/password)
-- -----------------------------------------------------------
INSERT INTO public.users (first_name, last_name, email, phone, date_of_birth, password) VALUES
('Marko',     'Petrović',   'marko.petrovic@gmail.com',    '+381641234567',  '1990-03-15', 'Marko1990!'),
('Ana',       'Jovanović',  'ana.jovanovic@yahoo.com',     '+381601234568',  '1985-07-22', 'ana_pass_123'),
('Stefan',    'Nikolić',    'stefan.nikolic@hotmail.com',  '+381691234569',  '1993-11-08', 'Stefan@secure'),
('Jelena',    'Đorđević',   'jelena.djordjevic@gmail.com', '+381651234570',  '1988-04-30', 'jel1988pass'),
('Nikola',    'Stojanović', 'nikola.stojanovic@outlook.com','+381621234571', '1995-09-12', 'nik_95_pass'),
('Ivana',     'Ilić',       'ivana.ilic@gmail.com',        '+381631234572',  '1991-02-14', 'Iv@na2021'),
('Aleksandar','Pavlović',   'alex.pavlovic@gmail.com',     '+381641234573',  '1987-06-25', 'aleksPass!'),
('Milica',    'Janković',   'milica.jankovic@gmail.com',   '+381601234574',  '1994-12-03', 'milica_123'),
('Petar',     'Vasić',      'petar.vasic@company.rs',      '+381691234575',  '1989-08-17', 'PetarV2019!'),
('Maja',      'Lukić',      'maja.lukic@gmail.com',        '+381651234576',  '1996-01-09', 'maja_l_pass'),
('Đorđe',     'Marinović',  'djordje.marinovic@gmail.com', '+381621234577',  '1992-05-21', 'djole1992'),
('Tamara',    'Kostić',     'tamara.kostic@yahoo.com',     '+381631234578',  '1990-10-14', 'Tamara@2020'),
('Luka',      'Bogdanović', 'luka.bogdanovic@gmail.com',   '+381641234579',  '1997-07-07', 'luka97pass'),
('Jovana',    'Simić',      'jovana.simic@outlook.com',    '+381601234580',  '1986-03-28', 'jova_sim!'),
('Miloš',     'Ristić',     'milos.ristic@gmail.com',      '+381691234581',  '1993-09-19', 'Milos2022#'),
('Nina',      'Popović',    'nina.popovic@gmail.com',      '+381651234582',  '1998-11-11', 'nina_pop_11'),
('Vuk',       'Đukić',      'vuk.djukic@hotmail.com',      '+381621234583',  '1984-04-04', 'VukD1984'),
('Sanja',     'Milošević',  'sanja.milosevic@gmail.com',   '+381631234584',  '1991-08-23', 'sanja_m!'),
('Boris',     'Todorović',  'boris.todorovic@gmail.com',   '+381641234585',  '1988-12-31', 'Boris2023'),
('Katarina',  'Lazić',      'katarina.lazic@company.rs',   '+381601234586',  '1995-06-06', 'kataLazic!'),
('Ivan',      'Filipović',  'ivan.filipovic@gmail.com',    '+381691234587',  '1990-02-28', 'ivan_fil_90'),
('Milena',    'Đorić',      'milena.djoric@yahoo.com',     '+381651234588',  '1987-09-15', 'Milena87@'),
('Radovan',   'Stević',     'radovan.stevic@gmail.com',    '+381621234589',  '1983-07-04', 'rad_stev!'),
('Dragana',   'Vuković',    'dragana.vukovic@gmail.com',   '+381631234590',  '1994-01-20', 'dravuk2024'),
('Nemanja',   'Stanković',  'nemanja.stankovic@gmail.com', '+381641234591',  '1996-03-03', 'nem_stan_96'),
('Vesna',     'Kovačević',  'vesna.kovacevic@outlook.com', '+381601234592',  '1982-05-16', 'Vesna82!'),
('Slavko',    'Petković',   'slavko.petkovic@gmail.com',   '+381691234593',  '1979-11-27', 'slavko79'),
('Tijana',    'Matić',      'tijana.matic@gmail.com',      '+381651234594',  '1997-04-08', 'tija_matic'),
('Nenad',     'Arsić',      'nenad.arsic@hotmail.com',     '+381621234595',  '1991-10-10', 'nenad2021'),
('Danijela',  'Mihajlović', 'danijela.mihajlovic@gmail.com','+381631234596', '1989-08-30', 'dani_miha!'),
('Vojislav',  'Đurić',      'vojislav.djuric@gmail.com',   '+381641234597',  '1985-02-19', 'voja_djuric'),
('Gorana',    'Savić',      'gorana.savic@company.rs',     '+381601234598',  '1993-06-14', 'GorSav2023'),
('Bojan',     'Marinić',    'bojan.marinic@gmail.com',     '+381691234599',  '1990-12-25', 'bojan_mar!'),
('Snežana',   'Stanić',     'snezana.stanic@yahoo.com',    '+381651234600',  '1986-03-17', 'snez86pass'),
('Dragan',    'Nikolić',    'dragan.nikolic@gmail.com',    '+381621234601',  '1977-09-09', 'dragan77!'),
('Aleksandra','Vujanović',  'aleksandra.vujanovic@gmail.com','+381631234602','1998-07-21', 'aleks_vuj'),
('Zoran',     'Perić',      'zoran.peric@outlook.com',     '+381641234603',  '1975-04-12', 'ZoranP75'),
('Bojana',    'Gajić',      'bojana.gajic@gmail.com',      '+381601234604',  '1994-10-05', 'boja_gaj!'),
('Saša',      'Lazović',    'sasa.lazovic@gmail.com',      '+381691234605',  '1988-01-31', 'sasa_laz88'),
('Mirjana',   'Bogosavljević','mirjana.bogo@gmail.com',    '+381651234606',  '1981-06-22', 'mirj_bogo'),
('Slobodan',  'Nešić',      'slobodan.nesic@gmail.com',    '+381621234607',  '1980-08-08', 'slobodan80'),
('Jasmina',   'Radović',    'jasmina.radovic@yahoo.com',   '+381631234608',  '1995-02-02', 'jas_rad95'),
('Dušan',     'Milanović',  'dusan.milanovic@gmail.com',   '+381641234609',  '1992-11-17', 'dusan_mil!'),
('Ljiljana',  'Cvetković',  'ljiljana.cvetkovic@gmail.com','+381601234610',  '1984-05-29', 'ljilja84'),
('Goran',     'Đorđević',   'goran.djordjevic@company.rs', '+381691234611',  '1979-03-11', 'GorDjordje'),
('Slađana',   'Vuković',    'sladjana.vukovic@gmail.com',  '+381651234612',  '1991-09-26', 'slad_vuk!'),
('Bratislav',  'Antić',     'bratislav.antic@hotmail.com', '+381621234613',  '1987-07-15', 'brat_anti'),
('Zorica',    'Filipović',  'zorica.filipovic@gmail.com',  '+381631234614',  '1983-12-20', 'zorica83'),
('Predrag',   'Živković',   'predrag.zivkovic@gmail.com',  '+381641234615',  '1976-04-07', 'pred_ziv76'),
('Dragica',   'Petrović',   'dragica.petrovic@yahoo.com',  '+381601234616',  '1970-10-01', 'dragi_pet70');

-- -----------------------------------------------------------
-- user_profiles
-- -----------------------------------------------------------
INSERT INTO public.user_profiles (user_id, address, city, zip, jmbg, passport, nationality)
SELECT
    id,
    'Ulica ' || id || ' br. ' || (id * 3),
    (ARRAY['Beograd','Novi Sad','Niš','Kragujevac','Subotica','Čačak','Pančevo'])[1 + (id % 7)],
    LPAD((10000 + id * 7)::text, 5, '0'),
    -- Realistični JMBG format: DDMMYYY(7) + RR(2) + BBB(3) + K(1) = 13 cifara
    LPAD((id % 28 + 1)::text, 2, '0') || LPAD((id % 12 + 1)::text, 2, '0') || '9' || LPAD((70 + id % 30)::text, 2, '0') || LPAD((id % 99)::text, 2, '0') || LPAD((id % 999)::text, 3, '0') || (id % 10)::text,
    'PA' || LPAD((100000 + id * 37)::text, 7, '0'),
    'Srpska'
FROM public.users;

-- -----------------------------------------------------------
-- payment_methods — IBAN i Luhn-validni brojevi kartica
-- -----------------------------------------------------------
INSERT INTO public.payment_methods (user_id, iban, card, swift, is_default) VALUES
(1,  'RS35260005601001611379', '4532015112830366', 'DBDBRSBG', TRUE),
(2,  'RS35105008123456789012', '5425233430109903', 'NBSRRS22', TRUE),
(3,  'RS35250007310000289955', '4916338506082832', 'RAIFRS21', FALSE),
(4,  'RS35160005080003294807', '4539578763621486', 'AIKBRS22', TRUE),
(5,  'RS35265001001000442009', '5500005555555559', 'JUBARS22', FALSE),
(6,  'RS35275000310000212837', '4111111111111111', 'PROCRS22', TRUE),
(7,  'RS35285001001012312311', '4012888888881881', 'EXPOBANK', FALSE),
(8,  'RS35200007200300430115', '5105105105105100', 'PIRARS22', TRUE),
(9,  'RS35190005080003294812', '4222222222222',    'CITIRS22', FALSE),
(10, 'RS35155008123456789099', '4532015112830366', 'SBERRS22', TRUE),
(11, 'RS35260005601001611300', '5425233430109903', 'DBDBRSBG', TRUE),
(12, 'RS35105008123456789013', '4916338506082832', 'NBSRRS22', FALSE);

-- -----------------------------------------------------------
-- api_keys — hex tokens, triggeriše AUTH + HASH_LIKE
-- -----------------------------------------------------------
INSERT INTO public.api_keys (user_id, api_key, secret, expires_at) VALUES
(1,  'a1b2c3d4e5f6789012345678901234567890abcd', 'sk_live_9x8y7w6v5u4t3s2r1q0p', NOW() + INTERVAL '1 year'),
(2,  'f0e1d2c3b4a5968778695a4b3c2d1e0f12345678', 'sk_live_zzzyyy222333444555',   NOW() + INTERVAL '6 months'),
(3,  '1234567890abcdef1234567890abcdef12345678', 'pk_test_AbCdEfGhIjKlMnOpQr',   NOW() + INTERVAL '3 months'),
(4,  'deadbeef1234567890abcdef0987654321fedcba', 'sk_live_TESTTESTTEST12345',     NOW() + INTERVAL '1 year'),
(5,  'cafebabe9876543210fedcba1234567890abcdef', 'rk_prod_XxYyZz123456789012',   NOW() + INTERVAL '2 years'),
(6,  'abcdef0123456789abcdef0123456789abcdef01', 'sk_live_aAbBcCdDeEfFgGhH',     NOW() + INTERVAL '1 year'),
(7,  '0123456789abcdef0123456789abcdef01234567', 'pk_live_1234567890abcdefgh',   NOW() + INTERVAL '1 year'),
(8,  'fedcba9876543210fedcba9876543210fedcba98', 'sk_test_abcdefghijklmnopqr',   NOW() + INTERVAL '1 month');

-- -----------------------------------------------------------
-- sessions — JWT tokeni (triggeriše JWT detektor)
-- -----------------------------------------------------------
INSERT INTO public.sessions (user_id, token, ip_address, user_agent) VALUES
(1, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6Ik1hcmtvIiwiaWF0IjoxNzA5MDAwMDAwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
(2, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwibmFtZSI6IkFuYSIsImlhdCI6MTcwOTAwMDAwMH0.abc123def456ghi789jkl012mno345pqr678stu901',
    '10.0.0.50', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)'),
(3, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzIiwibmFtZSI6IlN0ZWZhbiIsImlhdCI6MTcwOTAwMDAwMH0.xyz789abc123def456ghi789jkl012mno345pqr6',
    '172.16.0.10', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)'),
(4, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0IiwibmFtZSI6IkplbGVuYSIsImlhdCI6MTcwOTAwMDAwMH0.def456ghi789jkl012mno345pqr678stu901vwx2',
    '192.168.0.1', 'PostmanRuntime/7.36.0'),
(5, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1IiwibmFtZSI6Ik5pa29sYSIsImlhdCI6MTcwOTAwMDAwMH0.ghi789jkl012mno345pqr678stu901vwx234yz56',
    '10.10.10.1', 'Mozilla/5.0 (Android 14; Mobile)'),
(1, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6Ik1hcmtvMiIsImlhdCI6MTcwOTEwMDAwMH0.secondsessiontoken1234567890abcdef1234567',
    '192.168.1.101', 'Mozilla/5.0 (Windows NT 10.0)'),
(6, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2IiwibmFtZSI6Ikl2YW5hIiwiaWF0IjoxNzA5MDAwMDAwfQ.jkl012mno345pqr678stu901vwx234yz5678ab90',
    '172.20.0.5', 'curl/7.88.1'),
(7, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI3IiwibmFtZSI6IkFsZWtzYW5kYXIiLCJpYXQiOjE3MDkwMDAwMDB9.mno345pqr678stu901vwx234yz5678ab90cd1234',
    '10.0.0.75', 'Mozilla/5.0 (X11; Linux x86_64)');

-- -----------------------------------------------------------
-- products — bezbedan sadržaj
-- -----------------------------------------------------------
INSERT INTO public.products (name, description, price, stock, category, sku) VALUES
('Laptop ProBook 15',    'Poslovni laptop, Intel i7, 16GB RAM',   1299.99, 45, 'Elektronika', 'LPBK-001'),
('Bežična tastatura',    'Bluetooth tastatura, crna',             49.99,  120, 'Periferni',   'WKBD-002'),
('Monitor 27" 4K',       '4K IPS panel, 144Hz, USB-C',           599.99,  30, 'Elektronika', 'MON4K-003'),
('Mehanička miš',        'Gaming miš, 16000 DPI',                 79.99,  85, 'Periferni',   'MMSE-004'),
('USB-C Hub 7-in-1',     'HDMI, USB3, SD card reader',           39.99,  200, 'Periferni',   'HUBC-005'),
('SSD 1TB NVMe',         'PCIe 4.0, 7000MB/s čitanje',          149.99,  60, 'Komponente',  'SSD1T-006'),
('Webcam Full HD',        '1080p, autofokus, mikrofon',           69.99,  90, 'Periferni',   'WCAM-007'),
('Slušalice ANC',         'Active noise cancelling, Bluetooth',   199.99, 55, 'Audio',       'SANC-008'),
('RAM 32GB DDR5',         'DDR5 6000MHz, CL36',                  189.99,  40, 'Komponente',  'RAM32-009'),
('Grafička kartica RTX',  'RTX 4070, 12GB GDDR6X',              799.99,  15, 'Komponente',  'GPU4070-010');

-- -----------------------------------------------------------
-- orders
-- -----------------------------------------------------------
INSERT INTO public.orders (user_id, total_amount, status, shipping_address) VALUES
(1, 1299.99, 'delivered',  'Ulica 1 br. 3, 10001 Beograd'),
(2,   49.99, 'delivered',  'Ulica 2 br. 6, 10002 Novi Sad'),
(3,  599.99, 'shipped',    'Ulica 3 br. 9, 10003 Niš'),
(4,   79.99, 'pending',    'Ulica 4 br. 12, 10004 Kragujevac'),
(5,  149.99, 'delivered',  'Ulica 5 br. 15, 10005 Subotica'),
(1,  269.98, 'processing', 'Ulica 1 br. 3, 10001 Beograd'),
(6,  799.99, 'pending',    'Ulica 6 br. 18, 10006 Čačak'),
(7,  189.99, 'shipped',    'Ulica 7 br. 21, 10007 Pančevo'),
(8,  199.99, 'delivered',  'Ulica 8 br. 24, 10008 Beograd'),
(2,  239.98, 'cancelled',  'Ulica 2 br. 6, 10002 Novi Sad');

-- -----------------------------------------------------------
-- audit_log — PII leak u log tabeli (triggeriše +10 bonus score)
-- -----------------------------------------------------------
INSERT INTO public.audit_log (event_type, user_id, email, ip_address, payload) VALUES
('LOGIN_SUCCESS',    1, 'marko.petrovic@gmail.com', '192.168.1.100', '{"browser":"Chrome"}'),
('PASSWORD_CHANGE',  2, 'ana.jovanovic@yahoo.com',  '10.0.0.50',     '{"method":"email_link"}'),
('LOGIN_FAILED',     3, 'stefan.nikolic@hotmail.com','172.16.0.10',  '{"attempts":3}'),
('PROFILE_UPDATE',   4, 'jelena.djordjevic@gmail.com','10.0.0.1',   '{"fields":["phone"]}'),
('LOGOUT',           5, 'nikola.stojanovic@outlook.com','10.10.10.1','{"session":"abc"}'),
('LOGIN_SUCCESS',    6, 'ivana.ilic@gmail.com',      '172.20.0.5',   '{"browser":"Firefox"}'),
('PAYMENT_ADDED',    7, 'alex.pavlovic@gmail.com',   '10.0.0.75',    '{"method":"card"}'),
('LOGIN_SUCCESS',    1, 'marko.petrovic@gmail.com',  '192.168.1.100','{"browser":"Chrome"}'),
('EMAIL_VERIFIED',   8, 'milica.jankovic@gmail.com', '10.0.1.10',   '{"code":"verified"}'),
('ACCOUNT_LOCKED',   9, 'petar.vasic@company.rs',    '192.168.2.50', '{"reason":"too_many_attempts"}'),
('LOGIN_SUCCESS',   10, 'maja.lukic@gmail.com',      '10.5.0.100',   '{"browser":"Safari"}'),
('DATA_EXPORT',     11, 'djordje.marinovic@gmail.com','192.168.3.1', '{"format":"csv"}'),
('SUBSCRIPTION',    12, 'tamara.kostic@yahoo.com',   '10.0.0.200',   '{"plan":"premium"}'),
('LOGIN_SUCCESS',   13, 'luka.bogdanovic@gmail.com', '172.16.5.5',   '{"browser":"Edge"}'),
('PASSWORD_RESET',  14, 'jovana.simic@outlook.com',  '10.20.0.1',    '{"method":"sms"}');

-- -----------------------------------------------------------
-- password_reset_tokens — SHA256 hash-ovi (NE bi trebalo da flaguje plaintext)
-- -----------------------------------------------------------
INSERT INTO public.password_reset_tokens (user_id, token, expires_at) VALUES
(1, 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', NOW() + INTERVAL '1 hour'),
(2, 'b3a8e0e1f9ab1bfe3a36f231f676f78bb28a2d0b8df7a7a8a0c5f5b5e9e9a9b1', NOW() + INTERVAL '1 hour'),
(3, '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', NOW() + INTERVAL '30 min'),
(4, '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', NOW() + INTERVAL '45 min'),
(5, '3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1', NOW() - INTERVAL '1 hour');

-- -----------------------------------------------------------
-- newsletters
-- -----------------------------------------------------------
INSERT INTO public.newsletters (email, first_name) VALUES
('newsletter1@gmail.com',   'Petar'),
('newsletter2@yahoo.com',   'Slavica'),
('newsletter3@outlook.com', 'Marija'),
('info@firma.rs',            'Kontakt'),
('marketing@brand.com',     'Marketing'),
('user.subscribe@mail.com', 'Subscriber'),
('test.user@testmail.com',  'Test');

-- -----------------------------------------------------------
-- app.employees
-- -----------------------------------------------------------
INSERT INTO app.employees (first_name, last_name, email, phone, jmbg, salary, position, hired_at) VALUES
('Gordana',  'Milović',   'gordana.milovic@firma.rs',   '+381641111001', '1502197510001',  95000.00, 'HR Manager',          '2015-03-01'),
('Radiša',   'Trifunović','radisa.trifunovic@firma.rs', '+381641111002', '2203198520002',  120000.00,'CTO',                 '2012-06-15'),
('Biljana',  'Cvetić',    'biljana.cvetic@firma.rs',    '+381641111003', '0507199030003',  75000.00, 'Developer',           '2019-09-01'),
('Miroslav', 'Đurišić',   'miroslav.djurisic@firma.rs', '+381641111004', '1109196840004',  85000.00, 'Senior Developer',    '2018-02-14'),
('Svetlana', 'Krstić',    'svetlana.krstic@firma.rs',   '+381641111005', '2811199250005',  70000.00, 'QA Engineer',         '2020-11-01'),
('Branislav','Nedić',     'branislav.nedic@firma.rs',   '+381641111006', '1704198060006',  110000.00,'DevOps Engineer',     '2017-04-01'),
('Veseljko', 'Bošković',  'veseljko.boskovic@firma.rs', '+381641111007', '0612197570007',  130000.00,'Head of Engineering', '2010-01-15'),
('Tatjana',  'Đurević',   'tatjana.djurevic@firma.rs',  '+381641111008', '2309199280008',  65000.00, 'Designer',            '2021-07-01');

-- -----------------------------------------------------------
-- app.oauth_tokens — JWT + UUID refresh tokeni
-- -----------------------------------------------------------
INSERT INTO app.oauth_tokens (user_id, access_token, refresh_token, client_id, expires_at) VALUES
(1, 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxIiwiZW1haWwiOiJtYXJrby5wZXRyb3ZpY0BnbWFpbC5jb20iLCJpYXQiOjE3MDkwMDAwMDB9.oauth_signature_here_abcdef1234',
    '550e8400-e29b-41d4-a716-446655440001', 'web_client_v2', NOW() + INTERVAL '1 hour'),
(2, 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIyIiwiZW1haWwiOiJhbmEuam92YW5vdmljQHlhaG9vLmNvbSIsImlhdCI6MTcwOTAwMDAwMH0.another_oauth_signature_xyz789',
    '6ba7b810-9dad-11d1-80b4-00c04fd430c8', 'mobile_app_v3', NOW() + INTERVAL '1 hour'),
(3, 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIzIiwiaWF0IjoxNzA5MDAwMDAwfQ.third_oauth_token_signature_def456ghi',
    '7c9e6679-7425-40de-944b-e07fc1f90ae7', 'web_client_v2', NOW() + INTERVAL '2 hours');

-- -----------------------------------------------------------
-- app.config — NAJGORI SCENARIO: plaintext secrets u config tabeli
-- -----------------------------------------------------------
INSERT INTO app.config (key, value, description) VALUES
('stripe_secret_key',   'sk_live_51NzXXXXXXXXXXXXXXXXXXXXXXXX', 'Stripe payment secret key'),
('aws_access_key',      'AKIAIOSFODNN7EXAMPLE',                    'AWS IAM access key'),
('aws_secret',          'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'AWS IAM secret'),
('sendgrid_api_key',    'SG.xxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyy', 'SendGrid email API key'),
('jwt_secret',          'mySuperSecretJWTKey2024!@#$',             'JWT signing secret'),
('db_password',         'ProductionDbPass2024!',                   'Backup DB password'),
('recaptcha_secret',    '6LeXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', 'Google reCAPTCHA secret'),
('encryption_key',      'AES256Key-32bytes-long-key-here!!',       'AES encryption key'),
('smtp_password',       'smtp_prod_password_2024',                 'SMTP server password'),
('webhook_secret',      'whsec_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',  'Stripe webhook secret');

-- =============================================================
-- Kreiranje read-only scanner role-a (opciono, ali preporučeno)
-- =============================================================

-- Pokreni ovo odvojeno ako hoćeš read-only usera:
-- CREATE ROLE dbqa_scanner LOGIN PASSWORD 'scanner_pass_2024';
-- GRANT CONNECT ON DATABASE dbqa_testdb TO dbqa_scanner;
-- GRANT USAGE ON SCHEMA public TO dbqa_scanner;
-- GRANT USAGE ON SCHEMA app TO dbqa_scanner;
-- GRANT SELECT ON ALL TABLES IN SCHEMA public TO dbqa_scanner;
-- GRANT SELECT ON ALL TABLES IN SCHEMA app TO dbqa_scanner;

-- =============================================================
-- Verifikacija — koliko redova gde
-- =============================================================
SELECT 'public.users'                  AS tabela, COUNT(*) AS redova FROM public.users
UNION ALL SELECT 'public.user_profiles',           COUNT(*) FROM public.user_profiles
UNION ALL SELECT 'public.payment_methods',         COUNT(*) FROM public.payment_methods
UNION ALL SELECT 'public.api_keys',                COUNT(*) FROM public.api_keys
UNION ALL SELECT 'public.sessions',                COUNT(*) FROM public.sessions
UNION ALL SELECT 'public.products',                COUNT(*) FROM public.products
UNION ALL SELECT 'public.orders',                  COUNT(*) FROM public.orders
UNION ALL SELECT 'public.audit_log',               COUNT(*) FROM public.audit_log
UNION ALL SELECT 'public.password_reset_tokens',   COUNT(*) FROM public.password_reset_tokens
UNION ALL SELECT 'public.newsletters',             COUNT(*) FROM public.newsletters
UNION ALL SELECT 'app.employees',                  COUNT(*) FROM app.employees
UNION ALL SELECT 'app.oauth_tokens',               COUNT(*) FROM app.oauth_tokens
UNION ALL SELECT 'app.config',                     COUNT(*) FROM app.config
ORDER BY tabela;
