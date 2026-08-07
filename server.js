const express = require('express');
const { Pool } = require('pg');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();

// 🛡️ Seguridad base
// - helmet añade cabeceras seguras por defecto (oculta X-Powered-By, evita
//   sniffing de tipo MIME, fija Content-Security-Policy básica, etc.)
app.disable('x-powered-by');
// La app sirve HTML estático con <script> y <style> inline (sin build
// step ni archivos .js/.css separados), así que el CSP por defecto de
// helmet (que bloquea todo lo inline) rompería el JavaScript de cada
// página. Lo abrimos explícitamente para inline + Google Fonts, y
// dejamos el resto de protecciones de helmet como están.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "script-src": ["'self'", "'unsafe-inline'"],
      "script-src-attr": ["'self'", "'unsafe-inline'"],
      "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      "font-src": ["'self'", "https://fonts.gstatic.com", "data:"]
    }
  }
}));

// - límite de peticiones por IP: mitiga fuerza bruta / scraping masivo
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 300,                 // peticiones por IP en esa ventana
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

// Les respostes de l'API no s'han de guardar mai en caché del navegador —
// són dades que canvien sovint (assajos, plantilles, posicions...) i un
// refresc normal podria ensenyar-te una versió antiga sense que et
// n'adonis. Això evita haver de fer "refresc forçat" cada vegada.
app.use('/api/', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

app.use(express.json({ limit: '1mb' })); // límite de tamaño de body, evita payloads gigantes
app.use(express.static('public', {
  dotfiles: 'deny', // nunca sirvas .env, .git, etc.
  index: ['index.html']
}));

// Nota sobre inyección SQL: todas las consultas de este archivo usan
// parámetros ($1, $2...) de node-postgres en vez de concatenar texto, que
// es la defensa real contra SQL injection. Nunca metas variables directamente
// dentro de un template string SQL (`... WHERE x = ${valor}`), siempre $n.

// 🔑 Conexión a PostgreSQL (Render)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Respuesta de error genérica: registra el detalle real en el log del
// servidor (Render lo verás en tus logs), pero nunca lo devuelve tal cual
// al cliente — un mensaje de error de Postgres puede revelar nombres de
// tabla/columna útiles para un atacante.
function errorHandler(res, error, mensajePublico = 'Error del servidor') {
  console.error(error);
  res.status(500).json({ success: false, error: mensajePublico });
}

// 🔐 Sesiones: se guardan en la misma base de datos Postgres (tabla
// "session", se crea sola) en vez de en memoria, para que sobrevivan a
// reinicios/redeploys y funcionen igual aunque haya varias instancias.
// Render está detrás de un proxy: hace falta "trust proxy" para que la
// cookie "secure" (solo por https) funcione bien.
app.set('trust proxy', 1);
app.use(session({
  store: new pgSession({ pool, tableName: 'session', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'castellers-dev-secret-canvia-això-en-produccio',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 dies
  }
}));

// Middleware: exigeix sessió iniciada
async function requireLogin(req, res, next) {
  if (!req.session || !req.session.usuarioId) {
    return res.status(401).json({ success: false, error: 'Cal iniciar sessió' });
  }
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE "id" = $1', [req.session.usuarioId]);
    if (result.rows.length === 0 || result.rows[0].estado !== 'activo') {
      req.session.destroy(() => {});
      return res.status(401).json({ success: false, error: 'Sessió no vàlida' });
    }
    req.usuarioActual = result.rows[0];
    next();
  } catch (error) {
    errorHandler(res, error);
  }
}

// Middleware: exigeix, a més, permís d'AdminGeneral
function requireAdmin(req, res, next) {
  if (!req.usuarioActual || !(req.usuarioActual.permisos || []).includes('AdminGeneral')) {
    return res.status(403).json({ success: false, error: 'Necessites permisos d\'administrador' });
  }
  next();
}

// Exigeix el permís "GestioMembres" (o ser AdminGeneral, que sempre té accés
// a tot) — protegeix les accions de gestió del mòdul de membres.
function requireGestioMembres(req, res, next) {
  const permisos = (req.usuarioActual && req.usuarioActual.permisos) || [];
  if (!permisos.includes('GestioMembres') && !permisos.includes('AdminGeneral')) {
    return res.status(403).json({ success: false, error: 'Necessites permisos de gestió de membres' });
  }
  next();
}

// 🔒 Guardia global: TOTA la API exigeix sessió iniciada, tret de les rutes
// d'autenticació en si mateixes (login/registre/verificació...) i de les
// rutes temporals de migració (que ja de per si s'han d'esborrar aviat).
// Això és el que de veritat protegeix les dades — l'ocultació visual al
// frontend (CSS/redirect) és només per evitar el parpelleig, mai seguretat
// real: sense això, qualsevol podria trucar directament a l'API sense passar
// per cap pàgina ni sessió.
const RUTAS_PUBLICAS_API = new Set([
  '/api/auth/registro', '/api/auth/login', '/api/auth/logout',
  '/api/auth/verificar-email', '/api/auth/reenviar-verificacion', '/api/auth/me'
]);
app.use('/api/', (req, res, next) => {
  const rutaCompleta = req.originalUrl.split('?')[0];
  const esTemporal = /^\/api\/(migrate-|bootstrap-admin|migrar-a-supabase|debug-|test-|fix-id-sequence|reset-miembros)/.test(rutaCompleta);
  if (RUTAS_PUBLICAS_API.has(rutaCompleta) || esTemporal) return next();
  requireLogin(req, res, next);
});

// ✉️ Correu (verificació d'email + avisos). Configuració 100% per variables
// d'entorn perquè canviar de Gmail a un altre proveïdor (ex. el correu
// @castellersdetortosa.cat el dia que hi tinguis accés) sigui només canviar
// aquestes variables a Render, sense tocar ni una línia de codi:
//   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
// Per Gmail: SMTP_HOST=smtp.gmail.com, SMTP_PORT=587, SMTP_USER=el teu gmail,
// SMTP_PASS=una "contrasenya d'aplicació" (no la contrasenya normal del compte).
// ✉️ Correu (verificació d'email + avisos). Prioritzem Resend (funciona per
// HTTPS, no per un port SMTP — necessari perquè Render bloqueja els ports
// SMTP tradicionals al pla gratuït). Si no hi ha RESEND_API_KEY, cau cap a
// SMTP (útil el dia que hi hagi un pla de pagament o un altre proveïdor que
// sí accepti SMTP). Sense cap de les dues, es queda en mode "simulat" (log).
let mailer = null;
if (!process.env.RESEND_API_KEY && process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    // si el proveïdor/xarxa bloqueja la connexió (com fa Render al pla
    // gratuït amb els ports SMTP), que falli de seguida en comptes de deixar
    // la petició penjada per sempre esperant una resposta que no arribarà
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 10000
  });
} else if (!process.env.RESEND_API_KEY) {
  console.warn('⚠️ Ni RESEND_API_KEY ni SMTP configurats — els correus només es mostraran al log del servidor, no s\'enviaran de veritat.');
}

async function enviarCorreo({ to, subject, html }) {
  if (process.env.RESEND_API_KEY) {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: process.env.SMTP_FROM || 'onboarding@resend.dev',
        to: [to],
        subject,
        html
      })
    });
    if (!resp.ok) {
      const detalle = await resp.text().catch(() => '');
      throw new Error(`Resend ha respost ${resp.status}: ${detalle}`);
    }
  } else if (mailer) {
    await mailer.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to, subject, html
    });
  } else {
    // Sense cap proveïdor configurat: deixem constància al log perquè es
    // pugui provar el flux igualment (mira els logs de Render per veure
    // l'enllaç).
    console.log(`📧 [correu simulat, sense proveïdor configurat] Per a: ${to} | Assumpte: ${subject}\n${html}`);
  }
}

// 🔥 TEST DB
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({
      success: true,
      time: result.rows[0],
    });
  } catch (error) {
    errorHandler(res, error, 'No se pudo conectar a la base de datos');
  }
});

// ⚠️ TEMPORAL: BORRA la tabla castellers ENTERA (todas las columnas y filas)
// y la crea de nuevo con el esquema alineado 1:1 al CSV. Sin ?confirm=si
// solo muestra un aviso; con ?confirm=si sí que la borra y recrea.
// BÓRRALA del código en cuanto la hayas ejecutado una vez.
// ⚠️ TEMPORAL: BORRA por completo los datos de miembros (castellers +
// sus rols de castell asignados) y recrea la tabla con el esquema FINAL
// (con "posicionPinyaId", sin la vieja columna "rol"). Los catálogos
// roles_castillo / posiciones_pinya NO se tocan (se crean/siembran si
// faltan). Sin ?confirm=si solo avisa. BÓRRALA del código en cuanto la
// hayas ejecutado.
app.get('/api/reset-miembros', async (req, res) => {
  if (req.query.confirm !== 'si') {
    return res.json({
      success: false,
      aviso: 'Esto BORRA todos los castellers y sus rols asignados, y recrea la tabla con el esquema final. Añade ?confirm=si para confirmar, ej: /api/reset-miembros?confirm=si'
    });
  }

  const statements = [
    `CREATE TABLE IF NOT EXISTS posiciones_pinya (
       "id" SERIAL PRIMARY KEY,
       "nombre" TEXT UNIQUE NOT NULL
     )`,
    `CREATE TABLE IF NOT EXISTS roles_castillo (
       "id" SERIAL PRIMARY KEY,
       "nombre" TEXT UNIQUE NOT NULL
     )`,
    `INSERT INTO posiciones_pinya ("nombre") VALUES
       ('MANS'), ('NOVATOS'), ('CROSSES'), ('LATERALS'), ('CONTRAFORTS'),
       ('BAIXOS'), ('DAUS'), ('GRALLES I TABALS'), ('ALTRES')
     ON CONFLICT ("nombre") DO NOTHING`,
    `INSERT INTO roles_castillo ("nombre") VALUES
       ('Baix'), ('Segon'), ('Terç'), ('Acotxador'), ('Enxaneta')
     ON CONFLICT ("nombre") DO NOTHING`,
    `DROP TABLE IF EXISTS casteller_roles`,
    `DROP TABLE IF EXISTS castellers CASCADE`,
    `CREATE TABLE castellers (
       "id" INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       "nombre" TEXT NOT NULL,
       "primerApellido" TEXT,
       "segundoApellido" TEXT,
       "apodo" TEXT,
       "posicionPinyaId" INTEGER REFERENCES posiciones_pinya("id"),
       "accesoAPP" BOOLEAN,
       "correo" TEXT,
       "fNac" DATE,
       "movil" TEXT,
       "fechaCamisa" DATE,
       "alturaHombros" INTEGER,
       "revisado" BOOLEAN,
       "estadoAcogida" TEXT,
       "habitual" BOOLEAN,
       "permisosAPP" TEXT[],
       "integranteColla" BOOLEAN,
       "lesionLargoPlazo" BOOLEAN,
       "formularios" INTEGER,
       "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
     )`,
    `CREATE TABLE casteller_roles (
       "castellerId" INTEGER NOT NULL REFERENCES castellers("id") ON DELETE CASCADE,
       "rolId" INTEGER NOT NULL REFERENCES roles_castillo("id") ON DELETE CASCADE,
       "orden" INTEGER NOT NULL,
       PRIMARY KEY ("castellerId", "rolId")
     )`
  ];

  const resultados = [];
  for (const sql of statements) {
    try {
      await pool.query(sql);
      resultados.push({ sql, ok: true });
    } catch (err) {
      resultados.push({ sql, ok: false, error: err.message });
    }
  }

  const fallos = resultados.filter(r => !r.ok);
  res.json({
    success: fallos.length === 0,
    detalle: resultados,
    aviso: 'Tabla de miembros recreada. Borra /api/reset-miembros del server.js ahora que ya la has usado. Después de importar el CSV, visita una vez /api/fix-id-sequence.'
  });
});

// ⚠️ TEMPORAL: separa "rol" (texto libre, hoy la Posició del CSV) en dos
// conceptos: catálogo de posicions de pinya (FK, un valor por casteller) y
// catálogo de rols de castell (vector ordenado, varios por casteller, vía
// la taula pont casteller_roles). Migra los datos existentes de "rol" hacia
// "posicionPinyaId" antes de borrar la columna de texto. Sin ?confirm=si
// solo avisa. BÓRRALA del código en cuanto la hayas ejecutado.
app.get('/api/migrate-roles', async (req, res) => {
  if (req.query.confirm !== 'si') {
    return res.json({
      success: false,
      aviso: 'Esto crea roles_castillo, posiciones_pinya y casteller_roles, migra "rol" a "posicionPinyaId" y borra la columna "rol". Añade ?confirm=si para confirmar.'
    });
  }

  const statements = [
    `CREATE TABLE IF NOT EXISTS roles_castillo (
       "id" SERIAL PRIMARY KEY,
       "nombre" TEXT UNIQUE NOT NULL
     )`,
    `CREATE TABLE IF NOT EXISTS posiciones_pinya (
       "id" SERIAL PRIMARY KEY,
       "nombre" TEXT UNIQUE NOT NULL
     )`,
    `INSERT INTO roles_castillo ("nombre") VALUES
       ('Baix'), ('Segon'), ('Terç'), ('Acotxador'), ('Enxaneta')
     ON CONFLICT ("nombre") DO NOTHING`,
    `INSERT INTO posiciones_pinya ("nombre") VALUES
       ('MANS'), ('NOVATOS'), ('CROSSES'), ('LATERALS'), ('CONTRAFORTS'),
       ('BAIXOS'), ('DAUS'), ('GRALLES I TABALS'), ('ALTRES')
     ON CONFLICT ("nombre") DO NOTHING`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS "posicionPinyaId" INTEGER REFERENCES posiciones_pinya("id")`,
    `UPDATE castellers c
       SET "posicionPinyaId" = pp."id"
       FROM posiciones_pinya pp
       WHERE pp."nombre" = c."rol" AND c."posicionPinyaId" IS NULL`,
    `ALTER TABLE castellers DROP COLUMN IF EXISTS "rol"`,
    `CREATE TABLE IF NOT EXISTS casteller_roles (
       "castellerId" INTEGER NOT NULL REFERENCES castellers("id") ON DELETE CASCADE,
       "rolId" INTEGER NOT NULL REFERENCES roles_castillo("id") ON DELETE CASCADE,
       "orden" INTEGER NOT NULL,
       PRIMARY KEY ("castellerId", "rolId")
     )`
  ];

  const resultados = [];
  for (const sql of statements) {
    try {
      await pool.query(sql);
      resultados.push({ sql, ok: true });
    } catch (err) {
      resultados.push({ sql, ok: false, error: err.message });
    }
  }

  const fallos = resultados.filter(r => !r.ok);
  res.json({
    success: fallos.length === 0,
    detalle: resultados,
    aviso: 'Borra /api/migrate-roles del server.js ahora que ya la has ejecutado.'
  });
});

// ⚠️ TEMPORAL: tras importar el CSV (que trae sus propios "id" con huecos,
// del 1 al 1434), la secuencia interna de autoincremento de Postgres no se
// entera de esos valores. Esto la deja apuntando al siguiente número libre,
// para que añadir un casteller nuevo a mano no choque con un id importado.
// BÓRRALA también del código cuando ya no la necesites.
app.get('/api/fix-id-sequence', async (req, res) => {
  try {
    await pool.query(
      `SELECT setval(pg_get_serial_sequence('castellers', 'id'), COALESCE((SELECT MAX("id") FROM castellers), 1))`
    );
    res.json({ success: true, mensaje: 'Seqüència d\'id ajustada correctament.' });
  } catch (error) {
    errorHandler(res, error);
  }
});

// api para cargar miembros y sus datos
app.post('/api/castellers', requireGestioMembres, async (req, res) => {
  try {
    const {
      id, nombre, primerApellido, segundoApellido, apodo, posicionPinyaId,
      accesoAPP, correo, fNac, movil, fechaCamisa, alturaHombros,
      revisado, estadoAcogida, habitual, permisosAPP, integranteColla,
      lesionLargoPlazo, formularios
    } = req.body;

    if (!nombre) {
      return res.status(400).json({ error: 'nombre es obligatorio' });
    }

    const columnas = [
      'nombre', 'primerApellido', 'segundoApellido', 'apodo', 'posicionPinyaId',
      'accesoAPP', 'correo', 'fNac', 'movil', 'fechaCamisa', 'alturaHombros',
      'revisado', 'estadoAcogida', 'habitual', 'permisosAPP', 'integranteColla',
      'lesionLargoPlazo', 'formularios'
    ];
    const valores = [
      nombre,
      primerApellido || null,
      segundoApellido || null,
      apodo || null,
      (posicionPinyaId === '' || posicionPinyaId === undefined) ? null : posicionPinyaId,
      accesoAPP === undefined ? null : accesoAPP,
      correo || null,
      fNac || null,
      movil || null,
      fechaCamisa || null,
      (alturaHombros === '' || alturaHombros === undefined) ? null : alturaHombros,
      revisado === undefined ? null : revisado,
      estadoAcogida || null,
      habitual === undefined ? null : habitual,
      Array.isArray(permisosAPP) ? permisosAPP : (permisosAPP ? [permisosAPP] : null),
      integranteColla === undefined ? null : integranteColla,
      lesionLargoPlazo === undefined ? null : lesionLargoPlazo,
      (formularios === '' || formularios === undefined) ? null : formularios
    ];

    // Si viene un "id" explícito (p. ej. al importar el CSV), lo respetamos.
    // Si no, dejamos que la tabla lo autogenere (alta manual de un casteller).
    if (id !== undefined && id !== null && id !== '') {
      columnas.unshift('id');
      valores.unshift(id);
    }

    const columnasSQL = columnas.map(c => `"${c}"`).join(', ');
    const placeholders = columnas.map((_, i) => `$${i + 1}`).join(', ');

    const result = await pool.query(
      `INSERT INTO castellers (${columnasSQL}) VALUES (${placeholders}) RETURNING *`,
      valores
    );

    res.json({
      success: true,
      casteller: result.rows[0]
    });

  } catch (error) {
    errorHandler(res, error);
  }
});

//api para visualizar miembros (incluye posició pinya i el vector de rols de castell)
app.get('/api/castellers', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        c.*,
        pp."nombre" AS "posicionPinyaNombre",
        COALESCE(
          (SELECT json_agg(json_build_object('id', rc."rolId", 'nombre', rcast."nombre", 'orden', rc."orden") ORDER BY rc."orden")
           FROM casteller_roles rc
           JOIN roles_castillo rcast ON rcast."id" = rc."rolId"
           WHERE rc."castellerId" = c."id"),
          '[]'
        ) AS "rolesCastell"
      FROM castellers c
      LEFT JOIN posiciones_pinya pp ON pp."id" = c."posicionPinyaId"
      ORDER BY c."id" DESC
    `);
    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    errorHandler(res, error);
  }
});

//api para el catàleg de posicions de pinya
app.get('/api/posiciones-pinya', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM posiciones_pinya ORDER BY "id"');
    res.json({ success: true, data: result.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

//api para el catàleg de rols de castell
app.get('/api/roles-castillo', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM roles_castillo ORDER BY "id"');
    res.json({ success: true, data: result.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

//api per llegir el vector de rols (ordenat) d'un casteller concret
app.get('/api/castellers/:id/roles', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT rc."rolId" AS "id", rcast."nombre", rc."orden"
       FROM casteller_roles rc
       JOIN roles_castillo rcast ON rcast."id" = rc."rolId"
       WHERE rc."castellerId" = $1
       ORDER BY rc."orden"`,
      [id]
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

//api per desar el vector de rols (ordenat, el primer és el principal) d'un casteller
app.put('/api/castellers/:id/roles', requireGestioMembres, async (req, res) => {
  const { id } = req.params;
  const { rolIds } = req.body; // array ordenat d'ids de roles_castillo

  if (!Array.isArray(rolIds)) {
    return res.status(400).json({ error: 'rolIds ha de ser un array d\'ids, en ordre (principal primer)' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM casteller_roles WHERE "castellerId" = $1', [id]);

    for (let i = 0; i < rolIds.length; i++) {
      await client.query(
        `INSERT INTO casteller_roles ("castellerId", "rolId", "orden") VALUES ($1, $2, $3)`,
        [id, rolIds[i], i + 1]
      );
    }

    await client.query('COMMIT');
    res.json({ success: true });
  } catch (error) {
    await client.query('ROLLBACK');
    errorHandler(res, error);
  } finally {
    client.release();
  }
});

//api para editar un miembro existente
app.put('/api/castellers/:id', requireGestioMembres, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      nombre, primerApellido, segundoApellido, apodo, posicionPinyaId,
      accesoAPP, correo, fNac, movil, fechaCamisa, alturaHombros,
      revisado, estadoAcogida, habitual, permisosAPP, integranteColla,
      lesionLargoPlazo, formularios
    } = req.body;

    if (!nombre) {
      return res.status(400).json({ error: 'nombre es obligatorio' });
    }

    const result = await pool.query(
      `UPDATE castellers SET
         "nombre" = $1, "primerApellido" = $2, "segundoApellido" = $3, "apodo" = $4, "posicionPinyaId" = $5,
         "accesoAPP" = $6, "correo" = $7, "fNac" = $8, "movil" = $9, "fechaCamisa" = $10,
         "alturaHombros" = $11, "revisado" = $12, "estadoAcogida" = $13, "habitual" = $14,
         "permisosAPP" = $15, "integranteColla" = $16, "lesionLargoPlazo" = $17, "formularios" = $18
       WHERE "id" = $19
       RETURNING *`,
      [
        nombre,
        primerApellido || null,
        segundoApellido || null,
        apodo || null,
        (posicionPinyaId === '' || posicionPinyaId === undefined) ? null : posicionPinyaId,
        accesoAPP === undefined ? null : accesoAPP,
        correo || null,
        fNac || null,
        movil || null,
        fechaCamisa || null,
        (alturaHombros === '' || alturaHombros === undefined) ? null : alturaHombros,
        revisado === undefined ? null : revisado,
        estadoAcogida || null,
        habitual === undefined ? null : habitual,
        Array.isArray(permisosAPP) ? permisosAPP : (permisosAPP ? [permisosAPP] : null),
        integranteColla === undefined ? null : integranteColla,
        lesionLargoPlazo === undefined ? null : lesionLargoPlazo,
        (formularios === '' || formularios === undefined) ? null : formularios,
        id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Casteller no trobat' });
    }

    res.json({
      success: true,
      casteller: result.rows[0]
    });

  } catch (error) {
    errorHandler(res, error);
  }
});

// Elimina un casteller. Exigeix tornar a introduir la contrasenya de qui fa
// l'acció (l'usuari amb sessió iniciada, no el membre) com a confirmació
// extra abans d'un esborrat permanent. Les taules relacionades (rols,
// posicions assignades en assajos, comptes d'usuari vinculats) ja tenen
// ON DELETE CASCADE / SET NULL definit, així que s'esborren o desvinculen
// soles.
app.delete('/api/castellers/:id', requireGestioMembres, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ success: false, error: 'Cal introduir la contrasenya per confirmar' });
    const coincide = await bcrypt.compare(password, req.usuarioActual.passwordHash);
    if (!coincide) return res.status(400).json({ success: false, error: 'Contrasenya incorrecta' });

    const result = await pool.query('DELETE FROM castellers WHERE "id" = $1 RETURNING "id"', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'No trobat' });

    res.json({ success: true });
  } catch (error) {
    errorHandler(res, error);
  }
});

//api generar castells
// Cada casteller ahora puede tener VARIOS rols de castell asignados
// (baix/segon/terç/acotxador/enxaneta), guardados en casteller_roles con un
// orden (1 = principal). Para generar propuestas, contamos a alguien como
// elegible para un rol si ese rol está en su vector, sin importar el orden
// — es una asunción de partida (cualquier rol asignado cuenta igual), no
// distingue todavía "rol principal" de "también sabe hacerlo".
app.get('/api/generar', async (req, res) => {
  try {
    const resultado = await pool.query(`
      SELECT
        c."id", c."nombre", c."alturaHombros",
        COALESCE(
          array_agg(lower(rcast."nombre")) FILTER (WHERE rcast."nombre" IS NOT NULL),
          '{}'
        ) AS roles
      FROM castellers c
      LEFT JOIN casteller_roles rc ON rc."castellerId" = c."id"
      LEFT JOIN roles_castillo rcast ON rcast."id" = rc."rolId"
      GROUP BY c."id"
    `);
    const castellers = resultado.rows;

    const obtenerMasAltos = (arr) => [...arr].sort((a, b) => b.alturaHombros - a.alturaHombros);
    const obtenerMasBajos = (arr) => [...arr].sort((a, b) => a.alturaHombros - b.alturaHombros);

    const estructuras = [
      { nombre: '2d6', segons: 2, tersos: 2 },
      { nombre: '3d7', segons: 3, tersos: 3 },
      { nombre: '4d7', segons: 4, tersos: 4 },
      { nombre: '5d7', segons: 5, tersos: 5 }
    ];

    const calcularRiesgo = ({ baix, segons, tersos, pom }) => {
      let riesgo = 0;

      const mediaSegons = segons.reduce((acc, s) => acc + s.alturaHombros, 0) / segons.length;
      const mediaTersos = tersos.reduce((acc, t) => acc + t.alturaHombros, 0) / tersos.length;

      riesgo += Math.abs(baix.alturaHombros - mediaSegons) * 0.3;
      riesgo += Math.abs(mediaSegons - mediaTersos) * 0.3;

      if (pom.enxaneta.alturaHombros > 140) riesgo += 20;
      if (pom.acotxador.alturaHombros > 150) riesgo += 15;

      return Math.round(riesgo);
    };

    const clasificarRiesgo = (riesgo) => {
      if (riesgo < 20) return '🟢 Seguro';
      if (riesgo < 50) return '🟡 Medio';
      return '🔴 Alto';
    };

    const generarParaEstructura = (config) => {

      const baixos = castellers.filter(c => c.roles.includes('baix'));
      const segons = castellers.filter(c => c.roles.includes('segon'));
      const tersos = castellers.filter(c => c.roles.includes('terç'));
      const acotxadors = castellers.filter(c => c.roles.includes('acotxador'));
      const enxanetes = castellers.filter(c => c.roles.includes('enxaneta'));

      const resultado = {
        tipo: config.nombre,
        valido: true,
        mensajes: []
      };

      if (baixos.length < 1) {
        resultado.valido = false;
        resultado.mensajes.push('Falta baix');
      }

      if (segons.length < config.segons) {
        resultado.valido = false;
        resultado.mensajes.push(`Faltan segons (${config.segons})`);
      }

      if (tersos.length < config.tersos) {
        resultado.valido = false;
        resultado.mensajes.push(`Faltan tersos (${config.tersos})`);
      }

      if (acotxadors.length < 1) {
        resultado.valido = false;
        resultado.mensajes.push('Falta acotxador');
      }

      if (enxanetes.length < 1) {
        resultado.valido = false;
        resultado.mensajes.push('Falta enxaneta');
      }

      if (!resultado.valido) return resultado;

      const estructura = {
        baix: obtenerMasAltos(baixos)[0],
        segons: obtenerMasAltos(segons).slice(0, config.segons),
        tersos: obtenerMasAltos(tersos).slice(0, config.tersos),
        pom: {
          acotxador: obtenerMasBajos(acotxadors)[0],
          enxaneta: obtenerMasBajos(enxanetes)[0]
        }
      };

      const riesgo = calcularRiesgo(estructura);
      const nivel = clasificarRiesgo(riesgo);

      resultado.estructura = estructura;
      resultado.riesgo = riesgo;
      resultado.nivel = nivel;

      return resultado;
    };

    const propuestas = estructuras.map(config => generarParaEstructura(config));

    res.json({
      success: true,
      propuestas
    });

  } catch (error) {
    console.error(error);
    res.status(500).send('Error generando castells');
  }
});

/* =========================================================
   MÒDUL ENSAJOS
   ========================================================= */

// ⚠️ TEMPORAL: crea les taules d'ensayos i assistència. Sense ?confirm=si
// només avisa. BÓRRALA del server.js en cuanto la hayas ejecutado.
app.get('/api/migrate-ensayos', async (req, res) => {
  if (req.query.confirm !== 'si') {
    return res.json({
      success: false,
      aviso: 'Esto crea las tablas ensayos y ensayo_asistentes. Añade ?confirm=si para confirmar.'
    });
  }

  const statements = [
    `CREATE TABLE IF NOT EXISTS ensayos (
       "id" SERIAL PRIMARY KEY,
       "fecha" DATE NOT NULL,
       "horaInicio" TIME,
       "horaFin" TIME,
       "notas" TEXT,
       "publicado" BOOLEAN NOT NULL DEFAULT FALSE,
       "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
     )`,
    `CREATE TABLE IF NOT EXISTS ensayo_asistentes (
       "ensayoId" INTEGER NOT NULL REFERENCES ensayos("id") ON DELETE CASCADE,
       "castellerId" INTEGER NOT NULL REFERENCES castellers("id") ON DELETE CASCADE,
       PRIMARY KEY ("ensayoId", "castellerId")
     )`
  ];

  const resultados = [];
  for (const sql of statements) {
    try {
      await pool.query(sql);
      resultados.push({ sql, ok: true });
    } catch (err) {
      resultados.push({ sql, ok: false, error: err.message });
    }
  }

  res.json({
    success: resultados.every(r => r.ok),
    detalle: resultados,
    aviso: 'Borra /api/migrate-ensayos del server.js ahora que ya la has ejecutado.'
  });
});

// ⚠️ TEMPORAL: crea las tablas de estructuras guardadas por assaig
// (el castell/pinya que se decide conservar) y sus posiciones. Sin
// ?confirm=si solo avisa. BÓRRALA del server.js en cuanto la hayas ejecutado.
app.get('/api/migrate-estructuras', async (req, res) => {
  if (req.query.confirm !== 'si') {
    return res.json({
      success: false,
      aviso: 'Esto crea las tablas estructuras_ensayo y estructura_posiciones. Añade ?confirm=si para confirmar.'
    });
  }

  const statements = [
    `CREATE TABLE IF NOT EXISTS estructuras_ensayo (
       "id" SERIAL PRIMARY KEY,
       "ensayoId" INTEGER NOT NULL REFERENCES ensayos("id") ON DELETE CASCADE,
       "tipo" TEXT NOT NULL,
       "notas" TEXT,
       "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
     )`,
    // "slot" = nombre de la posición (Baix, Crossa, Soca, Rengle...) tal
    // como aparece en las plantillas; "slotIndex" distingue repeticiones
    // (Crossa-1, Crossa-2...). castellerId nulo = posición vacía todavía.
    `CREATE TABLE IF NOT EXISTS estructura_posiciones (
       "id" SERIAL PRIMARY KEY,
       "estructuraEnsayoId" INTEGER NOT NULL REFERENCES estructuras_ensayo("id") ON DELETE CASCADE,
       "slot" TEXT NOT NULL,
       "slotIndex" INTEGER NOT NULL DEFAULT 1,
       "castellerId" INTEGER REFERENCES castellers("id") ON DELETE SET NULL,
       UNIQUE ("estructuraEnsayoId", "slot", "slotIndex")
     )`
  ];

  const resultados = [];
  for (const sql of statements) {
    try {
      await pool.query(sql);
      resultados.push({ sql, ok: true });
    } catch (err) {
      resultados.push({ sql, ok: false, error: err.message });
    }
  }

  res.json({
    success: resultados.every(r => r.ok),
    detalle: resultados,
    aviso: 'Borra /api/migrate-estructuras del server.js ahora que ya la has ejecutado.'
  });
});

// Crear una estructura guardada dentro de un assaig (p.ex. al pulsar
// "Desar aquesta proposta" en el modal de propostes de castells)
app.post('/api/ensayos/:id/estructuras', async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const { tipo, notas } = req.body;
    if (!tipo) return res.status(400).json({ error: 'tipo es obligatorio' });

    // Niveles reals definits a l'editor de castells per a aquest tipus.
    // L'ordre de la llista importa: el PRIMER nivell rep els membres més
    // baixos (ex. Enxaneta), l'ÚLTIM els més alts (ex. Baix) — es pot
    // reordenar arrossegant a l'editor de castells.
    const estructuraDefResult = await client.query(
      `SELECT "niveles" FROM castells_estructura WHERE "tipo" = $1`,
      [tipo]
    );
    const nivelesDefinidos = estructuraDefResult.rows[0] ? estructuraDefResult.rows[0].niveles : null;

    // Si encara no hi ha una estructura de castell definida per a aquest
    // tipus, fem servir uns nivells per defecte (compatibilitat amb el
    // comportament anterior).
    const configsPerDefecte = {
      '2d6': [{ nombre: 'Enxaneta', cantidad: 1 }, { nombre: 'Acotxador', cantidad: 1 }, { nombre: 'Terç', cantidad: 2 }, { nombre: 'Segon', cantidad: 2 }, { nombre: 'Baix', cantidad: 2 }],
      '3d7': [{ nombre: 'Enxaneta', cantidad: 1 }, { nombre: 'Acotxador', cantidad: 1 }, { nombre: 'Terç', cantidad: 3 }, { nombre: 'Segon', cantidad: 3 }, { nombre: 'Baix', cantidad: 3 }],
      '4d7': [{ nombre: 'Enxaneta', cantidad: 1 }, { nombre: 'Acotxador', cantidad: 1 }, { nombre: 'Terç', cantidad: 4 }, { nombre: 'Segon', cantidad: 4 }, { nombre: 'Baix', cantidad: 4 }],
      '5d7': [{ nombre: 'Enxaneta', cantidad: 1 }, { nombre: 'Acotxador', cantidad: 1 }, { nombre: 'Terç', cantidad: 5 }, { nombre: 'Segon', cantidad: 5 }, { nombre: 'Baix', cantidad: 5 }]
    };
    const niveles = nivelesDefinidos || configsPerDefecte[tipo] || configsPerDefecte['3d7'];

    await client.query('BEGIN');

    const estructuraResult = await client.query(
      `INSERT INTO estructuras_ensayo ("ensayoId", "tipo", "notas") VALUES ($1, $2, $3) RETURNING *`,
      [id, tipo, notas || null]
    );
    const estructura = estructuraResult.rows[0];

    // Presents ordenats de més baix a més alt: el primer nivell de la
    // llista (normalment Enxaneta) es queda amb els primers (més baixos).
    const presentesResult = await client.query(
      `SELECT c."id", c."alturaHombros"
       FROM ensayo_asistentes ea
       JOIN castellers c ON c."id" = ea."castellerId"
       WHERE ea."ensayoId" = $1
       ORDER BY c."alturaHombros" ASC NULLS FIRST`,
      [id]
    );
    const presentes = presentesResult.rows;
    const necesarios = niveles.reduce((acc, n) => acc + n.cantidad, 0);

    if (presentes.length >= necesarios) {
      let i = 0;
      const posiciones = [];
      niveles.forEach(nivel => {
        for (let k = 0; k < nivel.cantidad; k++) {
          posiciones.push({ slot: nivel.nombre, slotIndex: k + 1, castellerId: presentes[i++].id });
        }
      });

      for (const p of posiciones) {
        await client.query(
          `INSERT INTO estructura_posiciones ("estructuraEnsayoId", "slot", "slotIndex", "castellerId")
           VALUES ($1, $2, $3, $4)
           ON CONFLICT ("estructuraEnsayoId", "slot", "slotIndex") DO UPDATE SET "castellerId" = EXCLUDED."castellerId"`,
          [estructura.id, p.slot, p.slotIndex, p.castellerId]
        );
      }
    }

    await client.query('COMMIT');
    res.json({ success: true, estructura });
  } catch (error) {
    await client.query('ROLLBACK');
    errorHandler(res, error);
  } finally {
    client.release();
  }
});

// Listar las estructuras guardadas de un assaig, con cuántas posiciones
// tienen ya asignadas
app.get('/api/ensayos/:id/estructuras', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(`
      SELECT ee.*,
        COUNT(ep."id")::int AS "totalPosiciones",
        COUNT(ep."castellerId")::int AS "posicionesAsignadas"
      FROM estructuras_ensayo ee
      LEFT JOIN estructura_posiciones ep ON ep."estructuraEnsayoId" = ee."id"
      WHERE ee."ensayoId" = $1
      GROUP BY ee."id"
      ORDER BY ee."created_at" ASC
    `, [id]);
    res.json({ success: true, data: result.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Detalle de una estructura guardada: cabecera + todas sus posiciones
// (con el nombre del casteller asignado, si lo hay)
app.get('/api/estructuras/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const estructura = await pool.query('SELECT * FROM estructuras_ensayo WHERE "id" = $1', [id]);
    if (estructura.rows.length === 0) return res.status(404).json({ error: 'Estructura no trobada' });

    const posiciones = await pool.query(`
      SELECT ep."slot", ep."slotIndex", ep."castellerId", c."nombre" AS "castellerNombre"
      FROM estructura_posiciones ep
      LEFT JOIN castellers c ON c."id" = ep."castellerId"
      WHERE ep."estructuraEnsayoId" = $1
      ORDER BY ep."slot", ep."slotIndex"
    `, [id]);

    res.json({ success: true, estructura: estructura.rows[0], posiciones: posiciones.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Asignar (o vaciar, con castellerId null) un casteller a una posición
// concreta. Sirve tanto para el "arrastrar y soltar" como para colocar
// manualmente en una pinya en blanco.
app.put('/api/estructuras/:id/posiciones', async (req, res) => {
  try {
    const { id } = req.params;
    const { slot, slotIndex, castellerId } = req.body;
    if (!slot) return res.status(400).json({ error: 'slot es obligatorio' });

    const result = await pool.query(
      `INSERT INTO estructura_posiciones ("estructuraEnsayoId", "slot", "slotIndex", "castellerId")
       VALUES ($1, $2, $3, $4)
       ON CONFLICT ("estructuraEnsayoId", "slot", "slotIndex")
       DO UPDATE SET "castellerId" = EXCLUDED."castellerId"
       RETURNING *`,
      [id, slot, slotIndex || 1, castellerId || null]
    );
    res.json({ success: true, posicion: result.rows[0] });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Intercambiar quién ocupa dos posiciones (drag&drop de sujeto sobre
// sujeto, o el "clic en B, clic en A" que también queréis soportar).
// Crea las filas si alguna posición todavía no existía (pinya en blanco).
app.put('/api/estructuras/:id/swap', async (req, res) => {
  const { id } = req.params;
  const { a, b } = req.body; // { slot, slotIndex } cada una
  if (!a || !b || !a.slot || !b.slot) {
    return res.status(400).json({ error: 'a y b (con slot) son obligatorios' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const upsertVacio = async (pos) => {
      await client.query(
        `INSERT INTO estructura_posiciones ("estructuraEnsayoId", "slot", "slotIndex")
         VALUES ($1, $2, $3)
         ON CONFLICT ("estructuraEnsayoId", "slot", "slotIndex") DO NOTHING`,
        [id, pos.slot, pos.slotIndex || 1]
      );
      const r = await client.query(
        `SELECT "castellerId" FROM estructura_posiciones
         WHERE "estructuraEnsayoId" = $1 AND "slot" = $2 AND "slotIndex" = $3`,
        [id, pos.slot, pos.slotIndex || 1]
      );
      return r.rows[0].castellerId;
    };

    const castellerA = await upsertVacio(a);
    const castellerB = await upsertVacio(b);

    await client.query(
      `UPDATE estructura_posiciones SET "castellerId" = $1
       WHERE "estructuraEnsayoId" = $2 AND "slot" = $3 AND "slotIndex" = $4`,
      [castellerB, id, a.slot, a.slotIndex || 1]
    );
    await client.query(
      `UPDATE estructura_posiciones SET "castellerId" = $1
       WHERE "estructuraEnsayoId" = $2 AND "slot" = $3 AND "slotIndex" = $4`,
      [castellerA, id, b.slot, b.slotIndex || 1]
    );

    await client.query('COMMIT');
    res.json({ success: true });
  } catch (error) {
    await client.query('ROLLBACK');
    errorHandler(res, error);
  } finally {
    client.release();
  }
});

// Descartar una estructura guardada (p.ex. una prova que no ha quedat bé)
app.delete('/api/estructuras/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM estructuras_ensayo WHERE "id" = $1', [id]);
    res.json({ success: true });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Llistar tots els ensayos (esborranys inclosos — encara no hi ha usuaris
// per restringir la visibilitat dels privats; això arribarà amb el login)
app.get('/api/ensayos', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT e.*, COUNT(ea."castellerId")::int AS "numAsistentes"
      FROM ensayos e
      LEFT JOIN ensayo_asistentes ea ON ea."ensayoId" = e."id"
      GROUP BY e."id"
      ORDER BY e."fecha" DESC, e."id" DESC
    `);
    res.json({ success: true, data: result.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Crear un ensayo nou
app.post('/api/ensayos', async (req, res) => {
  try {
    const { fecha, horaInicio, horaFin, notas } = req.body;
    if (!fecha) return res.status(400).json({ error: 'fecha es obligatoria' });

    const result = await pool.query(
      `INSERT INTO ensayos ("fecha", "horaInicio", "horaFin", "notas")
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [fecha, horaInicio || null, horaFin || null, notas || null]
    );
    res.json({ success: true, ensayo: result.rows[0] });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Detall d'un ensayo + llista d'ids de castellers presents
app.get('/api/ensayos/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const ensayo = await pool.query('SELECT * FROM ensayos WHERE "id" = $1', [id]);
    if (ensayo.rows.length === 0) return res.status(404).json({ error: 'Ensayo no trobat' });

    const asistentes = await pool.query(
      'SELECT "castellerId" FROM ensayo_asistentes WHERE "ensayoId" = $1',
      [id]
    );
    res.json({
      success: true,
      ensayo: ensayo.rows[0],
      asistentesIds: asistentes.rows.map(r => r.castellerId)
    });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Marcar/desmarcar l'assistència d'un casteller a un ensayo
app.put('/api/ensayos/:id/asistencia', async (req, res) => {
  try {
    const { id } = req.params;
    const { castellerId, asiste } = req.body;
    if (!castellerId) return res.status(400).json({ error: 'castellerId es obligatorio' });

    if (asiste) {
      await pool.query(
        `INSERT INTO ensayo_asistentes ("ensayoId", "castellerId") VALUES ($1, $2)
         ON CONFLICT DO NOTHING`,
        [id, castellerId]
      );
    } else {
      await pool.query(
        `DELETE FROM ensayo_asistentes WHERE "ensayoId" = $1 AND "castellerId" = $2`,
        [id, castellerId]
      );
    }
    res.json({ success: true });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Publicar un ensayo (deixa de ser esborrany privat)
app.put('/api/ensayos/:id/publicar', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `UPDATE ensayos SET "publicado" = TRUE WHERE "id" = $1 RETURNING *`,
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Ensayo no trobat' });
    res.json({ success: true, ensayo: result.rows[0] });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Propostes de castells PER A UN ENSAYO CONCRET, basades només en els
// presents (encara no tenim rols de castell assignats de forma fiable a
// totes les collas que faran servir això, així que aquí NO exigim rols:
// només comptem caps i, opcionalment, ordenem per alçada).
// ?criterio=altura -> suggereix qui podria anar de pom (més baixos) i de
// base (més alts). ?criterio=ninguno (o sense el paràmetre) -> només
// comprova viabilitat per nombre de gent.
app.get('/api/ensayos/:id/propuestas', async (req, res) => {
  try {
    const { id } = req.params;
    const criterio = req.query.criterio === 'altura' ? 'altura' : 'ninguno';

    const result = await pool.query(
      `SELECT c."id", c."nombre", c."alturaHombros"
       FROM ensayo_asistentes ea
       JOIN castellers c ON c."id" = ea."castellerId"
       WHERE ea."ensayoId" = $1`,
      [id]
    );
    const presentes = result.rows;

    // Estructures simplificades: nombre mínim de persones al tronc + pom
    // (1 baix + segons + tersos + acotxador + enxaneta). No modelem encara
    // la pinya de suport.
    const estructuras = [
      { tipo: '2d6', segons: 2, tersos: 2 },
      { tipo: '3d7', segons: 3, tersos: 3 },
      { tipo: '4d7', segons: 4, tersos: 4 },
      { tipo: '5d7', segons: 5, tersos: 5 }
    ];

    const propuestas = estructuras.map(e => {
      const requerido = 1 + e.segons + e.tersos + 1 + 1; // baix + segons + tersos + acotxador + enxaneta
      const viable = presentes.length >= requerido;

      const propuesta = { tipo: e.tipo, requerido, presentes: presentes.length, viable };

      if (viable && criterio === 'altura') {
        const conAltura = presentes.filter(p => p.alturaHombros !== null && p.alturaHombros !== undefined);
        const ordenados = [...conAltura].sort((a, b) => a.alturaHombros - b.alturaHombros);
        propuesta.sugerencia = {
          pom_mas_bajos: ordenados.slice(0, 2).map(p => ({ id: p.id, nombre: p.nombre, alturaHombros: p.alturaHombros })),
          base_mas_altos: ordenados.slice(-2).reverse().map(p => ({ id: p.id, nombre: p.nombre, alturaHombros: p.alturaHombros })),
          sinAlturaRegistrada: presentes.length - conAltura.length
        };
      }

      return propuesta;
    });

    res.json({ success: true, criterio, propuestas });
  } catch (error) {
    errorHandler(res, error);
  }
});

/* =========================================================
   MÒDUL PLANTILLES DE PINYA (editables des de l'editor visual)
   ========================================================= */

// ⚠️ TEMPORAL: crea la taula de plantilles. Sense ?confirm=si només avisa.
// BÓRRALA del server.js en cuanto la hayas ejecutado.
// ⚠️ TEMPORAL: solo para depurar — muestra las columnas reales que Postgres
// tiene guardadas para plantillas_posicion, directamente desde el catálogo
// del sistema (sin pasar por SELECT * ni por ninguna suposición del código).
// Bórrala del server.js en cuanto hayamos resuelto esto.
app.get('/api/debug-columnas', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT column_name, data_type, column_default, is_nullable
      FROM information_schema.columns
      WHERE table_name = 'plantillas_posicion'
      ORDER BY ordinal_position
    `);
    res.json({ success: true, columnas: result.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.get('/api/migrate-plantillas', async (req, res) => {
  if (req.query.confirm !== 'si') {
    return res.json({
      success: false,
      aviso: 'Esto crea la tabla plantillas_posicion. Añade ?confirm=si para confirmar.'
    });
  }
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS plantillas_posicion (
        "id" SERIAL PRIMARY KEY,
        "tipo" TEXT NOT NULL,
        "slot" TEXT NOT NULL,
        "slotIndex" INTEGER NOT NULL DEFAULT 1,
        "x" NUMERIC NOT NULL,
        "y" NUMERIC NOT NULL,
        "w" NUMERIC NOT NULL DEFAULT 70,
        "h" NUMERIC NOT NULL DEFAULT 32,
        "shape" TEXT NOT NULL DEFAULT 'rect',
        UNIQUE ("tipo", "slot", "slotIndex")
      )
    `);
    // idempotent: si la tabla ya existía de antes, añade la columna nueva
    await pool.query(`ALTER TABLE plantillas_posicion ADD COLUMN IF NOT EXISTS "rotacion" NUMERIC NOT NULL DEFAULT 0`);
    res.json({ success: true, aviso: 'Borra /api/migrate-plantillas del server.js ahora que ya la has ejecutado.' });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Llegir la plantilla desada d'un tipus de castell
app.get('/api/plantillas/:tipo', async (req, res) => {
  try {
    const { tipo } = req.params;
    const result = await pool.query('SELECT * FROM plantillas_posicion WHERE "tipo" = $1 ORDER BY "id"', [tipo]);
    res.json({ success: true, data: result.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Desar (reemplaçant) tota la plantilla d'un tipus, tal com l'ha deixat
// l'editor visual
app.put('/api/plantillas/:tipo', async (req, res) => {
  const { tipo } = req.params;
  const { posiciones } = req.body; // array de { slot, slotIndex, x, y, w, h, shape }
  if (!Array.isArray(posiciones)) {
    return res.status(400).json({ error: 'posiciones ha de ser un array' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM plantillas_posicion WHERE "tipo" = $1', [tipo]);
    for (const p of posiciones) {
      await client.query(
        `INSERT INTO plantillas_posicion ("tipo", "slot", "slotIndex", "x", "y", "w", "h", "shape", "rotacion")
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [tipo, p.slot, p.slotIndex || 1, p.x, p.y, p.w || 70, p.h || 32, p.shape || 'rect', p.rotacion || 0]
      );
    }
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (error) {
    await client.query('ROLLBACK');
    errorHandler(res, error);
  } finally {
    client.release();
  }
});


/* =========================================================
   MÒDUL IMATGES DE REFERÈNCIA (biblioteca compartida pels editors)
   ========================================================= */

// ⚠️ TEMPORAL: crea la taula d'imatges. Sense ?confirm=si només avisa.
app.get('/api/migrate-imagenes', async (req, res) => {
  if (req.query.confirm !== 'si') {
    return res.json({ success: false, aviso: 'Esto crea la tabla imagenes_referencia. Añade ?confirm=si para confirmar.' });
  }
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS imagenes_referencia (
        "id" SERIAL PRIMARY KEY,
        "nombre" TEXT,
        "categoria" TEXT,
        "dataUrl" TEXT NOT NULL,
        "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    res.json({ success: true, aviso: 'Borra /api/migrate-imagenes del server.js ahora que ya la has ejecutado.' });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Nota: guardem la imatge com a text (base64 o URL externa) directament a
// Postgres. És senzill i persisteix bé entre desplegaments (el disc local de
// Render s'esborra a cada deploy), però per a una biblioteca molt gran
// d'imatges pesades caldria un servei d'emmagatzematge real més endavant.
app.get('/api/imagenes', async (req, res) => {
  try {
    const { categoria } = req.query;
    const result = categoria
      ? await pool.query('SELECT * FROM imagenes_referencia WHERE "categoria" = $1 ORDER BY "id" DESC', [categoria])
      : await pool.query('SELECT * FROM imagenes_referencia ORDER BY "id" DESC');
    res.json({ success: true, data: result.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.post('/api/imagenes', async (req, res) => {
  try {
    const { nombre, categoria, dataUrl } = req.body;
    if (!dataUrl) return res.status(400).json({ error: 'dataUrl es obligatorio' });
    const result = await pool.query(
      `INSERT INTO imagenes_referencia ("nombre","categoria","dataUrl") VALUES ($1,$2,$3) RETURNING "id","nombre","categoria","created_at"`,
      [nombre || null, categoria || null, dataUrl]
    );
    res.json({ success: true, imagen: result.rows[0] });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.delete('/api/imagenes/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM imagenes_referencia WHERE "id" = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Renombrar una imatge
app.put('/api/imagenes/:id', async (req, res) => {
  try {
    const { nombre } = req.body;
    if (!nombre) return res.status(400).json({ error: 'nombre es obligatorio' });
    const result = await pool.query(
      `UPDATE imagenes_referencia SET "nombre" = $1 WHERE "id" = $2 RETURNING "id","nombre","categoria","created_at"`,
      [nombre, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Imatge no trobada' });
    res.json({ success: true, imagen: result.rows[0] });
  } catch (error) {
    errorHandler(res, error);
  }
});

/* =========================================================
   MÒDUL CATEGORIES D'IMATGE (gestionables des de la biblioteca)
   ========================================================= */

// ⚠️ TEMPORAL: crea la taula de categories, la sembra amb les 4 inicials, i
// normalitza els valors antics ('pinya'/'castell') cap als noms nous. Sense
// ?confirm=si només avisa.
app.get('/api/migrate-categorias-imagen', async (req, res) => {
  if (req.query.confirm !== 'si') {
    return res.json({ success: false, aviso: 'Esto crea categorias_imagen y normaliza categorías antiguas. Añade ?confirm=si para confirmar.' });
  }
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS categorias_imagen (
        "id" SERIAL PRIMARY KEY,
        "nombre" TEXT UNIQUE NOT NULL,
        "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      INSERT INTO categorias_imagen ("nombre") VALUES
        ('Castells'), ('Pinyes'), ('Fotos de perfil'), ('Altres')
      ON CONFLICT ("nombre") DO NOTHING
    `);
    // les imatges que es van guardar abans amb categoria='castell'/'pinya'
    // (text lliure en minúscules) passen a fer servir els noms nous
    await pool.query(`UPDATE imagenes_referencia SET "categoria" = 'Castells' WHERE "categoria" = 'castell'`);
    await pool.query(`UPDATE imagenes_referencia SET "categoria" = 'Pinyes' WHERE "categoria" = 'pinya'`);
    await pool.query(`UPDATE imagenes_referencia SET "categoria" = 'Altres' WHERE "categoria" IS NULL OR "categoria" = ''`);
    res.json({ success: true, aviso: 'Borra /api/migrate-categorias-imagen del server.js ahora que ya la has ejecutado.' });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.get('/api/categorias-imagen', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, COUNT(i."id")::int AS "numImagenes"
      FROM categorias_imagen c
      LEFT JOIN imagenes_referencia i ON i."categoria" = c."nombre"
      GROUP BY c."id"
      ORDER BY c."nombre"
    `);
    res.json({ success: true, data: result.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.post('/api/categorias-imagen', async (req, res) => {
  try {
    const { nombre } = req.body;
    if (!nombre || !nombre.trim()) return res.status(400).json({ error: 'nombre es obligatorio' });
    const result = await pool.query(
      `INSERT INTO categorias_imagen ("nombre") VALUES ($1) RETURNING *`,
      [nombre.trim()]
    );
    res.json({ success: true, categoria: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') return res.status(400).json({ success: false, error: 'Ja existeix una categoria amb aquest nom' });
    errorHandler(res, error);
  }
});

// Renombrar una categoria — actualitza també totes les imatges que la feien
// servir, perquè quedin sincronitzades amb el nou nom.
app.put('/api/categorias-imagen/:id', async (req, res) => {
  const client = await pool.connect();
  try {
    const { nombre } = req.body;
    if (!nombre || !nombre.trim()) return res.status(400).json({ error: 'nombre es obligatorio' });

    await client.query('BEGIN');
    const actual = await client.query('SELECT * FROM categorias_imagen WHERE "id" = $1', [req.params.id]);
    if (actual.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Categoria no trobada' });
    }
    const nombreAnterior = actual.rows[0].nombre;

    const result = await client.query(
      `UPDATE categorias_imagen SET "nombre" = $1 WHERE "id" = $2 RETURNING *`,
      [nombre.trim(), req.params.id]
    );
    await client.query(
      `UPDATE imagenes_referencia SET "categoria" = $1 WHERE "categoria" = $2`,
      [nombre.trim(), nombreAnterior]
    );
    await client.query('COMMIT');
    res.json({ success: true, categoria: result.rows[0] });
  } catch (error) {
    await client.query('ROLLBACK');
    if (error.code === '23505') return res.status(400).json({ success: false, error: 'Ja existeix una categoria amb aquest nom' });
    errorHandler(res, error);
  } finally {
    client.release();
  }
});

/* =========================================================
   MÒDUL ESTRUCTURA DE CASTELLS (el tronc: nivells i quantitats)
   ========================================================= */

// ⚠️ TEMPORAL: crea la taula d'estructures de castell. Sense ?confirm=si
// només avisa.
app.get('/api/migrate-castells-estructura', async (req, res) => {
  if (req.query.confirm !== 'si') {
    return res.json({ success: false, aviso: 'Esto crea la tabla castells_estructura. Añade ?confirm=si para confirmar.' });
  }
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS castells_estructura (
        "id" SERIAL PRIMARY KEY,
        "tipo" TEXT UNIQUE NOT NULL,
        "niveles" JSONB NOT NULL,
        "imagenId" INTEGER REFERENCES imagenes_referencia("id") ON DELETE SET NULL,
        "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    res.json({ success: true, aviso: 'Borra /api/migrate-castells-estructura del server.js ahora que ya la has ejecutado.' });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.get('/api/castells-estructura/:tipo', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM castells_estructura WHERE "tipo" = $1', [req.params.tipo]);
    if (result.rows.length === 0) return res.json({ success: true, estructura: null });
    res.json({ success: true, estructura: result.rows[0] });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.put('/api/castells-estructura/:tipo', async (req, res) => {
  try {
    const { tipo } = req.params;
    const { niveles, imagenId } = req.body;
    if (!Array.isArray(niveles)) return res.status(400).json({ error: 'niveles ha de ser un array' });

    const result = await pool.query(
      `INSERT INTO castells_estructura ("tipo","niveles","imagenId")
       VALUES ($1,$2,$3)
       ON CONFLICT ("tipo") DO UPDATE SET "niveles" = EXCLUDED."niveles", "imagenId" = EXCLUDED."imagenId"
       RETURNING *`,
      [tipo, JSON.stringify(niveles), imagenId || null]
    );
    res.json({ success: true, estructura: result.rows[0] });
  } catch (error) {
    errorHandler(res, error);
  }
});

/* =========================================================
   MÒDUL DISSENY VISUAL DEL CASTELL (etiquetes de text sobre
   la imatge del tronc — mateix patró que la plantilla de pinya)
   ========================================================= */

// ⚠️ TEMPORAL: crea la taula del disseny visual del castell. Sense
// ?confirm=si només avisa.
app.get('/api/migrate-castell-plantilla', async (req, res) => {
  if (req.query.confirm !== 'si') {
    return res.json({ success: false, aviso: 'Esto crea la tabla castell_plantilla_posicion. Añade ?confirm=si para confirmar.' });
  }
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS castell_plantilla_posicion (
        "id" SERIAL PRIMARY KEY,
        "tipo" TEXT NOT NULL,
        "slot" TEXT NOT NULL,
        "slotIndex" INTEGER NOT NULL DEFAULT 1,
        "x" NUMERIC NOT NULL,
        "y" NUMERIC NOT NULL,
        "w" NUMERIC NOT NULL DEFAULT 90,
        "h" NUMERIC NOT NULL DEFAULT 28,
        UNIQUE ("tipo", "slot", "slotIndex")
      )
    `);
    res.json({ success: true, aviso: 'Borra /api/migrate-castell-plantilla del server.js ahora que ya la has ejecutado.' });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.get('/api/castell-plantilla/:tipo', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM castell_plantilla_posicion WHERE "tipo" = $1 ORDER BY "id"', [req.params.tipo]);
    res.json({ success: true, data: result.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.put('/api/castell-plantilla/:tipo', async (req, res) => {
  const { tipo } = req.params;
  const { posiciones } = req.body;
  if (!Array.isArray(posiciones)) return res.status(400).json({ error: 'posiciones ha de ser un array' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM castell_plantilla_posicion WHERE "tipo" = $1', [tipo]);
    for (const p of posiciones) {
      await client.query(
        `INSERT INTO castell_plantilla_posicion ("tipo","slot","slotIndex","x","y","w","h")
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [tipo, p.slot, p.slotIndex || 1, p.x, p.y, p.w || 90, p.h || 28]
      );
    }
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (error) {
    await client.query('ROLLBACK');
    errorHandler(res, error);
  } finally {
    client.release();
  }
});

/* =========================================================
   MÒDUL USUARIS I AUTENTICACIÓ
   ========================================================= */

// ⚠️ TEMPORAL: crea les taules d'usuaris i tokens de verificació. Sense
// ?confirm=si només avisa.
app.get('/api/migrate-usuarios', async (req, res) => {
  if (req.query.confirm !== 'si') {
    return res.json({ success: false, aviso: 'Esto crea las tablas usuarios y registros_pendientes. Añade ?confirm=si para confirmar.' });
  }
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        "id" SERIAL PRIMARY KEY,
        "email" TEXT UNIQUE NOT NULL,
        "passwordHash" TEXT NOT NULL,
        "nombre" TEXT NOT NULL,
        "castellerId" INTEGER REFERENCES castellers("id") ON DELETE SET NULL,
        "estado" TEXT NOT NULL DEFAULT 'pendiente',
        "emailVerificado" BOOLEAN NOT NULL DEFAULT FALSE,
        "permisos" TEXT[] NOT NULL DEFAULT '{}',
        "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    // idempotent: si la taula ja existia d'abans (com ara mateix), afegim
    // les columnes noves del nom complet
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS "primerApellido" TEXT`);
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS "segundoApellido" TEXT`);
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS "apodo" TEXT`);
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS "idioma" TEXT NOT NULL DEFAULT 'ca'`);
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS "fotoPerfil" TEXT`);
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS "fechaNacimiento" DATE`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS registros_pendientes (
        "id" SERIAL PRIMARY KEY,
        "email" TEXT UNIQUE NOT NULL,
        "passwordHash" TEXT NOT NULL,
        "nombre" TEXT NOT NULL,
        "primerApellido" TEXT NOT NULL,
        "segundoApellido" TEXT,
        "apodo" TEXT,
        "fechaNacimiento" DATE,
        "idioma" TEXT NOT NULL DEFAULT 'ca',
        "token" TEXT UNIQUE NOT NULL,
        "expiraEn" TIMESTAMP NOT NULL,
        "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    res.json({ success: true, aviso: 'Borra /api/migrate-usuarios del server.js ahora que ya la has ejecutado.' });
  } catch (error) {
    errorHandler(res, error);
  }
});

function emailValido(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function escaparHtmlCorreo(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// Registre: crea l'usuari (pendent), envia correu de verificació
app.post('/api/auth/registro', async (req, res) => {
  try {
    const { email, password, nombre, primerApellido, segundoApellido, apodo, idioma, fechaNacimiento } = req.body;
    if (!emailValido(email)) return res.status(400).json({ success: false, error: 'Correu no vàlid' });
    if (!password || password.length < 6) return res.status(400).json({ success: false, error: 'La contrasenya ha de tenir almenys 6 caràcters' });
    if (!nombre || !nombre.trim()) return res.status(400).json({ success: false, error: 'El nom és obligatori' });
    if (!primerApellido || !primerApellido.trim()) return res.status(400).json({ success: false, error: 'El primer cognom és obligatori' });
    const idiomaValido = ['ca', 'es', 'en'].includes(idioma) ? idioma : 'ca';
    // la data de naixement és opcional — només s'usa per suggerir vincles amb
    // fitxes de casteller existents i, en el futur, per un calendari d'aniversaris
    const fechaNacimientoValida = fechaNacimiento && /^\d{4}-\d{2}-\d{2}$/.test(fechaNacimiento) ? fechaNacimiento : null;

    const emailNorm = email.toLowerCase();

    const existente = await pool.query('SELECT "id" FROM usuarios WHERE "email" = $1', [emailNorm]);
    if (existente.rows.length > 0) {
      return res.status(400).json({ success: false, error: 'Ja hi ha un compte amb aquest correu' });
    }

    // neteja de pas qualsevol registre pendent caducat (housekeeping barat,
    // sense necessitat d'un cron a part)
    await pool.query(`DELETE FROM registros_pendientes WHERE "expiraEn" < NOW()::timestamp`);

    // Si ja hi havia una sol·licitud pendent (no caducada) per aquest
    // correu, NO la substituïm mai per les dades noves ni reenviem res
    // automàticament: avisem que ja n'hi ha una, perquè la persona pugui
    // comprovar que el correu és realment el seu (és fàcil equivocar-se
    // entre correus semblants d'una mateixa família, ex. garciaj@ vs
    // garciaju@) abans de decidir reenviar-lo de veritat.
    const pendienteExistente = await pool.query('SELECT "id" FROM registros_pendientes WHERE "email" = $1', [emailNorm]);
    if (pendienteExistente.rows.length > 0) {
      return res.json({
        success: false,
        yaPendiente: true,
        email: emailNorm,
        error: `Ja hi ha una sol·licitud pendent de verificar amb el correu ${emailNorm}. Comprova que sigui realment el teu correu.`
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString('hex');
    const expiraEn = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

    await pool.query(
      `INSERT INTO registros_pendientes
         ("email","passwordHash","nombre","primerApellido","segundoApellido","apodo","fechaNacimiento","idioma","token","expiraEn")
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [emailNorm, passwordHash, nombre.trim(), primerApellido.trim(), (segundoApellido || '').trim() || null, (apodo || '').trim() || null, fechaNacimientoValida, idiomaValido, token, expiraEn]
    );

    const enlace = `${req.protocol}://${req.get('host')}/verificar-email.html?token=${token}`;
    try {
      await enviarCorreo({
        to: emailNorm,
        subject: 'Verifica el teu correu — Castellers',
        html: `<p>Hola ${escaparHtmlCorreo(nombre.trim())},</p>
               <p>Per confirmar el teu correu i continuar amb l'alta, clica aquí:</p>
               <p><a href="${enlace}">${enlace}</a></p>
               <p>L'enllaç caduca en 24 hores. Un cop verificat, un administrador haurà de validar el teu accés.</p>`
      });
    } catch (errCorreo) {
      // el registre pendent ja ha quedat desat — l'usuari pot demanar-nos
      // reenviar-lo o l'administrador pot mirar els logs, però la petició
      // no s'ha de quedar penjada ni fallar per un problema del correu
      console.error('Error enviant correu de verificació:', errCorreo);
    }

    res.json({ success: true, mensaje: 'Registre rebut. Revisa el teu correu per verificar-lo (caduca en 24 hores).' });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Verificar correu (enllaç del token). Aquí és quan es crea l'usuari de
// veritat — si mai es verifica, no queda cap usuari desat, només el
// registre pendent (que a més caduca sol). Un cop verificat, l'usuari queda
// pendent d'aprovació d'un admin.
// Reenviar el correu de verificació d'una sol·licitud pendent — nomès
// s'invoca si la persona confirma explícitament que el correu és el seu
// (mai automàticament des de /registro, per evitar enviar correus a algú
// que no els ha demanat per un simple error de tecleig).
app.post('/api/auth/reenviar-verificacion', async (req, res) => {
  try {
    const { email } = req.body;
    if (!emailValido(email)) return res.status(400).json({ success: false, error: 'Correu no vàlid' });
    const emailNorm = email.toLowerCase();

    const result = await pool.query('SELECT * FROM registros_pendientes WHERE "email" = $1', [emailNorm]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'No hi ha cap sol·licitud pendent amb aquest correu' });
    }
    const p = result.rows[0];
    const enlace = `${req.protocol}://${req.get('host')}/verificar-email.html?token=${p.token}`;

    try {
      await enviarCorreo({
        to: emailNorm,
        subject: 'Verifica el teu correu — Castellers',
        html: `<p>Hola ${escaparHtmlCorreo(p.nombre)},</p>
               <p>Aquí tens de nou l'enllaç per confirmar el teu correu:</p>
               <p><a href="${enlace}">${enlace}</a></p>
               <p>Si no vas ser tu qui va omplir aquest formulari, pots ignorar aquest correu amb tranquil·litat.</p>`
      });
    } catch (errCorreo) {
      console.error('Error reenviant correu de verificació:', errCorreo);
      return res.status(500).json({ success: false, error: 'No s\'ha pogut enviar el correu. Torna-ho a provar en uns minuts.' });
    }

    res.json({ success: true, mensaje: 'Enllaç reenviat. Revisa el teu correu.' });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.get('/api/auth/verificar-email', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ success: false, error: 'Falta el token' });

    const result = await pool.query('SELECT * FROM registros_pendientes WHERE "token" = $1', [token]);
    if (result.rows.length === 0) return res.status(400).json({ success: false, error: 'Enllaç no vàlid o ja fet servir' });
    const pendiente = result.rows[0];
    if (new Date(pendiente.expiraEn) < new Date()) {
      await pool.query('DELETE FROM registros_pendientes WHERE "id" = $1', [pendiente.id]);
      return res.status(400).json({ success: false, error: 'Aquest enllaç ha caducat — torna a registrar-te' });
    }

    // pot ser que, entre que es va registrar i ara, algú altre hagi creat un
    // compte amb el mateix correu (poc probable, però ho comprovem igual)
    const yaExiste = await pool.query('SELECT "id" FROM usuarios WHERE "email" = $1', [pendiente.email]);
    if (yaExiste.rows.length > 0) {
      await pool.query('DELETE FROM registros_pendientes WHERE "id" = $1', [pendiente.id]);
      return res.status(400).json({ success: false, error: 'Ja hi ha un compte amb aquest correu' });
    }

    const nuevo = await pool.query(
      `INSERT INTO usuarios ("email","passwordHash","nombre","primerApellido","segundoApellido","apodo","fechaNacimiento","idioma","emailVerificado")
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE) RETURNING *`,
      [pendiente.email, pendiente.passwordHash, pendiente.nombre, pendiente.primerApellido, pendiente.segundoApellido, pendiente.apodo, pendiente.fechaNacimiento, pendiente.idioma || 'ca']
    );
    const usuario = nuevo.rows[0];
    await pool.query('DELETE FROM registros_pendientes WHERE "id" = $1', [pendiente.id]);

    // avisem els admins que hi ha una alta pendent de validar
    const admins = await pool.query(`SELECT "email" FROM usuarios WHERE 'AdminGeneral' = ANY("permisos") AND "estado" = 'activo'`);
    for (const admin of admins.rows) {
      try {
        await enviarCorreo({
          to: admin.email,
          subject: 'Nova alta pendent de validar — Castellers',
          html: `<p>${escaparHtmlCorreo(usuario.nombre)} (${escaparHtmlCorreo(usuario.email)}) ha verificat el seu correu i espera que li validis l'accés al panell d'usuaris.</p>`
        });
      } catch (errCorreo) {
        console.error('Error avisant a l\'admin', admin.email, errCorreo);
      }
    }

    res.json({ success: true, mensaje: 'Correu verificat. Un administrador ha de validar el teu accés abans que puguis entrar.' });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: 'Falten dades' });

    const result = await pool.query('SELECT * FROM usuarios WHERE "email" = $1', [email.toLowerCase()]);
    if (result.rows.length === 0) return res.status(401).json({ success: false, error: 'Correu o contrasenya incorrectes' });
    const usuario = result.rows[0];

    const coincide = await bcrypt.compare(password, usuario.passwordHash);
    if (!coincide) return res.status(401).json({ success: false, error: 'Correu o contrasenya incorrectes' });

    if (!usuario.emailVerificado) return res.status(403).json({ success: false, error: 'Encara no has verificat el teu correu' });
    if (usuario.estado === 'pendiente') return res.status(403).json({ success: false, error: 'El teu accés encara està pendent de validació d\'un administrador' });
    if (usuario.estado === 'rechazado') return res.status(403).json({ success: false, error: 'El teu accés no ha estat validat' });

    req.session.usuarioId = usuario.id;
    res.json({
      success: true,
      usuario: { id: usuario.id, email: usuario.email, nombre: usuario.nombre, primerApellido: usuario.primerApellido, segundoApellido: usuario.segundoApellido, apodo: usuario.apodo, idioma: usuario.idioma, permisos: usuario.permisos, castellerId: usuario.castellerId, fotoPerfil: usuario.fotoPerfil, fechaNacimiento: usuario.fechaNacimiento }
    });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get('/api/auth/me', async (req, res) => {
  if (!req.session || !req.session.usuarioId) return res.json({ success: true, usuario: null });
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE "id" = $1', [req.session.usuarioId]);
    if (result.rows.length === 0 || result.rows[0].estado !== 'activo') {
      return res.json({ success: true, usuario: null });
    }
    const u = result.rows[0];
    res.json({ success: true, usuario: { id: u.id, email: u.email, nombre: u.nombre, primerApellido: u.primerApellido, segundoApellido: u.segundoApellido, apodo: u.apodo, idioma: u.idioma, permisos: u.permisos, castellerId: u.castellerId, fotoPerfil: u.fotoPerfil, fechaNacimiento: u.fechaNacimiento } });
  } catch (error) {
    errorHandler(res, error);
  }
});

/* ---- Gestió d'usuaris (només AdminGeneral) ---- */

// Altes pendents: verificades però encara sense validar per un admin
app.get('/api/usuarios/pendientes', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT "id","email","nombre","primerApellido","segundoApellido","apodo","fechaNacimiento","created_at" FROM usuarios
       WHERE "estado" = 'pendiente' AND "emailVerificado" = TRUE
       ORDER BY "created_at" ASC`
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.get('/api/usuarios', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`SELECT "id","email","nombre","primerApellido","segundoApellido","apodo","estado","emailVerificado","permisos","castellerId","created_at" FROM usuarios ORDER BY "created_at" DESC`);
    res.json({ success: true, data: result.rows });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Compara les dades d'un usuari (nom, cognoms, correu, data de naixement)
// amb els membres ja existents a la taula de castellers, per suggerir a
// l'admin si aquest compte podria correspondre a algú que ja hi és.
// Nomès es tenen en compte castellers que encara no estan vinculats a cap
// altre usuari.
app.get('/api/usuarios/:id/candidatos-vinculo', requireAdmin, async (req, res) => {
  try {
    const usuarioResult = await pool.query('SELECT * FROM usuarios WHERE "id" = $1', [req.params.id]);
    if (usuarioResult.rows.length === 0) return res.status(404).json({ success: false, error: 'Usuari no trobat' });
    const u = usuarioResult.rows[0];

    const result = await pool.query(
      `SELECT c.*,
         (CASE WHEN c."correo" IS NOT NULL AND c."correo" <> '' AND LOWER(TRIM(c."correo")) = LOWER(TRIM($1)) THEN 1 ELSE 0 END) AS "matchCorreo",
         (CASE WHEN LOWER(TRIM(c."nombre")) = LOWER(TRIM($2)) THEN 1 ELSE 0 END) AS "matchNombre",
         (CASE WHEN c."primerApellido" IS NOT NULL AND LOWER(TRIM(c."primerApellido")) = LOWER(TRIM($3)) THEN 1 ELSE 0 END) AS "matchApellido",
         (CASE WHEN c."fNac" IS NOT NULL AND $4::date IS NOT NULL AND c."fNac" = $4::date THEN 1 ELSE 0 END) AS "matchFechaNacimiento"
       FROM castellers c
       WHERE NOT EXISTS (SELECT 1 FROM usuarios u2 WHERE u2."castellerId" = c."id")`,
      [u.email, u.nombre, u.primerApellido, u.fechaNacimiento]
    );

    const candidatos = result.rows
      .map(c => ({
        ...c,
        puntuacion: c.matchCorreo * 2 + c.matchNombre * 1 + c.matchApellido * 1 + c.matchFechaNacimiento * 2
      }))
      .filter(c => c.puntuacion >= 2)
      .sort((a, b) => b.puntuacion - a.puntuacion)
      .slice(0, 5);

    res.json({ success: true, candidatos });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Comprova si l'àlies d'un usuari pendent ja el fa servir algun altre
// membre (per evitar l'embolic d'àlies duplicats). Si hi ha conflicte,
// suggereix "àlies + primer cognom" com a alternativa.
app.get('/api/usuarios/:id/comprobar-alias', requireAdmin, async (req, res) => {
  try {
    const usuarioResult = await pool.query('SELECT * FROM usuarios WHERE "id" = $1', [req.params.id]);
    if (usuarioResult.rows.length === 0) return res.status(404).json({ success: false, error: 'Usuari no trobat' });
    const u = usuarioResult.rows[0];

    if (!u.apodo || !u.apodo.trim()) {
      return res.json({ success: true, disponible: true, alias: null });
    }

    const conflicto = await pool.query(
      `SELECT "id","nombre" FROM castellers WHERE LOWER(TRIM("apodo")) = LOWER(TRIM($1))`,
      [u.apodo]
    );
    const sugerido = `${u.apodo.trim()} ${(u.primerApellido || '').trim()}`.trim();

    res.json({
      success: true,
      disponible: conflicto.rows.length === 0,
      alias: u.apodo,
      sugerido,
      conflictoCon: conflicto.rows[0] || null
    });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.put('/api/usuarios/:id/aprobar', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE usuarios SET "estado" = 'activo' WHERE "id" = $1 AND "emailVerificado" = TRUE RETURNING *`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'Usuari no trobat o correu no verificat' });
    const usuario = result.rows[0];
    await enviarCorreo({
      to: usuario.email,
      subject: 'El teu accés ja està validat — Castellers',
      html: `<p>Hola ${usuario.nombre.split(' ')[0]},</p><p>Ja pots accedir amb el correu <strong>${usuario.email}</strong> i la contrasenya que vas triar.</p>`
    });
    res.json({ success: true, usuario });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.put('/api/usuarios/:id/rechazar', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`UPDATE usuarios SET "estado" = 'rechazado' WHERE "id" = $1 RETURNING *`, [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'Usuari no trobat' });
    res.json({ success: true });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Editar permisos / dades d'un usuari (admin)
app.put('/api/usuarios/:id', requireAdmin, async (req, res) => {
  try {
    const { nombre, permisos, estado, castellerId } = req.body;
    const result = await pool.query(
      `UPDATE usuarios SET
         "nombre" = COALESCE($1, "nombre"),
         "permisos" = COALESCE($2, "permisos"),
         "estado" = COALESCE($3, "estado"),
         "castellerId" = $4
       WHERE "id" = $5 RETURNING "id","email","nombre","estado","emailVerificado","permisos","castellerId"`,
      [nombre || null, permisos || null, estado || null, castellerId || null, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'Usuari no trobat' });
    res.json({ success: true, usuario: result.rows[0] });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Perfil propi (qualsevol usuari amb sessió, no cal ser admin)
// Canviar l'idioma preferit — es pot cridar en qualsevol moment des de
// qualsevol mòdul (el guardia global ja exigeix sessió iniciada aquí).
app.put('/api/auth/idioma', async (req, res) => {
  try {
    const { idioma } = req.body;
    if (!['ca', 'es', 'en'].includes(idioma)) return res.status(400).json({ success: false, error: 'Idioma no vàlid' });
    if (!req.usuarioActual) return res.status(401).json({ success: false, error: 'Cal iniciar sessió' });
    await pool.query('UPDATE usuarios SET "idioma" = $1 WHERE "id" = $2', [idioma, req.usuarioActual.id]);
    res.json({ success: true });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Foto de perfil (base64). La comprimim/redimensionem al navegador abans
// d'enviar-la per no carregar la base de dades amb imatges grans.
app.put('/api/auth/foto', async (req, res) => {
  try {
    const { fotoPerfil } = req.body;
    await pool.query('UPDATE usuarios SET "fotoPerfil" = $1 WHERE "id" = $2', [fotoPerfil || null, req.usuarioActual.id]);
    res.json({ success: true });
  } catch (error) {
    errorHandler(res, error);
  }
});

// Si el compte està vinculat a una fitxa de casteller (castellerId), retorna
// la seva posició de pinya i els rols de castell, per mostrar-ho al perfil.
app.get('/api/auth/mi-casteller', async (req, res) => {
  try {
    if (!req.usuarioActual.castellerId) return res.json({ success: true, casteller: null });
    const result = await pool.query(
      `SELECT c.*, p."nombre" AS "posicionPinyaNombre"
       FROM castellers c
       LEFT JOIN posiciones_pinya p ON p."id" = c."posicionPinyaId"
       WHERE c."id" = $1`,
      [req.usuarioActual.castellerId]
    );
    if (result.rows.length === 0) return res.json({ success: true, casteller: null });
    const rolesResult = await pool.query(
      `SELECT r."nombre", cr."orden" FROM casteller_roles cr
       JOIN roles_castillo r ON r."id" = cr."rolId"
       WHERE cr."castellerId" = $1 ORDER BY cr."orden"`,
      [req.usuarioActual.castellerId]
    );
    res.json({ success: true, casteller: { ...result.rows[0], roles: rolesResult.rows } });
  } catch (error) {
    errorHandler(res, error);
  }
});

app.put('/api/auth/perfil', async (req, res) => {
  try {
    const { nombre, passwordActual, passwordNueva } = req.body;
    const updates = [];
    const valores = [];
    let idx = 1;
    let cambioContrasenya = false;

    if (nombre && nombre.trim()) { updates.push(`"nombre" = $${idx++}`); valores.push(nombre.trim()); }

    if (passwordNueva) {
      if (!passwordActual) return res.status(400).json({ success: false, error: 'Cal la contrasenya actual per canviar-la' });
      const coincide = await bcrypt.compare(passwordActual, req.usuarioActual.passwordHash);
      if (!coincide) return res.status(400).json({ success: false, error: 'La contrasenya actual no és correcta' });
      if (passwordNueva.length < 6) return res.status(400).json({ success: false, error: 'La contrasenya nova ha de tenir almenys 6 caràcters' });
      const nuevoHash = await bcrypt.hash(passwordNueva, 10);
      updates.push(`"passwordHash" = $${idx++}`); valores.push(nuevoHash);
      cambioContrasenya = true;
    }

    if (!updates.length) return res.json({ success: true });

    valores.push(req.usuarioActual.id);
    await pool.query(`UPDATE usuarios SET ${updates.join(', ')} WHERE "id" = $${idx}`, valores);

    if (cambioContrasenya) {
      try {
        await enviarCorreo({
          to: req.usuarioActual.email,
          subject: 'La teva contrasenya ha canviat — Castellers',
          html: `<p>Hola ${escaparHtmlCorreo(req.usuarioActual.nombre)},</p>
                 <p>T'avisem que la contrasenya del teu compte (${escaparHtmlCorreo(req.usuarioActual.email)}) s'acaba de canviar.</p>
                 <p>Si no has estat tu, contacta amb un administrador de seguida.</p>`
        });
      } catch (errCorreo) {
        console.error('Error enviant confirmació de canvi de contrasenya:', errCorreo);
      }
    }

    res.json({ success: true });
  } catch (error) {
    errorHandler(res, error);
  }
});

// ⚠️ TEMPORAL: converteix un usuari ja registrat i amb correu verificat en
// administrador actiu — necessari per crear el PRIMER admin (ningú pot
// aprovar altes si encara no existeix cap admin). Sense ?confirm=si només
// avisa. Bórrala del server.js en cuanto la hayas usado.
app.get('/api/bootstrap-admin', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.json({ success: false, aviso: 'Afegeix ?email=el-teu-correu&confirm=si a la URL.' });
  if (req.query.confirm !== 'si') {
    return res.json({ success: false, aviso: `Això convertirà ${email} en AdminGeneral actiu. Afegeix &confirm=si per confirmar.` });
  }
  try {
    const result = await pool.query(
      `UPDATE usuarios SET "estado" = 'activo', "emailVerificado" = TRUE, "permisos" = ARRAY['AdminGeneral']
       WHERE "email" = $1 RETURNING "id","email","nombre","permisos"`,
      [email.toLowerCase()]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'No hi ha cap usuari registrat amb aquest correu' });
    res.json({ success: true, usuario: result.rows[0], aviso: 'Borra /api/bootstrap-admin del server.js ahora que ya la has usado.' });
  } catch (error) {
    errorHandler(res, error);
  }
});

/* =========================================================
   MIGRACIÓ A SUPABASE (temporal — fes-la servir una vegada i esborra-la)
   ========================================================= */

// Ordre de taules respectant les claus foranes (pares abans que fills)
const ORDRE_TAULES = [
  'posiciones_pinya', 'roles_castillo', 'castellers', 'casteller_roles',
  'ensayos', 'ensayo_asistentes', 'estructuras_ensayo', 'estructura_posiciones',
  'plantillas_posicion', 'imagenes_referencia', 'categorias_imagen',
  'castells_estructura', 'castell_plantilla_posicion', 'usuarios', 'registros_pendientes'
];

// Taules amb clau primària composta (sense columna pròpia "id") — a
// aquestes NO cal reajustar cap seqüència després de copiar-hi dades.
const TAULES_SENSE_ID_SERIAL = new Set(['casteller_roles', 'ensayo_asistentes']);

async function crearEsquemaCompleto(clientDestino) {
  await clientDestino.query(`CREATE TABLE IF NOT EXISTS posiciones_pinya ("id" SERIAL PRIMARY KEY, "nombre" TEXT UNIQUE NOT NULL)`);
  await clientDestino.query(`CREATE TABLE IF NOT EXISTS roles_castillo ("id" SERIAL PRIMARY KEY, "nombre" TEXT UNIQUE NOT NULL)`);
  await clientDestino.query(`
    CREATE TABLE IF NOT EXISTS castellers (
      "id" INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      "nombre" TEXT NOT NULL, "primerApellido" TEXT, "segundoApellido" TEXT, "apodo" TEXT,
      "posicionPinyaId" INTEGER REFERENCES posiciones_pinya("id"),
      "accesoAPP" BOOLEAN, "correo" TEXT, "fNac" DATE, "movil" TEXT, "fechaCamisa" DATE,
      "alturaHombros" INTEGER, "revisado" BOOLEAN, "estadoAcogida" TEXT, "habitual" BOOLEAN,
      "permisosAPP" TEXT[], "integranteColla" BOOLEAN, "lesionLargoPlazo" BOOLEAN,
      "formularios" INTEGER, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await clientDestino.query(`
    CREATE TABLE IF NOT EXISTS casteller_roles (
      "castellerId" INTEGER NOT NULL REFERENCES castellers("id") ON DELETE CASCADE,
      "rolId" INTEGER NOT NULL REFERENCES roles_castillo("id") ON DELETE CASCADE,
      "orden" INTEGER NOT NULL, PRIMARY KEY ("castellerId", "rolId")
    )
  `);
  await clientDestino.query(`
    CREATE TABLE IF NOT EXISTS ensayos (
      "id" SERIAL PRIMARY KEY, "fecha" DATE, "horaInicio" TIME, "horaFin" TIME,
      "notas" TEXT, "publicado" BOOLEAN DEFAULT FALSE, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await clientDestino.query(`
    CREATE TABLE IF NOT EXISTS ensayo_asistentes (
      "ensayoId" INTEGER NOT NULL REFERENCES ensayos("id") ON DELETE CASCADE,
      "castellerId" INTEGER NOT NULL REFERENCES castellers("id") ON DELETE CASCADE,
      PRIMARY KEY ("ensayoId", "castellerId")
    )
  `);
  await clientDestino.query(`
    CREATE TABLE IF NOT EXISTS estructuras_ensayo (
      "id" SERIAL PRIMARY KEY, "ensayoId" INTEGER REFERENCES ensayos("id") ON DELETE CASCADE,
      "tipo" TEXT, "notas" TEXT, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await clientDestino.query(`
    CREATE TABLE IF NOT EXISTS estructura_posiciones (
      "id" SERIAL PRIMARY KEY, "estructuraEnsayoId" INTEGER REFERENCES estructuras_ensayo("id") ON DELETE CASCADE,
      "slot" TEXT NOT NULL, "slotIndex" INTEGER NOT NULL, "castellerId" INTEGER REFERENCES castellers("id"),
      UNIQUE ("estructuraEnsayoId", "slot", "slotIndex")
    )
  `);
  await clientDestino.query(`
    CREATE TABLE IF NOT EXISTS plantillas_posicion (
      "id" SERIAL PRIMARY KEY, "tipo" TEXT, "slot" TEXT, "slotIndex" INTEGER,
      "x" NUMERIC, "y" NUMERIC, "w" NUMERIC, "h" NUMERIC, "shape" TEXT, "rotacion" NUMERIC DEFAULT 0,
      UNIQUE ("tipo", "slot", "slotIndex")
    )
  `);
  await clientDestino.query(`
    CREATE TABLE IF NOT EXISTS imagenes_referencia (
      "id" SERIAL PRIMARY KEY, "nombre" TEXT, "categoria" TEXT, "dataUrl" TEXT NOT NULL,
      "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await clientDestino.query(`CREATE TABLE IF NOT EXISTS categorias_imagen ("id" SERIAL PRIMARY KEY, "nombre" TEXT UNIQUE NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
  await clientDestino.query(`
    CREATE TABLE IF NOT EXISTS castells_estructura (
      "id" SERIAL PRIMARY KEY, "tipo" TEXT UNIQUE NOT NULL, "niveles" JSONB NOT NULL,
      "imagenId" INTEGER REFERENCES imagenes_referencia("id") ON DELETE SET NULL,
      "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await clientDestino.query(`
    CREATE TABLE IF NOT EXISTS castell_plantilla_posicion (
      "id" SERIAL PRIMARY KEY, "tipo" TEXT NOT NULL, "slot" TEXT NOT NULL, "slotIndex" INTEGER NOT NULL DEFAULT 1,
      "x" NUMERIC NOT NULL, "y" NUMERIC NOT NULL, "w" NUMERIC NOT NULL DEFAULT 90, "h" NUMERIC NOT NULL DEFAULT 28,
      UNIQUE ("tipo", "slot", "slotIndex")
    )
  `);
  await clientDestino.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      "id" SERIAL PRIMARY KEY, "email" TEXT UNIQUE NOT NULL, "passwordHash" TEXT NOT NULL, "nombre" TEXT NOT NULL,
      "primerApellido" TEXT, "segundoApellido" TEXT, "apodo" TEXT,
      "castellerId" INTEGER REFERENCES castellers("id") ON DELETE SET NULL, "estado" TEXT NOT NULL DEFAULT 'pendiente',
      "emailVerificado" BOOLEAN NOT NULL DEFAULT FALSE, "permisos" TEXT[] NOT NULL DEFAULT '{}',
      "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await clientDestino.query(`
    CREATE TABLE IF NOT EXISTS registros_pendientes (
      "id" SERIAL PRIMARY KEY, "email" TEXT UNIQUE NOT NULL, "passwordHash" TEXT NOT NULL, "nombre" TEXT NOT NULL,
      "primerApellido" TEXT NOT NULL, "segundoApellido" TEXT, "apodo" TEXT,
      "token" TEXT UNIQUE NOT NULL, "expiraEn" TIMESTAMP NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

// ⚠️ TEMPORAL: copia tot l'esquema i totes les dades de la base de dades
// actual (la de Render, ja connectada com a `pool`) cap a la base de dades
// nova indicada a la variable d'entorn SUPABASE_DATABASE_URL. Fes-la servir
// UNA VEGADA i esborra-la del server.js. No esborra ni toca la base de dades
// d'origen — només llegeix d'ella.
app.get('/api/migrar-a-supabase', async (req, res) => {
  if (req.query.confirm !== 'si') {
    return res.json({ success: false, aviso: 'Això copia TOTES les dades cap a SUPABASE_DATABASE_URL. Afegeix ?confirm=si per confirmar.' });
  }
  if (!process.env.SUPABASE_DATABASE_URL) {
    return res.status(400).json({ success: false, error: 'Falta la variable d\'entorn SUPABASE_DATABASE_URL a Render.' });
  }

  const { Pool: PoolDestino } = require('pg');
  const poolDestino = new PoolDestino({
    connectionString: process.env.SUPABASE_DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

  const resultado = [];
  try {
    await crearEsquemaCompleto(poolDestino);

    for (const tabla of ORDRE_TAULES) {
      const origen = await pool.query(`SELECT * FROM "${tabla}"`);
      const filas = origen.rows;
      let copiadas = 0;

      for (const fila of filas) {
        const columnas = Object.keys(fila);
        const placeholders = columnas.map((_, i) => `$${i + 1}`).join(', ');
        const nombresCol = columnas.map(c => `"${c}"`).join(', ');
        const valores = columnas.map(c => {
          const v = fila[c];
          // Les columnes JSONB (com "niveles") arriben com a array/objecte JS
          // des de node-pg. Cal passar-les com a text JSON explícit — si no,
          // node-pg intenta serialitzar-les com a array de Postgres i falla.
          // Els arrays de text normals (com "permisos"/"permisosAPP") NO
          // s'han de tocar: es distingeixen perquè un array JSONB conté
          // objectes, mentre que un TEXT[] conté cadenes soltes.
          const esArrayObjectes = Array.isArray(v) && v.length > 0 && typeof v[0] === 'object' && v[0] !== null;
          const esObjectePla = v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Date);
          if (esArrayObjectes || esObjectePla) return JSON.stringify(v);
          return v;
        });
        await poolDestino.query(
          `INSERT INTO "${tabla}" (${nombresCol}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`,
          valores
        );
        copiadas++;
      }

      // reajustem la seqüència de l'id perquè els propers inserts (sense id
      // explícit) continuïn a partir del màxim copiat, no des d'1
      if (!TAULES_SENSE_ID_SERIAL.has(tabla)) {
        await poolDestino.query(
          `SELECT setval(pg_get_serial_sequence('"${tabla}"', 'id'), COALESCE((SELECT MAX("id") FROM "${tabla}"), 1))`
        );
      }

      resultado.push({ tabla, filas: filas.length, copiadas });
    }

    res.json({ success: true, resultado, aviso: 'Migració completada. Comprova els comptadors i, si tot quadra, actualitza DATABASE_URL a Render i esborra aquest endpoint.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: error.message, progreso: resultado });
  } finally {
    await poolDestino.end();
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});