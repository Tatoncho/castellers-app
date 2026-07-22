const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// 🔑 Conexión a PostgreSQL (Render)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// 🔥 TEST DB
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({
      success: true,
      time: result.rows[0],
    });
  } catch (error) {
    console.error('Error DB:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// ⚠️ TEMPORAL: ejecuta la migración de columnas nuevas (alineación con el CSV)
// al cargar esta URL. BÓRRALA (o comenta esta ruta entera) en cuanto la hayas
// ejecutado una vez — deja tu base de datos abierta a cualquiera con el link.
app.get('/api/migrate', async (req, res) => {
  const statements = [
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS external_id INTEGER UNIQUE`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS primer_cognom TEXT`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS segon_cognom TEXT`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS alias TEXT`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS posicio_pinya TEXT`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS te_app BOOLEAN`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS email TEXT`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS mobil TEXT`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS data_naixement DATE`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS data_entrega_samarreta DATE`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS revisat BOOLEAN`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS estat_acollida TEXT`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS habitual BOOLEAN`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS permisos_app TEXT`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS integrant_colla TEXT`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS lesionat_llarga_durada BOOLEAN`,
    `ALTER TABLE castellers ADD COLUMN IF NOT EXISTS formularis INTEGER`
  ];

  const resultados = [];
  try {
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
      total: statements.length,
      aplicadas: resultados.length - fallos.length,
      fallidas: fallos.length,
      detalle: resultados,
      aviso: 'Recuerda eliminar esta ruta (/api/migrate) del server.js ahora que ya la has ejecutado.'
    });
  } catch (error) {
    console.error('Error migrando:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

//defino estructuras
const estructuras = [
  { nombre: '2d6', segons: 2, tersos: 2 },
  { nombre: '3d7', segons: 3, tersos: 3 },
  { nombre: '4d7', segons: 4, tersos: 4 },
  { nombre: '5d7', segons: 5, tersos: 5 }
];

//Función generadora por estructura
const generarParaEstructura = (castellers, config) => {

  const obtenerMasAltos = (arr) => [...arr].sort((a, b) => b.altura - a.altura);
  const obtenerMasBajos = (arr) => [...arr].sort((a, b) => a.altura - b.altura);

  const baixos = castellers.filter(c => c.rol === 'baix');
  const segons = castellers.filter(c => c.rol === 'segon');
  const tersos = castellers.filter(c => c.rol === 'terç');
  const acotxadors = castellers.filter(c => c.rol === 'acotxador');
  const enxanetes = castellers.filter(c => c.rol === 'enxaneta');

  const resultado = {
    tipo: config.nombre,
    valido: true,
    mensajes: []
  };

  // VALIDACIONES DINÁMICAS
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

  // SELECCIÓN ÓPTIMA
  const estructura = {
    baix: obtenerMasAltos(baixos)[0],
    segons: obtenerMasAltos(segons).slice(0, config.segons),
    tersos: obtenerMasAltos(tersos).slice(0, config.tersos),
    pom: {
      acotxador: obtenerMasBajos(acotxadors)[0],
      enxaneta: obtenerMasBajos(enxanetes)[0]
    }
  };

  resultado.estructura = estructura;
  return resultado;
};

// api para cargar miembros y sus datos
app.post('/api/castellers', async (req, res) => {
  try {
    const {
      nombre, altura, peso, rol,
      external_id, primer_cognom, segon_cognom, alias, posicio_pinya,
      te_app, email, mobil, data_naixement, data_entrega_samarreta,
      revisat, estat_acollida, habitual, permisos_app, integrant_colla,
      lesionat_llarga_durada, formularis
    } = req.body;

    if (!nombre) {
      return res.status(400).json({ error: 'nombre es obligatorio' });
    }

    const result = await pool.query(
      `INSERT INTO castellers (
         nombre, altura, peso, rol,
         external_id, primer_cognom, segon_cognom, alias, posicio_pinya,
         te_app, email, mobil, data_naixement, data_entrega_samarreta,
         revisat, estat_acollida, habitual, permisos_app, integrant_colla,
         lesionat_llarga_durada, formularis
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
       RETURNING *`,
      [
        nombre,
        altura || null,
        peso || null,
        rol || null,
        external_id || null,
        primer_cognom || null,
        segon_cognom || null,
        alias || null,
        posicio_pinya || null,
        te_app === undefined ? null : te_app,
        email || null,
        mobil || null,
        data_naixement || null,
        data_entrega_samarreta || null,
        revisat === undefined ? null : revisat,
        estat_acollida || null,
        habitual === undefined ? null : habitual,
        permisos_app || null,
        integrant_colla || null,
        lesionat_llarga_durada === undefined ? null : lesionat_llarga_durada,
        formularis === undefined ? null : formularis
      ]
    );

    res.json({
      success: true,
      casteller: result.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// ⚠️ TEMPORAL: borra TODOS los castellers cargados. Sin ?confirm=si solo
// muestra un aviso (no hace nada); con ?confirm=si sí que vacía la tabla.
// Bórrala del código en cuanto hayas reimportado el CSV.
app.get('/api/reset-castellers', async (req, res) => {
  if (req.query.confirm !== 'si') {
    return res.json({
      success: false,
      aviso: 'Esto borrará TODOS los castellers de la base de datos. Añade ?confirm=si a la URL para confirmar, ej: /api/reset-castellers?confirm=si'
    });
  }

  try {
    await pool.query('TRUNCATE TABLE castellers RESTART IDENTITY');
    res.json({
      success: true,
      mensaje: 'Tabla castellers vaciada. Ya puedes importar el CSV.'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: error.message });
  }
});

//api para visualizar miembros
app.get('/api/castellers', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM castellers ORDER BY id DESC');
    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

//api para editar un miembro existente
app.put('/api/castellers/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { nombre, altura, peso, rol } = req.body;

    if (!nombre) {
      return res.status(400).json({ error: 'nombre es obligatorio' });
    }

    const result = await pool.query(
      `UPDATE castellers
       SET nombre = $1, altura = $2, peso = $3, rol = $4
       WHERE id = $5
       RETURNING *`,
      [nombre, altura || null, peso || null, rol || null, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Casteller no trobat' });
    }

    res.json({
      success: true,
      casteller: result.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

//api generar castells
app.get('/api/generar', async (req, res) => {
  try {
    const resultado = await pool.query('SELECT * FROM castellers');
    const castellers = resultado.rows;

    const obtenerMasAltos = (arr) => [...arr].sort((a, b) => b.altura - a.altura);
    const obtenerMasBajos = (arr) => [...arr].sort((a, b) => a.altura - b.altura);

    const estructuras = [
      { nombre: '2d6', segons: 2, tersos: 2 },
      { nombre: '3d7', segons: 3, tersos: 3 },
      { nombre: '4d7', segons: 4, tersos: 4 },
      { nombre: '5d7', segons: 5, tersos: 5 }
    ];

    const calcularRiesgo = ({ baix, segons, tersos, pom }) => {
      let riesgo = 0;

      const mediaSegons = segons.reduce((acc, s) => acc + s.altura, 0) / segons.length;
      const mediaTersos = tersos.reduce((acc, t) => acc + t.altura, 0) / tersos.length;

      riesgo += Math.abs(baix.altura - mediaSegons) * 0.3;
      riesgo += Math.abs(mediaSegons - mediaTersos) * 0.3;

      if (pom.enxaneta.altura > 140) riesgo += 20;
      if (pom.acotxador.altura > 150) riesgo += 15;

      return Math.round(riesgo);
    };

    const clasificarRiesgo = (riesgo) => {
      if (riesgo < 20) return '🟢 Seguro';
      if (riesgo < 50) return '🟡 Medio';
      return '🔴 Alto';
    };

    const generarParaEstructura = (config) => {

      const baixos = castellers.filter(c => c.rol === 'baix');
      const segons = castellers.filter(c => c.rol === 'segon');
      const tersos = castellers.filter(c => c.rol === 'terç');
      const acotxadors = castellers.filter(c => c.rol === 'acotxador');
      const enxanetes = castellers.filter(c => c.rol === 'enxaneta');

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
    }; // 👈 ESTA LÍNEA ES CLAVE (muchas veces falta)

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

//evaluación de riesgo
const calcularRiesgo = ({ baix, segons, tersos, pom }) => {
  let riesgo = 0;

  // 📏 Diferencia de altura entre niveles
  const mediaSegons = segons.reduce((acc, s) => acc + s.altura, 0) / segons.length;
  const mediaTersos = tersos.reduce((acc, t) => acc + t.altura, 0) / tersos.length;

  const diffBaixSegons = Math.abs(baix.altura - mediaSegons);
  const diffSegonsTersos = Math.abs(mediaSegons - mediaTersos);

  riesgo += diffBaixSegons * 0.3;
  riesgo += diffSegonsTersos * 0.3;

  // ⚠️ Penalizar si el enxaneta es demasiado alto
  if (pom.enxaneta.altura > 140) {
    riesgo += 20;
  }

  // ⚠️ Penalizar si el acotxador es alto
  if (pom.acotxador.altura > 150) {
    riesgo += 15;
  }

  return Math.round(riesgo);
};


// 🚀 Puerto (Render usa process.env.PORT)
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});