const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

// 🔑 Conexión a PostgreSQL (Render)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// 🧪 Ruta básica
app.get('/', (req, res) => {
  res.send('Castellers API funcionando 🚀');
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

// api para cargar miembros y sus datos
app.post('/api/castellers', async (req, res) => {
  try {
    const { nombre, altura, peso, rol } = req.body;

    if (!nombre) {
      return res.status(400).json({ error: 'nombre es obligatorio' });
    }

    const result = await pool.query(
      `INSERT INTO castellers (nombre, altura, peso, rol)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [nombre, altura || null, peso || null, rol || null]
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

//api generar castells
app.get('/api/generar', async (req, res) => {
  try {
    const resultado = await pool.query('SELECT * FROM castellers');
    const castellers = resultado.rows;

    // helpers
    const obtenerMasAltos = (arr) => [...arr].sort((a, b) => b.altura - a.altura);
    const obtenerMasBajos = (arr) => [...arr].sort((a, b) => a.altura - b.altura);

    // separar rols
    const baixos = castellers.filter(c => c.rol === 'baix');
    const segons = castellers.filter(c => c.rol === 'segon');
    const tersos = castellers.filter(c => c.rol === 'terç');
    const acotxadors = castellers.filter(c => c.rol === 'acotxador');
    const enxanetes = castellers.filter(c => c.rol === 'enxaneta');

    // elegir mejores dentro del rol
    const baix = obtenerMasAltos(baixos)[0];
    const Segons = obtenerMasAltos(segons).slice(0, 2);
    const Tersos = obtenerMasAltos(tersos).slice(0, 2);
    const acotxador = obtenerMasBajos(acotxadors)[0];
    const enxaneta = obtenerMasBajos(enxanetes)[0];

    // validación
    if (!baix || Segons.length < 1 || Tersos.length < 1 || !acotxador || !enxaneta) {
      return res.json({
        exit: false,
        mensaje: 'Faltan rols necesarios para montar un castell'
      });
    }

    const estructura = {
      baix,
      segons: Segons,
      tersos: Tersos,
      pom: {
        acotxador,
        enxaneta
      }
    };

const riesgo = calcularRiesgo(estructura);

const clasificarRiesgo = (riesgo) => {
  if (riesgo < 20) return '🟢 Seguro';
  if (riesgo < 50) return '🟡 Medio';
  return '🔴 Alto';
};

const nivel = clasificarRiesgo(riesgo);

    res.json({
      success: true,
      estructura: estructura,
	  riesgo,
	  nivel
    });

  } catch (error) {
    console.error(error);
    res.status(500).send('Error generando castell');
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