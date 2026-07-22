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
    const { name, height, weight, role } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Name es obligatorio' });
    }

    const result = await pool.query(
      `INSERT INTO castellers (name, height, weight, role)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name, height || null, weight || null, role || null]
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
    const obtenerMasAltos = (arr) => [...arr].sort((a, b) => b.height - a.height);
    const obtenerMasBajos = (arr) => [...arr].sort((a, b) => a.height - b.height);

    // separar roles
    const baixos = castellers.filter(c => c.role === 'baix');
    const segons = castellers.filter(c => c.role === 'segon');
    const tersos = castellers.filter(c => c.role === 'terç');
    const acotxadors = castellers.filter(c => c.role === 'acotxador');
    const enxanetes = castellers.filter(c => c.role === 'enxaneta');

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
        mensaje: 'Faltan roles necesarios para montar un castell'
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

    res.json({
      exit: true,
      estructura
    });

  } catch (error) {
    console.error(error);
    res.status(500).send('Error generando castell');
  }
});

//BORRAR
app.get('/api/alter-db', async (req, res) => {
  try {
    await pool.query(`ALTER TABLE castellers RENAME COLUMN name TO nombre`);
    await pool.query(`ALTER TABLE castellers RENAME COLUMN height TO altura`);
    await pool.query(`ALTER TABLE castellers RENAME COLUMN weight TO peso`);
    await pool.query(`ALTER TABLE castellers RENAME COLUMN role TO rol`);

    res.send('✅ Base de datos actualizada a español');
  } catch (error) {
    console.error(error);
    res.status(500).send(error.message);
  }
});

// 🚀 Puerto (Render usa process.env.PORT)
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});