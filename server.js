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
app.get('/api/generate', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM castellers');
    const castellers = result.rows;

    // Separar por roles
    const baix = castellers.find(c => c.role === 'baix');
    const segons = castellers.filter(c => c.role === 'segon');
    const tersos = castellers.filter(c => c.role === 'terç');
    const acotxador = castellers.find(c => c.role === 'acotxador');
    const enxaneta = castellers.find(c => c.role === 'enxaneta');

    // Validación mínima
    if (!baix || segons.length < 1 || tersos.length < 1 || !acotxador || !enxaneta) {
      return res.json({
        success: false,
        message: 'Faltan roles necesarios para montar un castell'
      });
    }

    const structure = {
      baix,
      segons: segons.slice(0, 2),
      tersos: tersos.slice(0, 2),
      pom: {
        acotxador,
        enxaneta
      }
    };

    res.json({
      success: true,
      structure
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Error generando castell');
  }
});

// 🚀 Puerto (Render usa process.env.PORT)
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});