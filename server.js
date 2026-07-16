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

// 🚀 Puerto (Render usa process.env.PORT)
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});