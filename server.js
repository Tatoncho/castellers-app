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

    // estructuras a evaluar
    const estructuras = [
      { nombre: '2d6', segons: 2, tersos: 2 },
      { nombre: '3d7', segons: 3, tersos: 3 },
      { nombre: '4d7', segons: 4, tersos: 4 },
      { nombre: '5d7', segons: 5, tersos: 5 }
    ];

    // función riesgo
    const calcularRiesgo = ({ baix, segons, tersos, pom }) => {
      let riesgo = 0;

      const mediaSegons = segons.reduce((acc, s) => acc + s.altura, 0) / segons.length;
      const mediaTersos = tersos.reduce((acc, t) => acc + t.altura, 0) / tersos.length;

      const diff1 = Math.abs(baix.altura - mediaSegons);
      const diff2 = Math.abs(mediaSegons - mediaTersos);

      riesgo += diff1 * 0.3;
      riesgo += diff2 * 0.3;

      if (pom.enxaneta.altura > 140) riesgo += 20;
      if (pom.acotxador.altura > 150) riesgo += 15;

      return Math.round(riesgo);
    };

    const clasificarRiesgo = (riesgo) => {
      if (riesgo < 20) return '🟢 Seguro';
      if (riesgo < 50) return '🟡 Medio';
      return '🔴 Alto';
    };

    // función generadora por estructura
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

      // validaciones
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

      // selección óptima
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

    // generar todas las propuestas
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