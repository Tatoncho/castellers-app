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
//BORRAR
app.post('/api/temporal-renombrar', async (req, res) => {
  const querySql = `
    UPDATE castellers
    SET nombre = CASE nombre
        WHEN 'ejemplo1' THEN 'NAN'
        WHEN 'ejemplo2' THEN 'Guillem'
        WHEN 'ejemplo3' THEN 'Roger'
        WHEN 'ejemplo4' THEN 'Laia'
        WHEN 'ejemplo5' THEN 'Joan'
        WHEN 'ejemplo6' THEN 'Núria'
        WHEN 'ejemplo7' THEN 'Oriol'
        WHEN 'ejemplo8' THEN 'Mireia'
        WHEN 'ejemplo9' THEN 'Arnau'
        WHEN 'ejemplo10' THEN 'Anna'
        WHEN 'ejemplo11' THEN 'Pol'
        WHEN 'ejemplo12' THEN 'Marta'
        WHEN 'ejemplo13' THEN 'Xavier'
        WHEN 'ejemplo14' THEN 'Clara'
        WHEN 'ejemplo15' THEN 'Pau'
        WHEN 'ejemplo16' THEN 'Berta'
        WHEN 'ejemplo17' THEN 'Martí'
        WHEN 'ejemplo18' THEN 'Virginia'
        WHEN 'ejemplo19' THEN 'Guillem'
        WHEN 'ejemplo20' THEN 'Sílvia'
        WHEN 'ejemplo21' THEN 'Albert'
        WHEN 'ejemplo22' THEN 'Laura'
        WHEN 'ejemplo23' THEN 'Roger'
        WHEN 'ejemplo24' THEN 'Meritxell'
        WHEN 'ejemplo25' THEN 'Sergi'
        WHEN 'ejemplo26' THEN 'Eulàlia'
        WHEN 'ejemplo27' THEN 'Aleix'
        WHEN 'ejemplo28' THEN 'Judit'
        WHEN 'ejemplo29' THEN 'Lluís'
        WHEN 'ejemplo30' THEN 'Aina'
        WHEN 'ejemplo31' THEN 'Gerard'
        WHEN 'ejemplo32' THEN 'Neus'
        WHEN 'ejemplo33' THEN 'Bernat'
        WHEN 'ejemplo34' THEN 'Ariadna'
        WHEN 'ejemplo35' THEN 'Joan Carles'
        ELSE nombre
    END
    WHERE nombre LIKE 'ejemplo%';
  `;

  try {
    // NOTA: Reemplaza "db" por el nombre de tu variable de conexión de Postgres 
    // (comúnmente se llama "pool", "client", "db", "sequelize", o "knex")
    const resultado = await pool.query(querySql); 
    
    res.status(200).json({
      mensaje: "¡Actualización completada con éxito!",
      filasModificadas: resultado.rowCount
    });
  } catch (error) {
    console.error("Error al renombrar castellers:", error);
    res.status(500).json({ error: "Error interno en la base de datos" });
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