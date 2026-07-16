const express = require("express");
const app = express();
const pool = require("./db");

app.use(express.json());
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;

// 🔥 TEST DB
app.get("/api/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error DB");
  }
});

app.listen(PORT, () => {
  console.log("Servidor corriendo en puerto " + PORT);
});