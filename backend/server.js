
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

// Conexión a PostgreSQL
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

// Middleware para registrar las consultas
app.use((req, res, next) => {
  console.log(
    `${new Date().toLocaleString()} - ${req.method} ${req.url}`
  );
  next();
});

// Middleware para validar el token JWT
const verificarToken = (req, res, next) => {
  const authorization = req.headers.authorization;

  if (!authorization) {
    return res.status(401).json({
      error: "Token no proporcionado",
    });
  }

  const partes = authorization.split(" ");

  if (partes.length !== 2 || partes[0] !== "Bearer" || !partes[1]) {
    return res.status(401).json({
      error: "Formato de token inválido",
    });
  }

  try {
    const payload = jwt.verify(
      partes[1],
      process.env.JWT_SECRET
    );

    req.email = payload.email;
    next();
  } catch (error) {
    return res.status(401).json({
      error: "Token inválido",
    });
  }
};

// Ruta inicial
app.get("/", (req, res) => {
  res.send("Servidor Soft Jobs funcionando");
});

// Comprobar conexión con PostgreSQL
app.get("/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT current_database()");

    res.json({
      mensaje: "Conexión exitosa",
      database: result.rows[0].current_database,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Error de conexión",
    });
  }
});

// Registrar un nuevo usuario
app.post("/usuarios", async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body || {};

    if (!email || !password || !rol || !lenguage) {
      return res.status(400).json({
        error: "Todos los campos son obligatorios",
      });
    }

    const passwordEncriptada = await bcrypt.hash(password, 10);

    const query = `
      INSERT INTO usuarios (email, password, rol, lenguage)
      VALUES ($1, $2, $3, $4)
      RETURNING id, email, rol, lenguage
    `;

    const values = [email, passwordEncriptada, rol, lenguage];
    const result = await pool.query(query, values);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);

    if (error.code === "23505") {
      return res.status(409).json({
        error: "El correo ya está registrado",
      });
    }

    res.status(500).json({
      error: "Error al registrar usuario",
    });
  }
});

// Iniciar sesión
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    // Validar que existan las credenciales
    if (!email || !password) {
      return res.status(400).json({
        error: "El correo y la contraseña son obligatorios",
      });
    }

    const query = "SELECT * FROM usuarios WHERE email = $1";
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(400).json({
        error: "Usuario no encontrado",
      });
    }

    const usuario = result.rows[0];

    const passwordValida = await bcrypt.compare(
      password,
      usuario.password
    );

    if (!passwordValida) {
      return res.status(400).json({
        error: "Contraseña incorrecta",
      });
    }

    if (!process.env.JWT_SECRET) {
      throw new Error("JWT_SECRET no está configurado");
    }

    const token = jwt.sign(
      { email: usuario.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Error al iniciar sesión",
    });
  }
});

// Obtener los datos del usuario autenticado
app.get("/usuarios", verificarToken, async (req, res) => {
  try {
    const query = `
      SELECT id, email, rol, lenguage
      FROM usuarios
      WHERE email = $1
    `;

    const result = await pool.query(query, [req.email]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Usuario no encontrado",
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Error al obtener los datos del usuario",
    });
  }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor funcionando en http://localhost:${PORT}`);
});