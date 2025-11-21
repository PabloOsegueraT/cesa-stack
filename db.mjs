// api/src/db.mjs
import mysql from 'mysql2/promise';
import fs from 'node:fs';

const DB_HOST = process.env.DB_HOST ?? 'db';
const DB_PORT = Number(process.env.DB_PORT ?? 3306);
const DB_USER = process.env.DB_USER ?? 'dev';
const DB_NAME = process.env.DB_NAME ?? 'cesa';
// ✅ lee DB_PASSWORD y, si no existe, DB_PASS
const DB_PASSWORD = process.env.DB_PASSWORD ?? process.env.DB_PASS ?? '';

const useSSL = (process.env.DB_SSL ?? 'false').toLowerCase() === 'true';
const ssl =
  useSSL
    ? {
        ca: fs.readFileSync(process.env.DB_SSL_CA || '', 'utf8'),
        minVersion: 'TLSv1.2',
      }
    : undefined;

export const pool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,   // 👈 importante
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  namedPlaceholders: true,
  ...(useSSL ? { ssl } : {}),
});

// Ping de verificación al arrancar (no imprime la contraseña)
try {
  await pool.query('SELECT 1');
  console.log(`MySQL OK: user=${DB_USER} host=${DB_HOST}:${DB_PORT} hasPwd=${DB_PASSWORD.length > 0}`);
} catch (err) {
  console.error('MySQL connection failed:', err.message);
}