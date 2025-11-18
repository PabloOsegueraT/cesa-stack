// api/src/db.mjs
import mysql from 'mysql2/promise';
import fs from 'node:fs';

const useSSL = (process.env.DB_SSL ?? 'false').toLowerCase() === 'true';
const ssl =
  useSSL
    ? {
        ca: fs.readFileSync(process.env.DB_SSL_CA || '', 'utf8'),
        minVersion: 'TLSv1.2',
      }
    : false;

export const pool = mysql.createPool({
  host: process.env.DB_HOST ?? '127.0.0.1',
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  ssl,
});