// src/server.mjs
// src/server.mjs
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import { pool } from './db.mjs';
import crypto from 'crypto';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';


/* ========================
 *  Configuración uploads (avatares)
 * ====================== */

// ========================
//  Configuración de uploads para avatares
// ========================
const avatarsDir =
  process.env.AVATARS_DIR || path.join(process.cwd(), 'uploads', 'avatars');

// Nos aseguramos de que exista la carpeta
fs.mkdirSync(avatarsDir, { recursive: true });

// Storage de multer para guardar archivos en disco
const avatarStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, avatarsDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '');
    const name = crypto.randomBytes(16).toString('hex');
    cb(null, `${name}${ext}`);
  },
});

// Límite de tamaño y validación de tipo
const avatarUpload = multer({
  storage: avatarStorage,
  limits: {
    fileSize: 15 * 1024 * 1024, // 15 MB por si tus fotos están grandes
  },
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Solo se permiten imágenes'));
    }
    cb(null, true);
  },
});

/* ========================
 *  App base
 * ====================== */

const app = express();

// Servir archivos estáticos (avatares, etc.)
app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));

/* ========================
 *  Middlewares base
 * ====================== */

const allowOrigin = process.env.CORS_ALLOW_ORIGIN || '*';
app.use(
  cors({
    origin: allowOrigin,
    credentials: false,
    allowedHeaders: ['Content-Type', 'x-role', 'x-user-id'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  }),
);
app.use(express.json({ limit: '30mb' }));

// Logger simple
app.use((req, _res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

const api = express.Router();

/* ========================
 *  Rutas públicas
 * ====================== */

api.get('/health', (_req, res) => res.json({ ok: true }));

// Login básico: devuelve { user: { id, name, email, role } }
api.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    if (!email || !password) {
      return res.status(400).json({ message: 'email y password requeridos' });
    }

    const sql = `
      SELECT u.id, u.name, u.email, u.password_hash, u.is_active, r.name AS role
      FROM users u
      JOIN roles r ON r.id = u.role_id
      WHERE u.email = ?
      LIMIT 1
    `;
    const [rows] = await pool.execute(sql, [email]);
    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) return res.status(401).json({ message: 'Credenciales inválidas' });

    const u = list[0];
    if (!u.is_active) return res.status(403).json({ message: 'Usuario inactivo' });

    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ message: 'Credenciales inválidas' });

    const role = String(u.role || '').toLowerCase(); // 'root' | 'admin' | 'usuario'
    return res.json({ user: { id: u.id, name: u.name, email: u.email, role } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Error interno' });
  }
});

/* ========================
 *  Helpers / Middlewares
 * ====================== */

// Solo root
function requireRoot(req, res, next) {
  const role = String(req.header('x-role') || '').toLowerCase();
  if (role !== 'root') {
    return res.status(403).json({ message: 'Solo root puede realizar esta acción' });
  }
  next();
}

// Root o admin
function requireAdminOrRoot(req, res, next) {
  const role = String(req.header('x-role') || '').toLowerCase();
  if (role !== 'root' && role !== 'admin') {
    return res.status(403).json({ message: 'Solo admin o root pueden realizar esta acción' });
  }
  next();
}

// Cualquier usuario autenticado (root, admin o usuario)
function requireAnyAuthenticated(req, res, next) {
  const role = String(req.header('x-role') || '').toLowerCase();
  const validRoles = ['root', 'admin', 'usuario'];
  if (!validRoles.includes(role)) {
    return res.status(401).json({ message: 'No autenticado' });
  }

  const userId = Number(req.header('x-user-id'));
  if (!Number.isFinite(userId) || userId <= 0) {
    return res.status(400).json({ message: 'x-user-id requerido' });
  }

  req.authUserId = userId;
  req.authRole = role;
  next();
}

async function getRoleIdByName(name) {
  const [rows] = await pool.execute('SELECT id FROM roles WHERE name = ? LIMIT 1', [name]);
  const list = Array.isArray(rows) ? rows : [];
  return list.length ? list[0].id : null;
}

/* ========================
 *  Catálogos
 * ====================== */

api.get('/roles', async (_req, res) => {
  try {
    const [rows] = await pool.execute('SELECT id, name FROM roles ORDER BY id');
    res.json({ roles: Array.isArray(rows) ? rows : [] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Error interno' });
  }
});

/* ========================
 *  Gestión de usuarios (root / admin)
 * ====================== */

// Crear usuario (solo root)
api.post('/users', requireRoot, async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      role = 'usuario', // 'root' | 'admin' | 'usuario'
      phone = null,
      about = null,
      avatar_url = null,
      is_active = 1,
    } = req.body ?? {};

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'name, email y password son requeridos' });
    }

    const roleName = String(role).toLowerCase();
    if (!['root', 'admin', 'usuario'].includes(roleName)) {
      return res.status(400).json({ message: 'role inválido' });
    }

    const roleId = await getRoleIdByName(roleName);
    if (!roleId) return res.status(400).json({ message: `Rol no configurado: ${roleName}` });

    // ¿email ya existe?
    const [dups] = await pool.execute('SELECT 1 FROM users WHERE email=? LIMIT 1', [email]);
    if (Array.isArray(dups) && dups.length) {
      return res.status(409).json({ message: 'Email ya registrado' });
    }

    const hash = await bcrypt.hash(password, 10);

    const [result] = await pool.execute(
      `INSERT INTO users (role_id, name, email, password_hash, phone, about, avatar_url, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [roleId, name, email, hash, phone, about, avatar_url, is_active ? 1 : 0],
    );

    res.status(201).json({
      user: {
        id: result.insertId,
        name,
        email,
        role: roleName,
        phone,
        about,
        avatar_url,
        is_active: !!is_active,
      },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Error interno' });
  }
});

// Listar usuarios (root o admin) con filtro opcional ?q=
api.get('/users', requireAdminOrRoot, async (req, res) => {
  try {
    const q = (req.query.q || '').toString().trim();
    let sql = `
      SELECT u.id, u.name, u.email, u.is_active, r.name AS role, u.phone, u.about, u.avatar_url
      FROM users u
      JOIN roles r ON r.id = u.role_id
    `;
    const params = [];
    if (q) {
      sql += ' WHERE u.name LIKE ? OR u.email LIKE ? ';
      params.push(`%${q}%`, `%${q}%`);
    }
    sql += ' ORDER BY u.id DESC LIMIT 200';

    const [rows] = await pool.execute(sql, params);
    res.json({ users: Array.isArray(rows) ? rows : [] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Error interno' });
  }
});

// Eliminar usuario (solo root)
api.delete('/users/:id', requireRoot, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: 'id inválido' });

    await pool.execute('DELETE FROM users WHERE id = ?', [id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Error interno' });
  }
});

// Cambiar contraseña (solo root)
api.put('/users/:id/password', requireRoot, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { password } = req.body ?? {};
    if (!id || !password) return res.status(400).json({ message: 'id y password requeridos' });

    const hash = await bcrypt.hash(password, 10);
    await pool.execute('UPDATE users SET password_hash = ? WHERE id = ?', [hash, id]);

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Error interno' });
  }
});

/* ========================
 *  Perfil del usuario actual
 * ====================== */

// GET /api/me  -> datos del usuario logueado
api.get('/me', requireAnyAuthenticated, async (req, res) => {
  try {
    const userId = req.authUserId;

    const sql = `
      SELECT
        u.id,
        u.name,
        u.email,
        u.phone,
        u.about,
        u.avatar_url,
        u.is_active,
        r.name AS role
      FROM users u
      JOIN roles r ON r.id = u.role_id
      WHERE u.id = ?
      LIMIT 1
    `;

    const [rows] = await pool.execute(sql, [userId]);
    const list = Array.isArray(rows) ? rows : [];

    if (!list.length) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const u = list[0];

    return res.json({
      user: {
        id: u.id,
        name: u.name,
        email: u.email,
        role: (u.role || '').toLowerCase(), // root | admin | usuario
        phone: u.phone,
        about: u.about,
        avatar_url: u.avatar_url,
        is_active: !!u.is_active,
      },
    });
  } catch (err) {
    console.error('Error en GET /me:', err);
    return res.status(500).json({ message: 'Error al obtener perfil' });
  }
});

// PUT /api/me  -> actualizar perfil básico
// Acepta avatar_url o avatarUrl en el body
api.put('/me', requireAnyAuthenticated, async (req, res) => {
  try {
    const userId = req.authUserId;
    const { name, phone, about } = req.body ?? {};

    // Permitimos ambos nombres de campo por compatibilidad
    const avatarFromSnake = req.body?.avatar_url;
    const avatarFromCamel = req.body?.avatarUrl;
    const avatar_url =
      (avatarFromSnake ?? avatarFromCamel ?? '').toString().trim() || null;

    if (!name || !String(name).trim()) {
      return res.status(400).json({ message: 'name es requerido' });
    }

    await pool.execute(
      `
        UPDATE users
        SET name = ?, phone = ?, about = ?, avatar_url = ?
        WHERE id = ?
      `,
      [String(name).trim(), phone || null, about || null, avatar_url, userId]
    );

    // Devolvemos el perfil actualizado
    const [rows] = await pool.execute(
      `
        SELECT
          u.id,
          u.name,
          u.email,
          u.phone,
          u.about,
          u.avatar_url,
          u.is_active,
          r.name AS role
        FROM users u
        JOIN roles r ON r.id = u.role_id
        WHERE u.id = ?
        LIMIT 1
      `,
      [userId]
    );

    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      return res
        .status(404)
        .json({ message: 'Usuario no encontrado luego de actualizar' });
    }

    const u = list[0];

    return res.json({
      user: {
        id: u.id,
        name: u.name,
        email: u.email,
        role: (u.role || '').toLowerCase(),
        phone: u.phone,
        about: u.about,
        avatar_url: u.avatar_url,
        is_active: !!u.is_active,
      },
    });
  } catch (err) {
    console.error('Error en PUT /me:', err);
    return res.status(500).json({ message: 'Error al actualizar perfil' });
  }
});

// POST /api/me/avatar  -> subir foto de perfil (archivo)
api.post(
  '/me/avatar',
  requireAnyAuthenticated,
  // envolvemos avatarUpload para poder capturar errores de multer
  (req, res, next) => {
    avatarUpload.single('avatar')(req, res, (err) => {
      if (err) {
        console.error('Error de multer en /me/avatar:', err);
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res
            .status(400)
            .json({ message: 'La imagen es demasiado grande (máx 15 MB)' });
        }
        return res
          .status(400)
          .json({ message: err.message || 'Error al procesar la imagen' });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      const userId = req.authUserId;

      if (!req.file) {
        return res.status(400).json({ message: 'Archivo no recibido' });
      }

      const publicBase = process.env.PUBLIC_BASE_URL || '';
      let avatarUrl;

      if (publicBase) {
        // URL absoluta: https://mi-api.com/uploads/avatars/...
        const relative = path
          .relative(process.cwd(), req.file.path)
          .replace(/\\/g, '/');
        avatarUrl = `${publicBase}/${relative}`;
      } else {
        // URL relativa (la app debe anteponer Env.apiBaseUrl)
        avatarUrl = `/uploads/avatars/${path.basename(req.file.path)}`;
      }

      // Guardar la URL en la BD
      await pool.execute(
        'UPDATE users SET avatar_url = ? WHERE id = ?',
        [avatarUrl, userId]
      );

      // Devolver el usuario actualizado
      const [rows] = await pool.execute(
        `
          SELECT
            u.id,
            u.name,
            u.email,
            u.phone,
            u.about,
            u.avatar_url,
            u.is_active,
            r.name AS role
          FROM users u
          JOIN roles r ON r.id = u.role_id
          WHERE u.id = ?
          LIMIT 1
        `,
        [userId]
      );

      const list = Array.isArray(rows) ? rows : [];
      if (!list.length) {
        return res.status(404).json({ message: 'Usuario no encontrado' });
      }

      const u = list[0];

      return res.json({
        user: {
          id: u.id,
          name: u.name,
          email: u.email,
          role: (u.role || '').toLowerCase(), // root | admin | usuario
          phone: u.phone,
          about: u.about,
          avatar_url: u.avatar_url,
          is_active: !!u.is_active,
        },
      });
    } catch (err) {
      console.error('Error en POST /me/avatar:', err);
      return res.status(500).json({ message: 'Error al subir avatar' });
    }
  }
);

/* ========================
 *  Mapeos de tareas (IDs reales de tu BD)
 * ====================== */

// task_status.id
// 1 = pendiente
// 2 = en_proceso
// 3 = completada
// 4 = no_lograda
const STATUS_IDS = {
  pending: 1,
  in_progress: 2,
  done: 3,
};

// Para leer desde la BD (tasks.current_status_id -> código que usa Flutter)
const STATUS_CODES = {
  1: 'pending',
  2: 'in_progress',
  3: 'done',
  4: 'done', // 'no_lograda' la tratamos como done por ahora
};

// priorities.id
// 1 = baja
// 2 = media
// 3 = alta
const PRIORITY_CODES = {
  1: 'low',
  2: 'medium',
  3: 'high',
};

// Para insertar desde el body JSON de Flutter
const PRIORITY_IDS = {
  low: 1,
  medium: 2,
  high: 3,
};

/* ========================
 *  Tareas (admin / root + usuarios)
 * ====================== */

// LISTAR TODAS LAS TAREAS (admin / root)
// GET /api/tasks
api.get('/tasks', requireAdminOrRoot, async (_req, res) => {
  try {
    const sql = `
      SELECT
        t.id,
        t.title,
        t.description,
        t.due_date,
        t.priority_id,
        t.current_status_id,
        COALESCE(u.name, 'Sin asignar') AS assignee_name,
        (SELECT COUNT(*) FROM task_attachments att WHERE att.task_id = t.id) AS evidence_count,
        (SELECT COUNT(*) FROM task_comments    c   WHERE c.task_id   = t.id) AS comments_count
      FROM tasks t
      LEFT JOIN task_assignments ta ON ta.task_id = t.id AND ta.is_active = 1
      LEFT JOIN users          u  ON u.id  = ta.user_id
      WHERE t.archived = 0
      ORDER BY
        t.due_date IS NULL,
        t.due_date ASC,
        t.id DESC
    `;

    const [rows] = await pool.query(sql);
    const list = Array.isArray(rows) ? rows : [];

    const tasks = list.map((r) => {
      let dueDateStr = null;
      if (r.due_date) {
        // MySQL DATE -> JS Date
        dueDateStr = r.due_date.toISOString().slice(0, 10); // 'YYYY-MM-DD'
      }

      const statusCode = STATUS_CODES[r.current_status_id] || 'pending';
      const priorityCode = PRIORITY_CODES[r.priority_id] || 'medium';

      return {
        id: r.id,
        title: r.title,
        description: r.description || '',
        dueDate: dueDateStr,
        priority: priorityCode, // 'low' | 'medium' | 'high'
        status: statusCode, // 'pending' | 'in_progress' | 'done'
        assignee: r.assignee_name || 'Sin asignar',
        evidenceCount: r.evidence_count ?? 0,
        commentsCount: r.comments_count ?? 0,
      };
    });

    return res.json({ tasks });
  } catch (err) {
    console.error('Error listando tareas:', err);
    return res.status(500).json({ message: 'Error al listar tareas' });
  }
});

// CREAR TAREA (admin / root)
// POST /api/tasks
// Body JSON:
// {
//   "title": "Hacer mockups",
//   "description": "Para el sprint 3",
//   "priority": "medium",          // low | medium | high
//   "dueDate": "2025-11-20",       // opcional (YYYY-MM-DD)
//   "assigneeId": 5                // opcional (id de usuario)
// }
api.post('/tasks', requireAdminOrRoot, async (req, res) => {
  try {
    const {
      title,
      description = '',
      priority = 'medium',
      dueDate = null,
      assigneeId = null,
    } = req.body ?? {};

    if (!title || !String(title).trim()) {
      return res.status(400).json({ message: 'title es requerido' });
    }

    const priorityKey = String(priority).toLowerCase();
    const priorityId = PRIORITY_IDS[priorityKey] || PRIORITY_IDS.medium;
    const statusId = STATUS_IDS.pending;

    // quién creó la tarea (simulado por header)
    const headerUserId = Number(req.header('x-user-id'));
    const createdBy = Number.isFinite(headerUserId) ? headerUserId : null;

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // 1) Insertar task
      const [result] = await conn.query(
        `
          INSERT INTO tasks (title, description, priority_id, due_date, created_by, current_status_id)
          VALUES (?, ?, ?, ?, ?, ?)
        `,
        [title, description, priorityId, dueDate, createdBy, statusId],
      );
      const taskId = result.insertId;

      // 2) Asignar usuario si viene assigneeId
      let assigneeName = 'Sin asignar';
      if (assigneeId) {
        await conn.query(
          `
            INSERT INTO task_assignments (task_id, user_id)
            VALUES (?, ?)
          `,
          [taskId, assigneeId],
        );

        const [uRows] = await conn.query('SELECT name FROM users WHERE id = ? LIMIT 1', [
          assigneeId,
        ]);
        const uList = Array.isArray(uRows) ? uRows : [];
        if (uList.length) {
          assigneeName = uList[0].name;
        }
      }

      // 3) Historial de estado inicial
      await conn.query(
        `
          INSERT INTO task_status_history (task_id, user_id, from_status_id, to_status_id)
          VALUES (?, ?, NULL, ?)
        `,
        [taskId, createdBy, statusId],
      );

      await conn.commit();

      // Respuesta alineada con Task.fromJson
      return res.status(201).json({
        id: taskId,
        title,
        description,
        dueDate,
        priority: priorityKey,
        status: 'pending',
        assignee: assigneeName,
        evidenceCount: 0,
        commentsCount: 0,
      });
    } catch (err) {
      await conn.rollback();
      console.error('Error creando tarea:', err);
      return res.status(500).json({ message: 'Error al crear tarea' });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error('Error en POST /tasks:', err);
    return res.status(500).json({ message: 'Error interno' });
  }
});

// CAMBIAR ESTADO DE TAREA (cualquier rol autenticado)
// PUT /api/tasks/:id/status
// Body: { "status": "pending" | "in_progress" | "done" }
api.put('/tasks/:id/status', requireAnyAuthenticated, async (req, res) => {
  const taskId = Number(req.params.id);
  const { status } = req.body ?? {};
  const userId = req.authUserId;

  if (!taskId || !status) {
    return res.status(400).json({ message: 'taskId y status son requeridos' });
  }

  const statusKey = String(status).toLowerCase();
  const newStatusId = STATUS_IDS[statusKey];
  if (!newStatusId) {
    return res.status(400).json({ message: 'status inválido' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1) Leer estado actual
    const [rows] = await conn.query(
      'SELECT current_status_id FROM tasks WHERE id = ? FOR UPDATE',
      [taskId],
    );
    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      await conn.rollback();
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }
    const fromStatusId = list[0].current_status_id;

    // Si es el mismo, no hacemos nada
    if (fromStatusId === newStatusId) {
      await conn.rollback();
      return res.json({ ok: true, noop: true });
    }

    // 2) Insertar histórico
    await conn.query(
      `
        INSERT INTO task_status_history (task_id, user_id, from_status_id, to_status_id)
        VALUES (?, ?, ?, ?)
      `,
      [taskId, userId, fromStatusId, newStatusId],
    );

    // 3) Actualizar tasks.current_status_id (+ completed_at)
    const completedAt = newStatusId === STATUS_IDS.done ? new Date() : null;

    await conn.query(
      `
        UPDATE tasks
        SET current_status_id = ?, completed_at = ?
        WHERE id = ?
      `,
      [newStatusId, completedAt, taskId],
    );

    await conn.commit();

    return res.json({ ok: true });
  } catch (err) {
    console.error('Error cambiando estado de tarea:', err);
    await conn.rollback();
    return res.status(500).json({ message: 'Error al cambiar estado' });
  } finally {
    conn.release();
  }
});

// BORRAR TAREA (admin / root)
// DELETE /api/tasks/:id
api.delete('/tasks/:id', requireAdminOrRoot, async (req, res) => {
  const taskId = Number(req.params.id);
  if (!taskId) {
    return res.status(400).json({ message: 'id inválido' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1) Borrar evidencias
    await conn.query('DELETE FROM task_attachments WHERE task_id = ?', [taskId]);

    // 2) Borrar comentarios
    await conn.query('DELETE FROM task_comments WHERE task_id = ?', [taskId]);

    // 3) Borrar historial de estado
    await conn.query('DELETE FROM task_status_history WHERE task_id = ?', [taskId]);

    // 4) Borrar asignaciones
    await conn.query('DELETE FROM task_assignments WHERE task_id = ?', [taskId]);

    // 5) Borrar la tarea principal
    const [result] = await conn.query('DELETE FROM tasks WHERE id = ? LIMIT 1', [taskId]);

    if (!result.affectedRows) {
      await conn.rollback();
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }

    await conn.commit();
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Error borrando tarea:', err);
    await conn.rollback();
    return res.status(500).json({ message: 'Error al borrar tarea' });
  } finally {
    conn.release();
  }
});

// LISTAR MIS TAREAS (usuario actual)
// GET /api/my-tasks
api.get('/my-tasks', requireAnyAuthenticated, async (req, res) => {
  try {
    const userId = req.authUserId;

    const sql = `
      SELECT
        t.id,
        t.title,
        t.description,
        t.due_date,
        t.priority_id,
        t.current_status_id,
        u.name AS assignee_name,
        (SELECT COUNT(*) FROM task_attachments att WHERE att.task_id = t.id) AS evidence_count,
        (SELECT COUNT(*) FROM task_comments    c   WHERE c.task_id   = t.id) AS comments_count
      FROM tasks t
      JOIN task_assignments ta
        ON ta.task_id = t.id
       AND ta.is_active = 1
      JOIN users u
        ON u.id = ta.user_id
      WHERE
        t.archived = 0
        AND ta.user_id = ?
      ORDER BY
        t.due_date IS NULL,
        t.due_date ASC,
        t.id DESC
    `;

    const [rows] = await pool.query(sql, [userId]);
    const rawList = Array.isArray(rows) ? rows : [];

    const tasks = rawList.map((r) => {
      let dueDateStr = null;
      if (r.due_date) {
        dueDateStr = r.due_date.toISOString().slice(0, 10);
      }
      const statusCode = STATUS_CODES[r.current_status_id] || 'pending';
      const priorityCode = PRIORITY_CODES[r.priority_id] || 'medium';

      return {
        id: r.id,
        title: r.title,
        description: r.description ?? '',
        dueDate: dueDateStr,
        priority: priorityCode,
        status: statusCode,
        assignee: r.assignee_name || 'Sin asignar',
        evidenceCount: r.evidence_count ?? 0,
        commentsCount: r.comments_count ?? 0,
      };
    });

    return res.json({ tasks });
  } catch (err) {
    console.error('Error listando mis tareas:', err);
    return res.status(500).json({ message: 'Error al listar mis tareas' });
  }
});

// Alias opcional: GET /api/tasks/my  -> mismo que /api/my-tasks
api.get('/tasks/my', requireAnyAuthenticated, async (req, res) => {
  req.url = '/my-tasks'; // redirige internamente al handler de arriba
  return api.handle(req, res);
});

// ========================
//  Evidencias de tareas (LONGBLOB)
// ========================

// GET /api/tasks/:id/attachments
api.get('/tasks/:id/attachments', requireAnyAuthenticated, async (req, res) => {
  const taskId = Number(req.params.id);
  if (!taskId) {
    return res.status(400).json({ message: 'taskId inválido' });
  }

  try {
    const [rows] = await pool.query(
      `
        SELECT
          id,
          task_id,
          uploaded_by,
          file_name,
          mime_type,
          size_bytes,
          sha256,
          created_at
        FROM task_attachments
        WHERE task_id = ?
        ORDER BY created_at DESC
      `,
      [taskId],
    );

    const list = Array.isArray(rows) ? rows : [];
    return res.json({ attachments: list });
  } catch (e) {
    console.error('Error listando evidencias:', e);
    return res.status(500).json({ message: 'Error al listar evidencias' });
  }
});

// POST /api/tasks/:id/attachments
// Body JSON: { fileName, mimeType, base64Data }
api.post('/tasks/:id/attachments', requireAnyAuthenticated, async (req, res) => {
  const taskId = Number(req.params.id);
  const userId = req.authUserId;

  if (!taskId) {
    return res.status(400).json({ message: 'taskId inválido' });
  }

  const { fileName, mimeType, base64Data } = req.body ?? {};

  if (!fileName || !mimeType || !base64Data) {
    return res.status(400).json({
      message: 'fileName, mimeType y base64Data son requeridos',
    });
  }

  try {
    // Convertir base64 -> Buffer
    const buffer = Buffer.from(
      base64Data.replace(/^data:[^;]+;base64,/, ''), // por si viene con prefijo data:
      'base64',
    );

    const sizeBytes = buffer.length;
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    const [result] = await pool.query(
      `
        INSERT INTO task_attachments
          (task_id, uploaded_by, file_data, file_name, mime_type, size_bytes, sha256)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      [taskId, userId, buffer, fileName, mimeType, sizeBytes, sha256],
    );

    return res.status(201).json({
      id: result.insertId,
      taskId,
      uploadedBy: userId,
      fileName,
      mimeType,
      sizeBytes,
      sha256,
      createdAt: new Date(),
    });
  } catch (e) {
    console.error('Error creando evidencia:', e);
    return res.status(500).json({ message: 'Error al crear evidencia' });
  }
});

// GET /api/attachments/:id/download
api.get('/attachments/:id/download', requireAnyAuthenticated, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) {
    return res.status(400).json({ message: 'id inválido' });
  }

  try {
    const [rows] = await pool.query(
      `
        SELECT file_data, file_name, mime_type
        FROM task_attachments
        WHERE id = ?
        LIMIT 1
      `,
      [id],
    );

    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      return res.status(404).json({ message: 'Archivo no encontrado' });
    }

    const att = list[0];

    res.setHeader('Content-Type', att.mime_type);
    res.setHeader('Content-Disposition', `inline; filename="${att.file_name}"`);
    return res.send(att.file_data);
  } catch (e) {
    console.error('Error descargando evidencia:', e);
    return res.status(500).json({ message: 'Error al descargar evidencia' });
  }
});

// Descargar / visualizar UNA evidencia (SIN middleware de auth)
api.get('/tasks/:taskId/attachments/:attId/file', async (req, res) => {
  try {
    const taskId = Number(req.params.taskId);
    const attId = Number(req.params.attId);

    if (!taskId || !attId) {
      return res.status(400).json({ message: 'ids inválidos' });
    }

    const [rows] = await pool.query(
      `
        SELECT
          file_name   AS fileName,
          mime_type   AS mimeType,
          size_bytes  AS sizeBytes,
          file_data   AS fileData
        FROM task_attachments
        WHERE id = ? AND task_id = ?
        LIMIT 1
      `,
      [attId, taskId],
    );

    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      return res.status(404).json({ message: 'Archivo no encontrado' });
    }

    const att = list[0];

    res.setHeader('Content-Type', att.mimeType || 'application/octet-stream');
    res.setHeader(
      'Content-Disposition',
      `inline; filename="${String(att.fileName || 'archivo').replace(/"/g, '\\"')}"`,
    );

    // Enviar binario
    return res.end(att.fileData);
  } catch (err) {
    console.error('Error sirviendo evidencia:', err);
    return res.status(500).json({ message: 'Error al descargar evidencia' });
  }
});

// DELETE /api/tasks/:taskId/attachments/:attId
// - root/admin: pueden borrar cualquier evidencia por id
// - usuario: solo puede borrar evidencias que él subió (uploaded_by = userId)
api.delete(
  '/tasks/:taskId/attachments/:attId',
  requireAnyAuthenticated,
  async (req, res) => {
    try {
      const taskId = Number(req.params.taskId);
      const attId = Number(req.params.attId);
      const userId = req.authUserId;
      const role = req.authRole; // 'root' | 'admin' | 'usuario'

      if (!taskId || !attId) {
        return res.status(400).json({ message: 'ids inválidos' });
      }

      console.log('DELETE attachment', { taskId, attId, userId, role });

      // 1) Verificar que el adjunto exista
      const [rows] = await pool.query(
        `
        SELECT uploaded_by
        FROM task_attachments
        WHERE id = ? AND task_id = ?
        LIMIT 1
      `,
        [attId, taskId],
      );

      const list = Array.isArray(rows) ? rows : [];
      if (!list.length) {
        // No existe el archivo
        return res.status(404).json({ message: 'Archivo no encontrado' });
      }

      const ownerId = list[0].uploaded_by;

      // 2) Solo root/admin o el dueño pueden borrar
      if (role === 'usuario' && ownerId !== userId) {
        // El archivo existe, pero no le pertenece a este usuario
        return res.status(403).json({
          message: 'No puedes eliminar esta evidencia (fue subida por otro usuario).',
        });
      }

      // 3) Borrar el adjunto
      const [result] = await pool.query(
        `
        DELETE FROM task_attachments
        WHERE id = ? AND task_id = ?
      `,
        [attId, taskId],
      );

      console.log('DELETE attachment result:', result);

      return res.status(204).end();
    } catch (err) {
      console.error('Error borrando evidencia:', err);
      return res.status(500).json({ message: 'Error al eliminar evidencia' });
    }
  },
);

/* ========================
 *  Dashboard (resumen tareas)
 * ====================== */

// GET /api/dashboard/summary?year=2025&month=11
// Si no mandas year/month, usa el mes actual.
api.get('/dashboard/summary', requireAdminOrRoot, async (req, res) => {
  try {
    const now = new Date();
    const year = Number(req.query.year) || now.getFullYear();
    const month = Number(req.query.month) || now.getMonth() + 1; // 1..12

    const mm = String(month).padStart(2, '0');

    // Rango del mes seleccionado [start, nextMonth)
    const startDateStr = `${year}-${mm}-01`;
    const nextMonth = month === 12 ? 1 : month + 1;
    const nextYear = month === 12 ? year + 1 : year;
    const nextMm = String(nextMonth).padStart(2, '0');
    const endDateStr = `${nextYear}-${nextMm}-01`;

    // 1) Conteo por estado (para tasks con due_date en ese mes)
    const [statusRows] = await pool.query(
      `
        SELECT t.current_status_id AS status_id, COUNT(*) AS count
        FROM tasks t
        WHERE t.archived = 0
          AND t.due_date IS NOT NULL
          AND t.due_date >= ?
          AND t.due_date < ?
        GROUP BY t.current_status_id
      `,
      [startDateStr, endDateStr],
    );

    let total = 0;
    let pending = 0;
    let inProgress = 0;
    let done = 0;

    const statusList = Array.isArray(statusRows) ? statusRows : [];
    for (const r of statusList) {
      const c = Number(r.count) || 0;
      total += c;

      const code = STATUS_CODES[r.status_id] || 'pending';
      if (code === 'pending') pending = c;
      else if (code === 'in_progress') inProgress = c;
      else if (code === 'done') done = c;
    }

    // 2) Conteo por prioridad (mismo rango)
    const [priorityRows] = await pool.query(
      `
        SELECT t.priority_id AS priority_id, COUNT(*) AS count
        FROM tasks t
        WHERE t.archived = 0
          AND t.due_date IS NOT NULL
          AND t.due_date >= ?
          AND t.due_date < ?
        GROUP BY t.priority_id
      `,
      [startDateStr, endDateStr],
    );

    let low = 0;
    let medium = 0;
    let high = 0;

    const prioList = Array.isArray(priorityRows) ? priorityRows : [];
    for (const r of prioList) {
      const c = Number(r.count) || 0;
      const code = PRIORITY_CODES[r.priority_id] || 'medium';
      if (code === 'low') low = c;
      else if (code === 'medium') medium = c;
      else if (code === 'high') high = c;
    }

    // 3) Tareas que vencen en las próximas 48 horas (pendientes / en proceso)
    const [dueSoonRows] = await pool.query(
      `
        SELECT COUNT(*) AS c
        FROM tasks t
        WHERE t.archived = 0
          AND t.due_date IS NOT NULL
          AND t.due_date >= CURDATE()
          AND t.due_date <= DATE_ADD(NOW(), INTERVAL 2 DAY)
          AND t.current_status_id IN (?, ?)
      `,
      [STATUS_IDS.pending, STATUS_IDS.in_progress],
    );
    const dueSoon48h =
      Array.isArray(dueSoonRows) && dueSoonRows.length ? Number(dueSoonRows[0].c) || 0 : 0;

    return res.json({
      period: { year, month },
      totals: {
        total,
        pending,
        inProgress,
        done,
      },
      priorities: {
        low,
        medium,
        high,
      },
      dueSoon48h,
    });
  } catch (err) {
    console.error('Error en /dashboard/summary:', err);
    return res
      .status(500)
      .json({ message: 'Error al obtener resumen de dashboard' });
  }
});

/* ========================
 *  Comentarios de tareas
 * ====================== */

// GET /api/tasks/:id/comments
api.get('/tasks/:id/comments', requireAnyAuthenticated, async (req, res) => {
  try {
    const taskId = Number(req.params.id);
    const userId = req.authUserId;
    if (!taskId) {
      return res.status(400).json({ message: 'taskId inválido' });
    }

    const [rows] = await pool.query(
      `
        SELECT
          c.id,
          c.task_id     AS taskId,
          c.user_id     AS userId,
          c.body        AS body,
          c.created_at  AS createdAt,
          u.name        AS author,
          r.name        AS role,
          CASE WHEN r.name IN ('admin','root') THEN 1 ELSE 0 END AS isAdmin,
          CASE WHEN c.user_id = ? THEN 1 ELSE 0 END AS isMine
        FROM task_comments c
        JOIN users u ON u.id = c.user_id
        JOIN roles r ON r.id = u.role_id
        WHERE c.task_id = ?
        ORDER BY c.created_at ASC
      `,
      [userId, taskId],
    );

    const list = Array.isArray(rows) ? rows : [];
    return res.json({ comments: list });
  } catch (err) {
    console.error('Error listando comentarios de tarea:', err);
    return res.status(500).json({ message: 'Error al listar comentarios' });
  }
});

// POST /api/tasks/:id/comments
// Body JSON: { "body": "texto del comentario" }
api.post('/tasks/:id/comments', requireAnyAuthenticated, async (req, res) => {
  try {
    const taskId = Number(req.params.id);
    const userId = req.authUserId;
    const { body } = req.body ?? {};

    if (!taskId) {
      return res.status(400).json({ message: 'taskId inválido' });
    }
    const text = (body ?? '').toString().trim();
    if (!text) {
      return res.status(400).json({ message: 'body es requerido' });
    }

    // Verificar que la tarea exista y no esté archivada
    const [taskRows] = await pool.query(
      'SELECT id FROM tasks WHERE id = ? AND archived = 0 LIMIT 1',
      [taskId],
    );
    if (!Array.isArray(taskRows) || taskRows.length === 0) {
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }

    const [insertResult] = await pool.query(
      `
        INSERT INTO task_comments (task_id, user_id, body)
        VALUES (?, ?, ?)
      `,
      [taskId, userId, text],
    );
    const commentId = insertResult.insertId;

    // Devolvemos el comentario completo
    const [rows] = await pool.query(
      `
        SELECT
          c.id,
          c.task_id     AS taskId,
          c.user_id     AS userId,
          c.body        AS body,
          c.created_at  AS createdAt,
          u.name        AS author,
          r.name        AS role,
          CASE WHEN r.name IN ('admin','root') THEN 1 ELSE 0 END AS isAdmin,
          CASE WHEN c.user_id = ? THEN 1 ELSE 0 END AS isMine
        FROM task_comments c
        JOIN users u ON u.id = c.user_id
        JOIN roles r ON r.id = u.role_id
        WHERE c.id = ?
        LIMIT 1
      `,
      [userId, commentId],
    );

    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      return res
        .status(500)
        .json({ message: 'No se pudo recuperar el comentario creado' });
    }

    return res.status(201).json(list[0]);
  } catch (err) {
    console.error('Error creando comentario de tarea:', err);
    return res.status(500).json({ message: 'Error al crear comentario' });
  }
});

// DELETE /api/task-comments/:id
api.delete('/task-comments/:id', requireAnyAuthenticated, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const userId = req.authUserId;
    const role = req.authRole; // 'root' | 'admin' | 'usuario'

    if (!id) {
      return res.status(400).json({ message: 'id inválido' });
    }

    const [rows] = await pool.query('SELECT user_id FROM task_comments WHERE id = ? LIMIT 1', [
      id,
    ]);
    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      return res.status(404).json({ message: 'Comentario no encontrado' });
    }

    const ownerId = list[0].user_id;

    // Solo root/admin o el dueño pueden borrar
    if (role === 'usuario' && ownerId !== userId) {
      return res.status(403).json({ message: 'No puedes eliminar este comentario' });
    }

    await pool.query('DELETE FROM task_comments WHERE id = ?', [id]);
    return res.status(204).end();
  } catch (err) {
    console.error('Error borrando comentario de tarea:', err);
    return res.status(500).json({ message: 'Error al eliminar comentario' });
  }
});

/* ========================
 *  Foros (admin / root + chat)
 * ====================== */

// Crear foro
// POST /api/forums
api.post('/forums', requireAdminOrRoot, async (req, res) => {
  const { title, description = null, isPublic = true, memberEmails = [] } = req.body ?? {};

  if (!title) {
    return res.status(400).json({ message: 'title es requerido' });
  }

  if (typeof isPublic !== 'boolean') {
    return res.status(400).json({ message: 'isPublic debe ser boolean' });
  }

  const headerUserId = Number(req.header('x-user-id'));
  const createdBy = Number.isFinite(headerUserId) ? headerUserId : null;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1) Insertar el foro
    const [forumResult] = await conn.query(
      `
        INSERT INTO forums (title, description, is_public, created_by)
        VALUES (?, ?, ?, ?)
      `,
      [title, description, isPublic ? 1 : 0, createdBy],
    );

    const forumId = forumResult.insertId;

    // 2) Si NO es público, insertar miembros
    let members = [];
    if (!isPublic && Array.isArray(memberEmails) && memberEmails.length > 0) {
      const [userRows] = await conn.query(
        `
          SELECT id, email
          FROM users
          WHERE email IN (${memberEmails.map(() => '?').join(',')})
        `,
        memberEmails,
      );

      const userList = Array.isArray(userRows) ? userRows : [];

      if (userList.length > 0) {
        const values = userList.map((u) => [forumId, u.id]);
        await conn.query(
          `
            INSERT INTO forum_members (forum_id, user_id)
            VALUES ?
          `,
          [values],
        );

        members = userList.map((u) => u.email);
      }
    }

    await conn.commit();

    return res.status(201).json({
      id: forumId,
      title,
      description,
      isPublic,
      members,
      messagesCount: 0,
    });
  } catch (err) {
    console.error('Error creando foro:', err);
    await conn.rollback();
    return res.status(500).json({ message: 'Error al crear foro' });
  } finally {
    conn.release();
  }
});

// Listar foros (admin/root)
// GET /api/forums
api.get('/forums', requireAdminOrRoot, async (_req, res) => {
  try {
    const sql = `
      SELECT
        f.id,
        f.title,
        f.description,
        f.is_public AS isPublic,
        COUNT(fp.id) AS messagesCount
      FROM forums f
      LEFT JOIN forum_posts fp ON fp.forum_id = f.id
      GROUP BY f.id, f.title, f.description, f.is_public
      ORDER BY f.created_at DESC
    `;

    const [rows] = await pool.query(sql);
    const list = Array.isArray(rows) ? rows : [];

    return res.json({ forums: list });
  } catch (err) {
    console.error('Error listando foros:', err);
    return res.status(500).json({ message: 'Error al listar foros' });
  }
});

// Listar foros del usuario actual (públicos + privados donde es miembro)
// GET /api/forums/my
api.get('/forums/my', requireAnyAuthenticated, async (req, res) => {
  try {
    const userId = req.authUserId;

    const sql = `
      SELECT
        f.id,
        f.title,
        f.description,
        f.is_public AS isPublic,
        COUNT(fp.id) AS messagesCount
      FROM forums f
      LEFT JOIN forum_posts fp
        ON fp.forum_id = f.id
      LEFT JOIN forum_members fm
        ON fm.forum_id = f.id
      WHERE
        f.is_public = 1           -- foros públicos
        OR fm.user_id = ?         -- o foros privados donde soy miembro
      GROUP BY
        f.id, f.title, f.description, f.is_public
      ORDER BY f.created_at DESC
    `;

    const [rows] = await pool.query(sql, [userId]);
    const list = Array.isArray(rows) ? rows : [];

    return res.json({ forums: list });
  } catch (err) {
    console.error('Error listando foros del usuario:', err);
    return res.status(500).json({ message: 'Error al listar foros del usuario' });
  }
});

// Listar mensajes de un foro
// GET /api/forums/:id/posts
api.get('/forums/:id/posts', requireAnyAuthenticated, async (req, res) => {
  try {
    const forumId = Number(req.params.id);
    if (!forumId) {
      return res.status(400).json({ message: 'forumId inválido' });
    }

    const sql = `
      SELECT
        fp.id,
        u.id       AS authorId,
        u.name     AS author,
        r.name     AS role,
        fp.body    AS text,
        fp.created_at AS createdAt,
        CASE WHEN r.name IN ('admin','root') THEN 1 ELSE 0 END AS isAdmin,
        fa.id         AS attId,
        fa.file_name  AS attFileName,
        fa.mime_type  AS attMimeType,
        fa.size_bytes AS attSizeBytes
      FROM forum_posts fp
      JOIN users u   ON u.id = fp.user_id
      JOIN roles r   ON r.id = u.role_id
      LEFT JOIN forum_attachments fa
        ON fa.forum_post_id = fp.id
      WHERE fp.forum_id = ?
      ORDER BY fp.created_at ASC, fa.created_at ASC
    `;

    const [rows] = await pool.query(sql, [forumId]);
    const list = Array.isArray(rows) ? rows : [];

    // Agrupar adjuntos por mensaje
    const map = new Map(); // postId -> post
    for (const r of list) {
      let post = map.get(r.id);
      if (!post) {
        post = {
          id: r.id,
          authorId: r.authorId,
          author: r.author,
          role: r.role,
          text: r.text || '',
          createdAt: r.createdAt,
          isAdmin: !!r.isAdmin,
          attachments: [],
        };
        map.set(r.id, post);
      }

      if (r.attId) {
        post.attachments.push({
          id: r.attId,
          fileName: r.attFileName,
          mimeType: r.attMimeType,
          sizeBytes: r.attSizeBytes,
          downloadUrl: `/api/forums/attachments/${r.attId}/file`,
        });
      }
    }

    return res.json({ posts: Array.from(map.values()) });
  } catch (err) {
    console.error('Error listando posts del foro:', err);
    return res.status(500).json({ message: 'Error al listar mensajes' });
  }
});

// Crear mensaje con archivo adjunto
// POST /api/forums/:id/posts-with-file
// Body JSON: { text?, fileName, mimeType, base64Data }
api.post('/forums/:id/posts-with-file', requireAnyAuthenticated, async (req, res) => {
  const forumId = Number(req.params.id);
  const userId = req.authUserId;
  const { text = '', fileName, mimeType, base64Data } = req.body ?? {};

  if (!forumId) {
    return res.status(400).json({ message: 'forumId inválido' });
  }
  if (!fileName || !mimeType || !base64Data) {
    return res.status(400).json({
      message: 'fileName, mimeType y base64Data son requeridos',
    });
  }

  try {
    // Verificar que el foro exista
    const [forumRows] = await pool.query('SELECT id FROM forums WHERE id = ? LIMIT 1', [forumId]);
    if (!Array.isArray(forumRows) || forumRows.length === 0) {
      return res.status(404).json({ message: 'Foro no encontrado' });
    }

    const body = text.toString().trim();

    // Decodificar base64
    const buffer = Buffer.from(
      base64Data.replace(/^data:[^;]+;base64,/, ''),
      'base64',
    );
    const sizeBytes = buffer.length;
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // 1) Insertar post
      const [postResult] = await conn.query(
        `
          INSERT INTO forum_posts (forum_id, user_id, body)
          VALUES (?, ?, ?)
        `,
        [forumId, userId, body],
      );
      const postId = postResult.insertId;

      // 2) Insertar attachment
      const [attResult] = await conn.query(
        `
          INSERT INTO forum_attachments
            (forum_post_id, uploaded_by, file_data, file_name, mime_type, size_bytes, sha256)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `,
        [postId, userId, buffer, fileName, mimeType, sizeBytes, sha256],
      );
      const attId = attResult.insertId;

      // 3) Info del autor
      const [uRows] = await conn.query(
        `
          SELECT u.name, r.name AS role
          FROM users u
          JOIN roles r ON r.id = u.role_id
          WHERE u.id = ?
          LIMIT 1
        `,
        [userId],
      );
      const uList = Array.isArray(uRows) ? uRows : [];
      const authorName = uList.length ? uList[0].name : 'Usuario';
      const role = uList.length ? uList[0].role : 'usuario';

      await conn.commit();

      const isAdmin = ['admin', 'root'].includes(String(role).toLowerCase());

      return res.status(201).json({
        id: postId,
        authorId: userId,
        author: authorName,
        role,
        text: body,
        createdAt: new Date().toISOString(),
        isAdmin,
        attachments: [
          {
            id: attId,
            fileName,
            mimeType,
            sizeBytes,
            downloadUrl: `/api/forums/attachments/${attId}/file`,
          },
        ],
      });
    } catch (err) {
      await conn.rollback();
      console.error('Error creando mensaje con archivo:', err);
      return res.status(500).json({ message: 'Error al crear mensaje con archivo' });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error('Error en /forums/:id/posts-with-file:', err);
    return res.status(500).json({ message: 'Error interno' });
  }
});

// GET /api/forums/attachments/:id/file
api.get('/forums/attachments/:id/file', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) {
      return res.status(400).json({ message: 'id inválido' });
    }

    const [rows] = await pool.query(
      `
        SELECT
          file_name   AS fileName,
          mime_type   AS mimeType,
          size_bytes  AS sizeBytes,
          file_data   AS fileData
        FROM forum_attachments
        WHERE id = ?
        LIMIT 1
      `,
      [id],
    );

    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      return res.status(404).json({ message: 'Archivo no encontrado' });
    }

    const att = list[0];

    res.setHeader('Content-Type', att.mimeType || 'application/octet-stream');
    res.setHeader(
      'Content-Disposition',
      `inline; filename="${String(att.fileName || 'archivo').replace(/"/g, '\\"')}"`,
    );
    return res.end(att.fileData);
  } catch (err) {
    console.error('Error sirviendo adjunto de foro:', err);
    return res.status(500).json({ message: 'Error al descargar adjunto' });
  }
});

// Crear mensaje en un foro (texto)
// POST /api/forums/:id/posts
// Body JSON: { "text": "Mensaje..." }
api.post('/forums/:id/posts', requireAnyAuthenticated, async (req, res) => {
  try {
    const forumId = Number(req.params.id);
    const { text } = req.body ?? {};
    const userId = req.authUserId;

    if (!forumId) {
      return res.status(400).json({ message: 'forumId inválido' });
    }
    if (!text || !text.toString().trim()) {
      return res.status(400).json({ message: 'text es requerido' });
    }

    // Verificamos que el foro exista
    const [forumRows] = await pool.query('SELECT id FROM forums WHERE id = ? LIMIT 1', [forumId]);
    if (!Array.isArray(forumRows) || forumRows.length === 0) {
      return res.status(404).json({ message: 'Foro no encontrado' });
    }

    const body = text.toString().trim();

    // Insertamos el mensaje
    const [insertResult] = await pool.query(
      `
        INSERT INTO forum_posts (forum_id, user_id, body)
        VALUES (?, ?, ?)
      `,
      [forumId, userId, body],
    );

    const postId = insertResult.insertId;

    // Recuperamos el mensaje
    const [rows] = await pool.query(
      `
        SELECT
          fp.id,
          u.id AS authorId,
          u.name AS author,
          r.name AS role,
          fp.body AS text,
          fp.created_at AS createdAt,
          CASE WHEN r.name IN ('admin', 'root') THEN 1 ELSE 0 END AS isAdmin
        FROM forum_posts fp
        JOIN users u ON u.id = fp.user_id
        JOIN roles r ON r.id = u.role_id
        WHERE fp.id = ?
        LIMIT 1
      `,
      [postId],
    );

    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      return res
        .status(500)
        .json({ message: 'No se pudo recuperar el mensaje creado' });
    }

    return res.status(201).json(list[0]);
  } catch (err) {
    console.error('Error creando mensaje del foro:', err);
    return res.status(500).json({ message: 'Error al crear mensaje' });
  }
});

// DELETE /api/forums/:id  -> Solo root puede borrar el foro y sus mensajes
api.delete('/forums/:id', async (req, res) => {
  try {
    const role = (req.headers['x-role'] || '').toString().toLowerCase();
    const forumId = req.params.id;

    // Solo root
    if (role !== 'root') {
      return res
        .status(403)
        .json({ message: 'Solo el usuario root puede eliminar foros.' });
    }

    const [result] = await pool.execute('DELETE FROM forums WHERE id = ? LIMIT 1', [forumId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Foro no encontrado' });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error('Error borrando foro', err);
    return res.status(500).json({ message: 'Error interno al eliminar foro' });
  }
});

/* ========================
 *  Montaje y 404 JSON
 * ====================== */

app.use('/api', api);
app.use((_req, res) => res.status(404).json({ message: 'Not found' }));

const port = Number(process.env.PORT ?? 3000);
const host = process.env.BIND || '0.0.0.0';
app.listen(port, host, () => {
  console.log(`API escuchando en ${host}:${port}`);
});
