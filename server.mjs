// src/server.mjs
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import { pool } from './db.mjs';

const app = express();

/* ========================
 *  Middlewares base
 * ====================== */
const allowOrigin = process.env.CORS_ALLOW_ORIGIN || '*';
app.use(cors({
  origin: allowOrigin,
  credentials: false,
  allowedHeaders: ['Content-Type', 'x-role', 'x-user-id'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));
app.use(express.json({ limit: '1mb' }));

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

// En DEV usamos headers para simular autorización.
// Cuando metas JWT real, reemplaza estos middlewares.
function requireRoot(req, res, next) {
  const role = String(req.header('x-role') || '').toLowerCase();
  if (role !== 'root') {
    return res.status(403).json({ message: 'Solo root puede realizar esta acción' });
  }
  next();
}

// Para rutas donde root o admin pueden entrar (por ejemplo foros)
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
      name, email, password,
      role = 'usuario',          // 'root' | 'admin' | 'usuario'
      phone = null, about = null,
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
      [roleId, name, email, hash, phone, about, avatar_url, is_active ? 1 : 0]
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
        is_active: !!is_active
      }
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
 *  Constantes de tareas
 *  (AJUSTA LOS IDs A TU BD)
 * ====================== */

// OJO: estos IDs deben coincidir con tu tabla "priorities"
const PRIORITY_MAP = {
  low: 1,    // prioridad baja
  medium: 2, // prioridad media
  high: 3,   // prioridad alta
};

const PRIORITY_ID_TO_CODE = {
  1: 'low',
  2: 'medium',
  3: 'high',
};

// OJO: estos IDs deben coincidir con tu tabla "task_status"
const STATUS_MAP = {
  pending: 1,      // pendiente
  in_progress: 2,  // en proceso
  done: 3,         // completada
};

const STATUS_ID_TO_CODE = {
  1: 'pending',
  2: 'in_progress',
  3: 'done',
};

/* ========================
 *  Tareas (admin / root + usuarios)
 * ====================== */

// Listar todas las tareas (root / admin)
// GET /api/tasks
// Devuelve: { tasks: [ { id, title, description, dueDate, priority, status, assignee } ] }
api.get('/tasks', requireAdminOrRoot, async (_req, res) => {
  try {
    const sql = `
      SELECT
        t.id,
        t.title,
        t.description,
        t.due_date       AS dueDate,
        t.priority_id,
        t.current_status_id,
        u.name           AS assigneeName
      FROM tasks t
      LEFT JOIN task_assignments ta
        ON ta.task_id = t.id
       AND ta.is_active = 1
      LEFT JOIN users u
        ON u.id = ta.user_id
      WHERE t.archived = 0
      ORDER BY
        t.due_date IS NULL ASC,
        t.due_date ASC,
        t.id DESC
    `;

    const [rows] = await pool.query(sql);
    const rawList = Array.isArray(rows) ? rows : [];

    const tasks = rawList.map((r) => ({
      id: r.id,
      title: r.title,
      description: r.description ?? '',
      dueDate: r.dueDate, // 'YYYY-MM-DD' o null
      priority: PRIORITY_ID_TO_CODE[r.priority_id] ?? 'medium',
      status: STATUS_ID_TO_CODE[r.current_status_id] ?? 'pending',
      assignee: r.assigneeName || 'Sin asignar',
    }));

    return res.json({ tasks });
  } catch (err) {
    console.error('Error listando tareas:', err);
    return res.status(500).json({ message: 'Error al listar tareas' });
  }
});

// Listar mis tareas (cualquier usuario autenticado)
// GET /api/my-tasks
api.get('/my-tasks', requireAnyAuthenticated, async (req, res) => {
  try {
    const userId = req.authUserId;

    const sql = `
      SELECT
        t.id,
        t.title,
        t.description,
        t.due_date       AS dueDate,
        t.priority_id,
        t.current_status_id,
        u.name           AS assigneeName
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
        t.due_date IS NULL ASC,
        t.due_date ASC,
        t.id DESC
    `;

    const [rows] = await pool.query(sql, [userId]);
    const rawList = Array.isArray(rows) ? rows : [];

    const tasks = rawList.map((r) => ({
      id: r.id,
      title: r.title,
      description: r.description ?? '',
      dueDate: r.dueDate,
      priority: PRIORITY_ID_TO_CODE[r.priority_id] ?? 'medium',
      status: STATUS_ID_TO_CODE[r.current_status_id] ?? 'pending',
      assignee: r.assigneeName || 'Sin asignar',
    }));

    return res.json({ tasks });
  } catch (err) {
    console.error('Error listando mis tareas:', err);
    return res.status(500).json({ message: 'Error al listar mis tareas' });
  }
});

// Crear tarea (root / admin)
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
      description = null,
      priority = 'medium',
      dueDate = null,
      assigneeId = null,
    } = req.body ?? {};

    if (!title || !String(title).trim()) {
      return res.status(400).json({ message: 'title es requerido' });
    }

    const priorityCode = String(priority).toLowerCase();
    const priorityId = PRIORITY_MAP[priorityCode];
    if (!priorityId) {
      return res.status(400).json({ message: 'priority inválida (usa low|medium|high)' });
    }

    const pendingStatusId = STATUS_MAP.pending;
    const headerUserId = Number(req.header('x-user-id'));
    const createdBy = Number.isFinite(headerUserId) ? headerUserId : null;

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // 1) Insertar la tarea
      const [taskResult] = await conn.query(
        `
        INSERT INTO tasks (title, description, priority_id, due_date, created_by, current_status_id)
        VALUES (?, ?, ?, ?, ?, ?)
        `,
        [title, description, priorityId, dueDate, createdBy, pendingStatusId]
      );

      const taskId = taskResult.insertId;
      let assigneeName = null;

      // 2) Asignación (opcional)
      if (assigneeId) {
        await conn.query(
          `
          INSERT INTO task_assignments (task_id, user_id)
          VALUES (?, ?)
          `,
          [taskId, assigneeId]
        );

        const [userRows] = await conn.query(
          'SELECT name FROM users WHERE id = ? LIMIT 1',
          [assigneeId]
        );
        const userList = Array.isArray(userRows) ? userRows : [];
        if (userList.length) {
          assigneeName = userList[0].name;
        }
      }

      // 3) Historial de estado
      await conn.query(
        `
        INSERT INTO task_status_history (task_id, user_id, from_status_id, to_status_id)
        VALUES (?, ?, NULL, ?)
        `,
        [taskId, createdBy, pendingStatusId]
      );

      await conn.commit();

      return res.status(201).json({
        id: taskId,
        title,
        description: description ?? '',
        dueDate,
        priority: priorityCode,
        status: 'pending',
        assignee: assigneeName || 'Sin asignar',
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

// Cambiar estado de una tarea (cualquier usuario autenticado)
// PUT /api/tasks/:id/status
// Body JSON: { "status": "pending" | "in_progress" | "done" }
api.put('/tasks/:id/status', requireAnyAuthenticated, async (req, res) => {
  try {
    const taskId = Number(req.params.id);
    const { status } = req.body ?? {};
    const userId = req.authUserId;

    if (!taskId) {
      return res.status(400).json({ message: 'id inválido' });
    }

    const statusCode = String(status || '').toLowerCase();
    const newStatusId = STATUS_MAP[statusCode];
    if (!newStatusId) {
      return res.status(400).json({ message: 'status inválido (pending|in_progress|done)' });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [rows] = await conn.query(
        'SELECT current_status_id FROM tasks WHERE id = ? FOR UPDATE',
        [taskId]
      );
      const list = Array.isArray(rows) ? rows : [];
      if (!list.length) {
        await conn.rollback();
        return res.status(404).json({ message: 'Tarea no encontrada' });
      }

      const currentStatusId = list[0].current_status_id;
      if (currentStatusId === newStatusId) {
        await conn.rollback();
        return res.json({ ok: true, skipped: true });
      }

      const completedAt = statusCode === 'done' ? new Date() : null;

      await conn.query(
        `
        UPDATE tasks
        SET current_status_id = ?, completed_at = ?
        WHERE id = ?
        `,
        [newStatusId, completedAt, taskId]
      );

      await conn.query(
        `
        INSERT INTO task_status_history (task_id, user_id, from_status_id, to_status_id)
        VALUES (?, ?, ?, ?)
        `,
        [taskId, userId, currentStatusId, newStatusId]
      );

      await conn.commit();
      return res.json({ ok: true });
    } catch (err) {
      await conn.rollback();
      console.error('Error actualizando estado de tarea:', err);
      return res.status(500).json({ message: 'Error al actualizar estado de tarea' });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error('Error en PUT /tasks/:id/status:', err);
    return res.status(500).json({ message: 'Error interno' });
  }
});

/* ========================
 *  Helpers para tareas
 * ====================== */

// OJO: aquí asumo que en tu tabla priorities los IDs son:
// 1 = low, 2 = medium, 3 = high
// y en task_status:
// 1 = pending, 2 = in_progress, 3 = done
// Ajusta estos valores si en tu BD están distintos.
function priorityCodeToId(code) {
  switch (String(code || '').toLowerCase()) {
    case 'low':
      return 1;
    case 'high':
      return 3;
    case 'medium':
    default:
      return 2;
  }
}

function statusCodeToId(code) {
  switch (String(code || '').toLowerCase()) {
    case 'pending':
      return 1;
    case 'in_progress':
      return 2;
    case 'done':
      return 3;
    default:
      return 1;
  }
}

/* ========================
 *  Tareas (solo admin / root)
 * ====================== */

// GET /api/tasks  -> lista TODAS las tareas (admin/root)
api.get('/tasks', requireAdminOrRoot, async (_req, res) => {
  try {
    const sql = `
      SELECT
        t.id,
        t.title,
        t.description,
        t.due_date AS dueDate,
        CASE t.priority_id
          WHEN 1 THEN 'low'
          WHEN 2 THEN 'medium'
          WHEN 3 THEN 'high'
          ELSE 'medium'
        END AS priority,
        CASE t.current_status_id
          WHEN 1 THEN 'pending'
          WHEN 2 THEN 'in_progress'
          WHEN 3 THEN 'done'
          ELSE 'pending'
        END AS status,
        COALESCE(u.name, 'Sin asignar') AS assignee,
        (SELECT COUNT(*) FROM task_attachments att WHERE att.task_id = t.id) AS evidenceCount,
        (SELECT COUNT(*) FROM task_comments c WHERE c.task_id = t.id) AS commentsCount
      FROM tasks t
      LEFT JOIN task_assignments ta
        ON ta.task_id = t.id
       AND ta.is_active = 1
      LEFT JOIN users u
        ON u.id = ta.user_id
      WHERE t.archived = 0
      ORDER BY t.due_date IS NULL, t.due_date ASC, t.id DESC
    `;

    const [rows] = await pool.query(sql);
    const list = Array.isArray(rows) ? rows : [];
    return res.json({ tasks: list });
  } catch (err) {
    console.error('Error listando tareas:', err);
    return res.status(500).json({ message: 'Error al listar tareas' });
  }
});


// POST /api/tasks  -> crea tarea + asignación
// Body JSON esperado:
// {
//   "title": "Tarea X",
//   "description": "texto opcional",
//   "priority": "low|medium|high",
//   "dueDate": "2025-11-18",   // opcional
//   "assigneeId": 3            // id del usuario asignado (opcional)
// }
api.post('/tasks', requireAdminOrRoot, async (req, res) => {
  try {
    const {
      title,
      description = null,
      priority = 'medium',
      dueDate = null,
      assigneeId = null,
    } = req.body ?? {};

    if (!title) {
      return res.status(400).json({ message: 'title es requerido' });
    }

    const creatorIdHeader = Number(req.header('x-user-id'));
    const createdBy = Number.isFinite(creatorIdHeader) ? creatorIdHeader : null;

    const priorityId = priorityCodeToId(priority);
    const statusId = statusCodeToId('pending');

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // 1) Insertar la tarea
      const [taskResult] = await conn.query(
        `
        INSERT INTO tasks (title, description, priority_id, due_date, created_by, current_status_id)
        VALUES (?, ?, ?, ?, ?, ?)
        `,
        [title, description, priorityId, dueDate || null, createdBy, statusId]
      );

      const taskId = taskResult.insertId;

      // 2) Asignación (si viene assigneeId)
      if (assigneeId) {
        await conn.query(
          `
          INSERT INTO task_assignments (task_id, user_id)
          VALUES (?, ?)
          `,
          [taskId, assigneeId]
        );
      }

      // 3) Historial de estado
      await conn.query(
        `
        INSERT INTO task_status_history (task_id, user_id, from_status_id, to_status_id)
        VALUES (?, ?, ?, ?)
        `,
        [taskId, createdBy, null, statusId]
      );

      // 4) Recuperar la tarea recién creada con el mismo formato que GET /tasks
      const [rows] = await conn.query(
        `
        SELECT
          t.id,
          t.title,
          t.description,
          t.due_date AS dueDate,
          CASE t.priority_id
            WHEN 1 THEN 'low'
            WHEN 2 THEN 'medium'
            WHEN 3 THEN 'high'
            ELSE 'medium'
          END AS priority,
          CASE t.current_status_id
            WHEN 1 THEN 'pending'
            WHEN 2 THEN 'in_progress'
            WHEN 3 THEN 'done'
            ELSE 'pending'
          END AS status,
          COALESCE(u.name, 'Sin asignar') AS assignee,
          (SELECT COUNT(*) FROM task_attachments att WHERE att.task_id = t.id) AS evidenceCount,
          (SELECT COUNT(*) FROM task_comments c WHERE c.task_id = t.id) AS commentsCount
        FROM tasks t
        LEFT JOIN task_assignments ta
          ON ta.task_id = t.id
         AND ta.is_active = 1
        LEFT JOIN users u
          ON u.id = ta.user_id
        WHERE t.id = ?
        LIMIT 1
        `,
        [taskId]
      );

      await conn.commit();

      const list = Array.isArray(rows) ? rows : [];
      if (!list.length) {
        // fallback por si algo raro pasa
        return res.status(201).json({
          id: taskId,
          title,
          description,
          dueDate,
          priority,
          status: 'pending',
          assignee: 'Sin asignar',
          evidenceCount: 0,
          commentsCount: 0,
        });
      }

      return res.status(201).json(list[0]);
    } catch (err) {
      await conn.rollback();
      console.error('Error creando tarea:', err);
      return res.status(500).json({ message: 'Error al crear tarea' });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Error interno' });
  }
});

/* ========================
 *  Tareas (tasks)
 * ====================== */

// Mapas simples de código -> id (AJUSTA ESTOS IDs a los de tu tabla real)
const PRIORITY_IDS = {
  low: 1,
  medium: 2,
  high: 3,
};

const STATUS_IDS = {
  pending: 1,        // pendiente
  in_progress: 2,    // en_proceso
  done: 3,           // completada
  failed: 4,         // no_lograda (si luego lo usas en el front)
};

// Helper para leer una tarea y devolverla en formato amigable al front
async function fetchTaskById(taskId) {
  const sql = `
    SELECT
      t.id,
      t.title,
      t.description,
      t.due_date AS dueDate,
      CASE t.priority_id
        WHEN 1 THEN 'low'
        WHEN 2 THEN 'medium'
        WHEN 3 THEN 'high'
        ELSE 'medium'
      END AS priority,
      CASE t.current_status_id
        WHEN 1 THEN 'pending'
        WHEN 2 THEN 'in_progress'
        WHEN 3 THEN 'done'
        WHEN 4 THEN 'failed'
        ELSE 'pending'
      END AS status,
      COALESCE(u.name, 'Sin asignar') AS assignee,
      (SELECT COUNT(*) FROM task_attachments ta2 WHERE ta2.task_id = t.id) AS evidenceCount,
      (SELECT COUNT(*) FROM task_comments tc WHERE tc.task_id = t.id) AS commentsCount
    FROM tasks t
    LEFT JOIN task_assignments ta
      ON ta.task_id = t.id AND ta.is_active = 1
    LEFT JOIN users u
      ON u.id = ta.user_id
    WHERE t.id = ?
    LIMIT 1
  `;
  const [rows] = await pool.query(sql, [taskId]);
  const list = Array.isArray(rows) ? rows : [];
  return list.length ? list[0] : null;
}

// Listar tareas (root / admin)
api.get('/tasks', requireAdminOrRoot, async (_req, res) => {
  try {
    const sql = `
      SELECT
        t.id,
        t.title,
        t.description,
        t.due_date AS dueDate,
        CASE t.priority_id
          WHEN 1 THEN 'low'
          WHEN 2 THEN 'medium'
          WHEN 3 THEN 'high'
          ELSE 'medium'
        END AS priority,
        CASE t.current_status_id
          WHEN 1 THEN 'pending'
          WHEN 2 THEN 'in_progress'
          WHEN 3 THEN 'done'
          ELSE 'pending'
        END AS status,
        COALESCE(u.name, 'Sin asignar') AS assignee,
        (SELECT COUNT(*) FROM task_attachments ta2 WHERE ta2.task_id = t.id) AS evidenceCount,
        (SELECT COUNT(*) FROM task_comments tc WHERE tc.task_id = t.id) AS commentsCount
      FROM tasks t
      LEFT JOIN task_assignments ta
        ON ta.task_id = t.id AND ta.is_active = 1
      LEFT JOIN users u
        ON u.id = ta.user_id
      WHERE t.archived = 0
      ORDER BY t.created_at DESC
    `;
    const [rows] = await pool.query(sql);
    const list = Array.isArray(rows) ? rows : [];
    return res.json({ tasks: list });
  } catch (err) {
    console.error('Error listando tareas:', err);
    return res.status(500).json({ message: 'Error al listar tareas' });
  }
});

// Crear tarea (root / admin)
api.post('/tasks', requireAdminOrRoot, async (req, res) => {
  const {
    title,
    description = null,
    priority = 'medium', // 'low' | 'medium' | 'high'
    dueDate = null,      // 'YYYY-MM-DD'
    assigneeId = null,   // user_id de la BD
  } = req.body ?? {};

  if (!title) {
    return res.status(400).json({ message: 'title es requerido' });
  }

  const priorityId = PRIORITY_IDS[priority];
  if (!priorityId) {
    return res.status(400).json({ message: `priority inválido: ${priority}` });
  }

  const statusId = STATUS_IDS.pending;
  if (!statusId) {
    return res.status(500).json({ message: 'Status pending no configurado' });
  }

  const createdByHeader = Number(req.header('x-user-id'));
  const createdBy = Number.isFinite(createdByHeader) ? createdByHeader : null;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Insertar la tarea
    const [taskResult] = await conn.query(
      `
      INSERT INTO tasks (title, description, priority_id, due_date, created_by, current_status_id)
      VALUES (?, ?, ?, ?, ?, ?)
      `,
      [title, description, priorityId, dueDate, createdBy, statusId]
    );

    const taskId = taskResult.insertId;

    // Asignación (si viene assigneeId)
    if (assigneeId) {
      await conn.query(
        `
        INSERT INTO task_assignments (task_id, user_id)
        VALUES (?, ?)
        `,
        [taskId, assigneeId]
      );
    }

    // Historial de estado (entrada inicial)
    await conn.query(
      `
      INSERT INTO task_status_history (task_id, user_id, from_status_id, to_status_id)
      VALUES (?, ?, NULL, ?)
      `,
      [taskId, createdBy, statusId]
    );

    await conn.commit();

    // Leer la tarea en formato DTO para el frontend
    const row = await fetchTaskById(taskId);
    if (!row) {
      return res.status(500).json({ message: 'No se pudo recuperar la tarea creada' });
    }

    return res.status(201).json(row);
  } catch (err) {
    console.error('Error creando tarea:', err);
    await conn.rollback();
    return res.status(500).json({ message: 'Error al crear tarea' });
  } finally {
    conn.release();
  }
});

// Actualizar estado de una tarea (cualquier usuario autenticado)
api.put('/tasks/:id/status', requireAnyAuthenticated, async (req, res) => {
  const taskId = Number(req.params.id);
  const { status } = req.body ?? {};
  const userId = req.authUserId;

  if (!taskId) {
    return res.status(400).json({ message: 'taskId inválido' });
  }
  if (!status) {
    return res.status(400).json({ message: 'status es requerido' });
  }

  const newStatusId = STATUS_IDS[status];
  if (!newStatusId) {
    return res.status(400).json({ message: `status inválido: ${status}` });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Obtener estado actual
    const [currentRows] = await conn.query(
      'SELECT current_status_id FROM tasks WHERE id = ? LIMIT 1',
      [taskId]
    );
    const currentList = Array.isArray(currentRows) ? currentRows : [];
    if (!currentList.length) {
      await conn.rollback();
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }
    const fromStatusId = currentList[0].current_status_id;

    // Actualizar task
    const completedAt =
      status === 'done' ? new Date() : null;

    await conn.query(
      `
      UPDATE tasks
      SET current_status_id = ?, completed_at = ?
      WHERE id = ?
      `,
      [newStatusId, completedAt, taskId]
    );

    // Insertar en historial
    await conn.query(
      `
      INSERT INTO task_status_history (task_id, user_id, from_status_id, to_status_id)
      VALUES (?, ?, ?, ?)
      `,
      [taskId, userId, fromStatusId, newStatusId]
    );

    await conn.commit();

    const row = await fetchTaskById(taskId);
    if (!row) {
      return res.status(500).json({ message: 'No se pudo recuperar la tarea actualizada' });
    }

    return res.json(row);
  } catch (err) {
    console.error('Error actualizando estado de tarea:', err);
    await conn.rollback();
    return res.status(500).json({ message: 'Error al actualizar estado de tarea' });
  } finally {
    conn.release();
  }
});

// ========================
//  Tareas del usuario actual (rol usuario)
//  GET /api/tasks/my
//  Requiere: x-role: 'usuario' | 'admin' | 'root' y x-user-id
// ========================
api.get('/tasks/my', requireAnyAuthenticated, async (req, res) => {
  try {
    const userId = req.authUserId; // viene del header x-user-id validado en requireAnyAuthenticated

    const sql = `
      SELECT
        t.id,
        t.title,
        t.description,
        t.due_date       AS dueDate,
        t.completed_at   AS completedAt,
        t.archived,
        -- prioridad en código ('low' | 'medium' | 'high')
        CASE p.name
          WHEN 'baja'  THEN 'low'
          WHEN 'media' THEN 'medium'
          WHEN 'alta'  THEN 'high'
          ELSE 'medium'
        END AS priority,
        -- estado en código ('pending' | 'in_progress' | 'done')
        CASE s.name
          WHEN 'pendiente'   THEN 'pending'
          WHEN 'en_proceso'  THEN 'in_progress'
          WHEN 'completada'  THEN 'done'
          ELSE 'pending'
        END AS status,
        u.name AS assignee,
        COALESCE(e.evidence_count, 0)  AS evidenceCount,
        COALESCE(c.comments_count, 0)  AS commentsCount
      FROM tasks t
      JOIN priorities   p  ON p.id = t.priority_id
      JOIN task_status  s  ON s.id = t.current_status_id
      LEFT JOIN (
        SELECT task_id, COUNT(*) AS evidence_count
        FROM task_attachments
        GROUP BY task_id
      ) e ON e.task_id = t.id
      LEFT JOIN (
        SELECT task_id, COUNT(*) AS comments_count
        FROM task_comments
        GROUP BY task_id
      ) c ON c.task_id = t.id
      JOIN task_assignments ta
        ON ta.task_id = t.id
       AND ta.is_active = 1
      JOIN users u
        ON u.id = ta.user_id
      WHERE t.archived = 0
        AND ta.user_id = ?
      ORDER BY
        t.due_date IS NULL,
        t.due_date ASC,
        t.id DESC
    `;

    const [rows] = await pool.query(sql, [userId]);
    const list = Array.isArray(rows) ? rows : [];

    return res.json({ tasks: list });
  } catch (err) {
    console.error('Error listando mis tareas:', err);
    return res.status(500).json({ message: 'Error al listar tareas del usuario' });
  }
});

/* ========================
 *  Foros (admin / root)
 * ====================== */

// Crear foro
// POST /api/forums
// Body JSON:
// {
//   "title": "Sprint 10 - Entregables",
//   "description": "Hilo para dudas",
//   "isPublic": true/false,
//   "memberEmails": ["alumno1@escuela.com", "alumno2@escuela.com"]
// }
//
// Headers esperados (en dev):
//   x-role: 'admin' o 'root'
//   x-user-id: id numérico del usuario creador (opcional)
api.post('/forums', requireAdminOrRoot, async (req, res) => {
  const {
    title,
    description = null,
    isPublic = true,
    memberEmails = []
  } = req.body ?? {};

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
      [title, description, isPublic ? 1 : 0, createdBy]
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
        memberEmails
      );

      const userList = Array.isArray(userRows) ? userRows : [];

      if (userList.length > 0) {
        const values = userList.map((u) => [forumId, u.id]);
        await conn.query(
          `
          INSERT INTO forum_members (forum_id, user_id)
          VALUES ?
          `,
          [values]
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

// Listar foros
// GET /api/forums
// Devuelve: { forums: [ { id, title, description, isPublic, messagesCount } ] }
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

/* ========================
 *  Mensajes de foro (chat)
 * ====================== */

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
        u.name AS author,
        fp.body AS text,
        fp.created_at AS createdAt,
        CASE WHEN r.name IN ('admin', 'root') THEN 1 ELSE 0 END AS isAdmin
      FROM forum_posts fp
      JOIN users u ON u.id = fp.user_id
      JOIN roles r ON r.id = u.role_id
      WHERE fp.forum_id = ?
      ORDER BY fp.created_at ASC
    `;

    const [rows] = await pool.query(sql, [forumId]);
    const list = Array.isArray(rows) ? rows : [];

    return res.json({ posts: list });
  } catch (err) {
    console.error('Error listando posts del foro:', err);
    return res.status(500).json({ message: 'Error al listar mensajes' });
  }
});

// Crear mensaje en un foro
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
    const [forumRows] = await pool.query(
      'SELECT id FROM forums WHERE id = ? LIMIT 1',
      [forumId]
    );
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
      [forumId, userId, body]
    );

    const postId = insertResult.insertId;

    // Recuperamos el mensaje con todos los datos
    const [rows] = await pool.query(
      `
      SELECT
        fp.id,
        u.name AS author,
        fp.body AS text,
        fp.created_at AS createdAt,
        CASE WHEN r.name IN ('admin', 'root') THEN 1 ELSE 0 END AS isAdmin
      FROM forum_posts fp
      JOIN users u ON u.id = fp.user_id
      JOIN roles r ON r.id = u.role_id
      WHERE fp.id = ?
      LIMIT 1
      `,
      [postId]
    );

    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      return res.status(500).json({ message: 'No se pudo recuperar el mensaje creado' });
    }

    return res.status(201).json(list[0]);
  } catch (err) {
    console.error('Error creando mensaje del foro:', err);
    return res.status(500).json({ message: 'Error al crear mensaje' });
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