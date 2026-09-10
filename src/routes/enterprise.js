const router         = require('express').Router();
const db             = require('../db');
const enterpriseAuth = require('../middleware/enterpriseAuth');

// All routes require enterprise admin authentication
router.use(enterpriseAuth);

// ══════════════════════════════════════════════════════════════════
// DASHBOARD
// ══════════════════════════════════════════════════════════════════

// GET /api/enterprise/dashboard — Total schools, revenue, subscriptions
router.get('/dashboard', async (req, res) => {
  try {
    const [schoolsCount, subsStats, revenueStats, ticketsCount] = await Promise.all([
      db.query('SELECT COUNT(*) FROM schools'),
      db.query(`
        SELECT
          COUNT(*) as total,
          COUNT(*) FILTER (WHERE status = 'active') as active,
          COUNT(*) FILTER (WHERE status = 'expired') as expired,
          COUNT(*) FILTER (WHERE status = 'trial') as trial
        FROM subscriptions
      `),
      db.query(`
        SELECT
          COALESCE(SUM(amount), 0) as total_revenue,
          COALESCE(SUM(amount) FILTER (WHERE start_date >= DATE_TRUNC('month', CURRENT_DATE)), 0) as this_month
        FROM subscriptions WHERE status = 'active'
      `),
      db.query("SELECT COUNT(*) FROM support_tickets WHERE status IN ('open','in_progress')"),
    ]);

    res.json({
      total_schools: parseInt(schoolsCount.rows[0].count),
      subscriptions: {
        total: parseInt(subsStats.rows[0].total),
        active: parseInt(subsStats.rows[0].active),
        expired: parseInt(subsStats.rows[0].expired),
        trial: parseInt(subsStats.rows[0].trial),
      },
      revenue: {
        total: parseFloat(revenueStats.rows[0].total_revenue),
        this_month: parseFloat(revenueStats.rows[0].this_month),
      },
      open_tickets: parseInt(ticketsCount.rows[0].count),
    });
  } catch (err) {
    console.error('Enterprise dashboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════════
// SCHOOLS MANAGEMENT
// ══════════════════════════════════════════════════════════════════

// GET /api/enterprise/schools — List all schools
router.get('/schools', async (req, res) => {
  try {
    const page  = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 25;
    const offset = (page - 1) * limit;
    const { search, status } = req.query;

    let query = `
      SELECT s.*,
        sub.plan, sub.status as subscription_status, sub.end_date as subscription_end,
        (SELECT COUNT(*) FROM students st WHERE st.school_id = s.id) as student_count,
        (SELECT COUNT(*) FROM teachers t WHERE t.school_id = s.id) as teacher_count
      FROM schools s
      LEFT JOIN subscriptions sub ON sub.school_id = s.id AND sub.status = 'active'
      WHERE 1=1`;
    const params = [];
    let idx = 1;

    if (search) {
      query += ` AND (s.name ILIKE $${idx} OR s.code ILIKE $${idx})`;
      params.push(`%${search}%`);
      idx++;
    }
    if (status === 'active') { query += ' AND s.is_active = true AND s.is_locked = false'; }
    else if (status === 'locked') { query += ' AND s.is_locked = true'; }
    else if (status === 'inactive') { query += ' AND s.is_active = false'; }

    query += ` ORDER BY s.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`;
    params.push(limit, offset);

    const { rows } = await db.query(query, params);

    const countResult = await db.query('SELECT COUNT(*) FROM schools');
    const total = parseInt(countResult.rows[0].count);

    res.json({
      data: rows,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('List schools error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/enterprise/schools — Add school + create school admin with email
router.post('/schools', async (req, res) => {
  const { name, code, address, city, state, phone, email, admin_name, admin_email, admin_phone } = req.body;

  if (!name || !code) {
    return res.status(400).json({ error: 'name and code are required' });
  }

  if (!admin_email) {
    return res.status(400).json({ error: 'admin_email is required to create school admin login' });
  }

  const crypto = require('crypto');
  const bcrypt = require('bcryptjs');
  const { sendSetPasswordEmail } = require('../services/email');
  const APP_URL = process.env.APP_URL || 'http://13.126.4.16';

  const client = await db.connect();
  try {
    await client.query('BEGIN');

    // Check if school code already exists
    const existingSchool = await client.query(
      'SELECT id FROM schools WHERE code = $1',
      [code]
    );
    if (existingSchool.rows.length) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `School code "${code}" already exists. Please use a unique code.` });
    }

    // Check if admin_email already exists as a user
    const existingUser = await client.query(
      'SELECT id FROM users WHERE email = $1',
      [admin_email]
    );
    if (existingUser.rows.length) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `A user with email ${admin_email} already exists` });
    }

    // 1. Create the school
    const schoolResult = await client.query(
      `INSERT INTO schools (name, code, address, city, state, phone, email)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [name, code, address || null, city || null, state || null, phone || null, email || null]
    );
    const school = schoolResult.rows[0];

    // 2. Create school admin user (password not set — must use email link)
    const adminId = `ADM${String(school.id).padStart(3, '0')}`;
    const placeholder = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(placeholder, 10);

    await client.query(
      `INSERT INTO users (id, school_id, password, role, name, email, phone, password_set)
       VALUES ($1, $2, $3, 'admin', $4, $5, $6, false)`,
      [adminId, school.id, hashedPassword, admin_name || `Admin - ${name}`, admin_email, admin_phone || null]
    );

    // 3. Generate password setup token (72 hours)
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000);

    await client.query(
      `INSERT INTO password_tokens (user_id, token, type, expires_at)
       VALUES ($1, $2, 'set_password', $3)`,
      [adminId, token, expiresAt]
    );

    await client.query('COMMIT');

    // 4. Send email with password setup link (non-blocking)
    const setupLink = `${APP_URL}/set-password?token=${token}`;

    // Fire-and-forget — don't block the response if email fails
    sendSetPasswordEmail(admin_email, admin_name || `Admin - ${name}`, token, name)
      .then(result => {
        if (result.success) {
          console.log(`✉️  Setup email sent to ${admin_email}`);
        } else {
          console.error(`❌ Email failed for ${admin_email}: ${result.error}`);
        }
      })
      .catch(err => console.error('Email send failed:', err.message));

    const emailResult = { success: true };



    res.status(201).json({
      school: school,
      admin: {
        id: adminId,
        name: admin_name || `Admin - ${name}`,
        email: admin_email,
        password_set: false,
        setup_link: setupLink,
        email_sent: emailResult.success,
        message: emailResult.success
          ? `School created! Admin login email sent to ${admin_email}`
          : `School created! Email failed — share this link with the admin: ${setupLink}`,
      },
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Add school error:', err);
    if (err.code === '23505') {
      return res.status(409).json({ error: 'School code already exists' });
    }
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// PUT /api/enterprise/schools/:id — Update school
router.put('/schools/:id', async (req, res) => {
  const { id } = req.params;
  const { name, address, city, state, phone, email, is_active } = req.body;

  try {
    const { rows } = await db.query(
      `UPDATE schools SET
        name = COALESCE($1, name),
        address = COALESCE($2, address),
        city = COALESCE($3, city),
        state = COALESCE($4, state),
        phone = COALESCE($5, phone),
        email = COALESCE($6, email),
        is_active = COALESCE($7, is_active),
        updated_at = NOW()
       WHERE id = $8 RETURNING *`,
      [name, address, city, state, phone, email, is_active, id]
    );
    if (!rows.length) return res.status(404).json({ error: 'School not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Update school error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/enterprise/schools/:id/lock — Lock/unlock school
router.put('/schools/:id/lock', async (req, res) => {
  const { id } = req.params;
  const { locked } = req.body;

  if (typeof locked !== 'boolean') {
    return res.status(400).json({ error: 'locked (boolean) is required' });
  }

  try {
    const { rows } = await db.query(
      `UPDATE schools SET is_locked = $1, updated_at = NOW() WHERE id = $2 RETURNING *`,
      [locked, id]
    );
    if (!rows.length) return res.status(404).json({ error: 'School not found' });
    res.json({ success: true, school: rows[0] });
  } catch (err) {
    console.error('Lock school error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════════
// SUBSCRIPTIONS
// ══════════════════════════════════════════════════════════════════

// GET /api/enterprise/subscriptions — All subscriptions
router.get('/subscriptions', async (req, res) => {
  try {
    const page  = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 25;
    const offset = (page - 1) * limit;

    const { rows } = await db.query(
      `SELECT sub.*, s.name as school_name, s.code as school_code
       FROM subscriptions sub
       JOIN schools s ON s.id = sub.school_id
       ORDER BY sub.created_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    const countResult = await db.query('SELECT COUNT(*) FROM subscriptions');
    const total = parseInt(countResult.rows[0].count);

    res.json({
      data: rows,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('List subscriptions error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/enterprise/subscriptions/:schoolId — Update subscription
router.put('/subscriptions/:schoolId', async (req, res) => {
  const { schoolId } = req.params;
  const { plan, status, start_date, end_date, amount, max_students, max_teachers, features } = req.body;

  try {
    // Upsert the subscription
    const { rows } = await db.query(
      `INSERT INTO subscriptions (school_id, plan, status, start_date, end_date, amount, max_students, max_teachers, features)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (id) DO UPDATE SET
         plan = COALESCE($2, subscriptions.plan),
         status = COALESCE($3, subscriptions.status),
         start_date = COALESCE($4, subscriptions.start_date),
         end_date = COALESCE($5, subscriptions.end_date),
         amount = COALESCE($6, subscriptions.amount),
         max_students = COALESCE($7, subscriptions.max_students),
         max_teachers = COALESCE($8, subscriptions.max_teachers),
         features = COALESCE($9, subscriptions.features),
         updated_at = NOW()
       RETURNING *`,
      [
        schoolId,
        plan || 'basic',
        status || 'active',
        start_date || new Date().toISOString().split('T')[0],
        end_date || null,
        amount || 0,
        max_students || 500,
        max_teachers || 50,
        features ? JSON.stringify(features) : '[]'
      ]
    );

    res.json(rows[0]);
  } catch (err) {
    console.error('Update subscription error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════════
// ANALYTICS
// ══════════════════════════════════════════════════════════════════

// GET /api/enterprise/analytics — Usage analytics
router.get('/analytics', async (req, res) => {
  try {
    const [userStats, attendanceStats, schoolGrowth] = await Promise.all([
      db.query(`
        SELECT role, COUNT(*) as count FROM users GROUP BY role
      `),
      db.query(`
        SELECT
          DATE_TRUNC('week', date) as week,
          COUNT(*) as total_records,
          COUNT(*) FILTER (WHERE status = 'present') as present
        FROM attendance
        WHERE date >= CURRENT_DATE - INTERVAL '12 weeks'
        GROUP BY week
        ORDER BY week
      `),
      db.query(`
        SELECT
          DATE_TRUNC('month', created_at) as month,
          COUNT(*) as new_schools
        FROM schools
        WHERE created_at >= CURRENT_DATE - INTERVAL '12 months'
        GROUP BY month
        ORDER BY month
      `),
    ]);

    res.json({
      users_by_role: userStats.rows,
      weekly_attendance: attendanceStats.rows,
      school_growth: schoolGrowth.rows,
    });
  } catch (err) {
    console.error('Analytics error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/enterprise/revenue — Revenue dashboard
router.get('/revenue', async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT
        DATE_TRUNC('month', start_date) as month,
        plan,
        COUNT(*) as subscriptions,
        SUM(amount) as revenue
      FROM subscriptions
      WHERE start_date >= CURRENT_DATE - INTERVAL '12 months'
      GROUP BY month, plan
      ORDER BY month DESC, plan
    `);

    const totalRevenue = await db.query(
      "SELECT COALESCE(SUM(amount), 0) as total FROM subscriptions WHERE status = 'active'"
    );

    res.json({
      monthly_breakdown: rows,
      total_active_revenue: parseFloat(totalRevenue.rows[0].total),
    });
  } catch (err) {
    console.error('Revenue error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════════
// SUPPORT TICKETS
// ══════════════════════════════════════════════════════════════════

// GET /api/enterprise/tickets — Support tickets
router.get('/tickets', async (req, res) => {
  try {
    const page  = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 25;
    const offset = (page - 1) * limit;
    const { status, priority } = req.query;

    let query = `
      SELECT t.*, s.name as school_name, u.name as raised_by_name
      FROM support_tickets t
      LEFT JOIN schools s ON s.id = t.school_id
      LEFT JOIN users u ON u.id = t.raised_by
      WHERE 1=1`;
    const params = [];
    let idx = 1;

    if (status) { query += ` AND t.status = $${idx}`; params.push(status); idx++; }
    if (priority) { query += ` AND t.priority = $${idx}`; params.push(priority); idx++; }

    query += ` ORDER BY
      CASE t.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
      t.created_at DESC
      LIMIT $${idx} OFFSET $${idx + 1}`;
    params.push(limit, offset);

    const { rows } = await db.query(query, params);

    const countResult = await db.query('SELECT COUNT(*) FROM support_tickets');
    const total = parseInt(countResult.rows[0].count);

    res.json({
      data: rows,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('List tickets error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/enterprise/tickets/:id — Update ticket status
router.put('/tickets/:id', async (req, res) => {
  const { id } = req.params;
  const { status, assigned_to, resolution } = req.body;

  if (!status) {
    return res.status(400).json({ error: 'status is required' });
  }

  try {
    const { rows } = await db.query(
      `UPDATE support_tickets SET
        status = $1,
        assigned_to = COALESCE($2, assigned_to),
        resolution = COALESCE($3, resolution),
        updated_at = NOW()
       WHERE id = $4 RETURNING *`,
      [status, assigned_to || null, resolution || null, id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Ticket not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Update ticket error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════════
// AUDIT LOG
// ══════════════════════════════════════════════════════════════════

// GET /api/enterprise/audit — Audit log
router.get('/audit', async (req, res) => {
  try {
    const page  = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    const { school_id, user_id, action } = req.query;

    let query = `
      SELECT al.*, s.name as school_name, u.name as user_name
      FROM audit_log al
      LEFT JOIN schools s ON s.id = al.school_id
      LEFT JOIN users u ON u.id = al.user_id
      WHERE 1=1`;
    const params = [];
    let idx = 1;

    if (school_id) { query += ` AND al.school_id = $${idx}`; params.push(school_id); idx++; }
    if (user_id) { query += ` AND al.user_id = $${idx}`; params.push(user_id); idx++; }
    if (action) { query += ` AND al.action = $${idx}`; params.push(action); idx++; }

    query += ` ORDER BY al.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`;
    params.push(limit, offset);

    const { rows } = await db.query(query, params);

    const countResult = await db.query('SELECT COUNT(*) FROM audit_log');
    const total = parseInt(countResult.rows[0].count);

    res.json({
      data: rows,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('Audit log error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
