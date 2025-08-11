const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(cors());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('Error acquiring client', err.stack);
  } else {
    console.log('✓ Database connected successfully');
    release();
  }
});

// =================================================================
// >> MIDDLEWARE <<
// =================================================================

// Authentication middleware
const authMiddleware = (req, res, next) => {
  const authHeader = req.header('Authorization');
  if (!authHeader) {
    return res.status(401).json({ success: false, msg: 'No token, authorization denied' });
  }

  try {
    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, msg: 'Token format is invalid' });
    }

    const decoded = jwt.verify(token, 'your_jwt_secret');
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ success: false, msg: 'Token is not valid' });
  }
};

// Admin middleware
const adminMiddleware = (req, res, next) => {
  if (req.user && (req.user.role === 'Admin' || req.user.role === 'Super Admin')) {
    next();
  } else {
    res.status(403).json({ success: false, msg: 'Access forbidden: Admin role required' });
  }
};

// Super Admin middleware
const superAdminMiddleware = (req, res, next) => {
  if (req.user && req.user.role === 'Super Admin') {
    next();
  } else {
    res.status(403).json({ success: false, msg: 'Access forbidden: Super Admin role required' });
  }
};

// =================================================================
// >> PUBLIC ROUTES <<
// =================================================================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'Server is running', timestamp: new Date().toISOString() });
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, msg: 'Please provide username and password' });
    }

    const userResult = await pool.query('SELECT * FROM Users WHERE username = $1', [username]);

    if (userResult.rows.length === 0) {
      return res.status(400).json({ success: false, msg: 'Invalid credentials' });
    }

    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ success: false, msg: 'Invalid credentials' });
    }

    const payload = {
      user: {
        id: user.user_id,
        username: user.username,
        role: user.role
      }
    };

    const token = jwt.sign(payload, 'your_jwt_secret', { expiresIn: '24h' });

    res.json({
      success: true,
      token,
      user: {
        id: user.user_id,
        username: user.username,
        role: user.role
      }
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});

// Register (for initial setup)
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, msg: 'Please provide username and password' });
    }

    // Check if user already exists
    const existingUser = await pool.query('SELECT * FROM Users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ success: false, msg: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await pool.query(
      'INSERT INTO Users (username, password, role) VALUES ($1, $2, $3) RETURNING user_id, username, role',
      [username, hashedPassword, role || 'Viewer']
    );

    res.status(201).json({ success: true, data: newUser.rows[0] });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});

// =================================================================
// >> PROTECTED ROUTES <<
// =================================================================

// Dashboard Summary
app.get('/api/dashboard-summary', authMiddleware, async (req, res) => {
  try {
    const { season_id } = req.query;
    
    let query;
    let params = [];
    
    if (season_id) {
      // Season-specific query - SIMPLE VERSION
      query = `
        SELECT
          COALESCE((SELECT SUM(quantity * unit_price) FROM Purchases WHERE season_id = $1), 0) AS total_purchases,
          COALESCE((SELECT SUM(quantity * unit_price) FROM Sales WHERE season_id = $1), 0) AS total_sales,
          COALESCE((SELECT SUM(amount) FROM Expenses WHERE season_id = $1), 0) AS total_expenses,
          COALESCE((SELECT SUM(stock_quantity) FROM Items), 0) AS total_stock_quantity
      `;
      params = [season_id];
    } else {
      // Original query (unchanged)
      query = `
        SELECT
          COALESCE((SELECT SUM(quantity * unit_price) FROM Purchases), 0) AS total_purchases,
          COALESCE((SELECT SUM(quantity * unit_price) FROM Sales), 0) AS total_sales,
          COALESCE((SELECT SUM(amount) FROM Expenses), 0) AS total_expenses,
          COALESCE((SELECT SUM(stock_quantity) FROM Items), 0) AS total_stock_quantity
      `;
    }

    const result = await pool.query(query, params);
    const stats = result.rows[0];
    
    const totalPurchases = parseFloat(stats.total_purchases) || 0;
    const totalSales = parseFloat(stats.total_sales) || 0;
    const totalExpenses = parseFloat(stats.total_expenses) || 0;
    const profit = totalSales - (totalPurchases + totalExpenses);

    res.json({
      success: true,
      data: {
        totalPurchases,
        totalSales,
        totalExpenses,
        totalStockValue: parseFloat(stats.total_stock_quantity) || 0,
        profit,
      }
    });
  } catch (err) {
    console.error('Dashboard summary error:', err.message);
    console.error('Error stack:', err.stack); // Extra debugging
    res.status(500).json({ success: false, msg: 'Server Error', error: err.message });
  }
});


// Items Routes
app.get('/api/items', authMiddleware, async (req, res) => {
  try {
    const allItems = await pool.query('SELECT * FROM Items ORDER BY item_name ASC');
    res.json({ success: true, data: allItems.rows });
  } catch (err) {
    console.error('Get items error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});

app.post('/api/items', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const { item_name, stock_quantity } = req.body;

    if (!item_name) {
      return res.status(400).json({ success: false, msg: 'Please include an item name' });
    }

    // Check if item already exists
    const existingItem = await pool.query('SELECT * FROM Items WHERE LOWER(item_name) = LOWER($1)', [item_name]);
    if (existingItem.rows.length > 0) {
      return res.status(400).json({ success: false, msg: 'Item already exists' });
    }

    const newItem = await pool.query(
      'INSERT INTO Items (item_name, stock_quantity) VALUES ($1, $2) RETURNING *',
      [item_name, stock_quantity || 0]
    );

    res.status(201).json({ success: true, data: newItem.rows[0] });
  } catch (err) {
    console.error('Add item error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});

app.delete('/api/items/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    await client.query('BEGIN');

    const itemResult = await client.query('SELECT * FROM Items WHERE item_id = $1', [id]);
    if (itemResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, msg: 'Item not found' });
    }

    const hasPurchases = await client.query('SELECT 1 FROM Purchases WHERE item_id = $1 LIMIT 1', [id]);
    const hasSales = await client.query('SELECT 1 FROM Sales WHERE item_id = $1 LIMIT 1', [id]);
    const hasExpenses = await client.query('SELECT 1 FROM Expenses WHERE item_id = $1 LIMIT 1', [id]);

    if (hasPurchases.rows.length > 0 || hasSales.rows.length > 0 || hasExpenses.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        success: false,
        msg: 'Cannot delete item because it has associated transactions'
      });
    }

    await client.query('DELETE FROM Items WHERE item_id = $1', [id]);

    await client.query('COMMIT');
    res.json({ success: true, msg: 'Item deleted successfully' });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Delete item error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  } finally {
    client.release();
  }
});

// Purchases Routes
app.get('/api/purchases', authMiddleware, async (req, res) => {
  try {
    const allPurchases = await pool.query(`
      SELECT p.*, i.item_name, s.season_name
      FROM Purchases p
      JOIN Items i ON p.item_id = i.item_id
      LEFT JOIN Seasons s ON p.season_id = s.season_id
      ORDER BY p.date DESC, p.purchase_id DESC
    `);
    res.json({ success: true, data: allPurchases.rows });
  } catch (err) {
    console.error('Get purchases error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});

app.post('/api/purchases', [authMiddleware, adminMiddleware], async (req, res) => {
  const client = await pool.connect();
  try {
    const { date, item_id, season_id, quantity, unit_price, vendor_name } = req.body;

    if (!date || !item_id || !season_id || !quantity || !unit_price || !vendor_name) {
      return res.status(400).json({ success: false, msg: 'All fields are required' });
    }
    if (quantity <= 0 || unit_price <= 0) {
      return res.status(400).json({ success: false, msg: 'Quantity and unit price must be greater than 0' });
    }

    await client.query('BEGIN');

    const purchaseQuery = `
      INSERT INTO Purchases (date, item_id, season_id, quantity, unit_price, vendor_name) 
      VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
    `;
    const newPurchase = await client.query(purchaseQuery, [date, item_id, season_id, quantity, unit_price, vendor_name]);

    const updateStockQuery = `UPDATE Items SET stock_quantity = stock_quantity + $1 WHERE item_id = $2`;
    await client.query(updateStockQuery, [quantity, item_id]);

    await client.query('COMMIT');
    res.status(201).json({ success: true, data: newPurchase.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Add purchase error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  } finally {
    client.release();
  }
});

app.delete('/api/purchases/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    await client.query('BEGIN');

    const purchaseResult = await client.query('SELECT * FROM Purchases WHERE purchase_id = $1', [id]);
    if (purchaseResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, msg: 'Purchase not found' });
    }
    const purchase = purchaseResult.rows[0];
    const { item_id, quantity } = purchase;

    const updateStockQuery = `UPDATE Items SET stock_quantity = stock_quantity - $1 WHERE item_id = $2`;
    await client.query(updateStockQuery, [quantity, item_id]);

    await client.query('DELETE FROM Purchases WHERE purchase_id = $1', [id]);
    await client.query('COMMIT');
    res.json({ success: true, msg: 'Purchase deleted successfully', data: purchase });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Delete purchase error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  } finally {
    client.release();
  }
});

// Sales Routes
app.get('/api/sales', authMiddleware, async (req, res) => {
  try {
    const allSales = await pool.query(`
      SELECT s.*, i.item_name, se.season_name
      FROM Sales s
      JOIN Items i ON s.item_id = i.item_id
      LEFT JOIN Seasons se ON s.season_id = se.season_id
      ORDER BY s.date DESC, s.sale_id DESC
    `);
    res.json({ success: true, data: allSales.rows });
  } catch (err) {
    console.error('Get sales error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});

app.post('/api/sales', [authMiddleware, adminMiddleware], async (req, res) => {
  const client = await pool.connect();
  try {
    const { date, item_id, season_id, quantity, unit_price, customer_name } = req.body;

    if (!date || !item_id || !season_id || !quantity || !unit_price || !customer_name) {
      return res.status(400).json({ success: false, msg: 'All fields are required' });
    }
    if (quantity <= 0 || unit_price <= 0) {
      return res.status(400).json({ success: false, msg: 'Quantity and unit price must be greater than 0' });
    }

    await client.query('BEGIN');

    const stockResult = await client.query('SELECT stock_quantity FROM Items WHERE item_id = $1', [item_id]);
    const currentStock = stockResult.rows[0]?.stock_quantity || 0;

    if (currentStock < quantity) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        success: false,
        msg: `Not enough stock available. Current stock: ${currentStock}, Requested: ${quantity}`
      });
    }

    const saleQuery = `
      INSERT INTO Sales (date, item_id, season_id, quantity, unit_price, customer_name) 
      VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
    `;
    const newSale = await client.query(saleQuery, [date, item_id, season_id, quantity, unit_price, customer_name]);

    const updateStockQuery = `UPDATE Items SET stock_quantity = stock_quantity - $1 WHERE item_id = $2`;
    await client.query(updateStockQuery, [quantity, item_id]);

    await client.query('COMMIT');
    res.status(201).json({ success: true, data: newSale.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Add sale error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  } finally {
    client.release();
  }
});

app.delete('/api/sales/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    await client.query('BEGIN');

    const saleResult = await client.query('SELECT * FROM Sales WHERE sale_id = $1', [id]);
    if (saleResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, msg: 'Sale not found' });
    }
    const sale = saleResult.rows[0];
    const { item_id, quantity } = sale;

    const updateStockQuery = `UPDATE Items SET stock_quantity = stock_quantity + $1 WHERE item_id = $2`;
    await client.query(updateStockQuery, [quantity, item_id]);

    await client.query('DELETE FROM Sales WHERE sale_id = $1', [id]);
    await client.query('COMMIT');
    res.json({ success: true, msg: 'Sale deleted successfully', data: sale });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Delete sale error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  } finally {
    client.release();
  }
});

// Expenses Routes
app.get('/api/expenses', authMiddleware, async (req, res) => {
  try {
    const allExpenses = await pool.query(`
      SELECT e.*, i.item_name, s.season_name
      FROM Expenses e
      LEFT JOIN Items i ON e.item_id = i.item_id
      LEFT JOIN Seasons s ON e.season_id = s.season_id
      ORDER BY e.date DESC, e.expense_id DESC
    `);
    res.json({ success: true, data: allExpenses.rows });
  } catch (err) {
    console.error('Get expenses error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});

app.post('/api/expenses', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const { date, expense_type, linked_transaction_id, item_id, amount, description, season_id } = req.body;

    if (!expense_type || !amount || !season_id || !description) {
      return res.status(400).json({ success: false, msg: 'Expense type, amount, description, and season_id are required' });
    }
    if (amount <= 0) {
      return res.status(400).json({ success: false, msg: 'Amount must be greater than 0' });
    }

    const newExpense = await pool.query(
      `INSERT INTO Expenses (date, expense_type, linked_transaction_id, item_id, amount, description, season_id) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [date, expense_type, linked_transaction_id, item_id, amount, description, season_id]
    );

    res.status(201).json({ success: true, data: newExpense.rows[0] });
  } catch (err) {
    console.error('Add expense error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});

app.delete('/api/expenses/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const { id } = req.params;

    const expenseResult = await pool.query('SELECT * FROM Expenses WHERE expense_id = $1', [id]);
    if (expenseResult.rows.length === 0) {
      return res.status(404).json({ success: false, msg: 'Expense not found' });
    }
    const expense = expenseResult.rows[0];

    await pool.query('DELETE FROM Expenses WHERE expense_id = $1', [id]);
    res.json({ success: true, msg: 'Expense deleted successfully', data: expense });
  } catch (err) {
    console.error('Delete expense error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});

/// GET all seasons
app.get('/api/seasons', authMiddleware, async (req, res) => {
  try {
    const allSeasons = await pool.query('SELECT * FROM Seasons ORDER BY season_id DESC');
    res.json({ success: true, data: allSeasons.rows });
  } catch (err) {
    console.error('Get seasons error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});

// POST new season
app.post('/api/seasons', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    console.log('Request body:', req.body); // Debug log
    
    const { season_name } = req.body;

    // Validate required fields
    if (!season_name) {
      return res.status(400).json({ success: false, msg: 'Season name is required' });
    }

    // Validate season name length
    if (season_name.length > 50) {
      return res.status(400).json({ success: false, msg: 'Season name cannot exceed 50 characters' });
    }

    // Check if season already exists
    const existingSeason = await pool.query(
      'SELECT * FROM Seasons WHERE LOWER(season_name) = LOWER($1)', 
      [season_name]
    );
    
    if (existingSeason.rows.length > 0) {
      return res.status(400).json({ success: false, msg: 'Season already exists' });
    }

    // Insert new season
    const newSeason = await pool.query(
      'INSERT INTO Seasons (season_name) VALUES ($1) RETURNING *',
      [season_name]
    );

    console.log('Season created:', newSeason.rows[0]); // Debug log
    res.status(201).json({ success: true, data: newSeason.rows[0] });
    
  } catch (err) {
    console.error('Add season error:', err);
    res.status(500).json({ success: false, msg: 'Server Error', error: err.message });
  }
});
app.delete('/api/seasons/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    await client.query('BEGIN');

    const seasonResult = await client.query('SELECT * FROM Seasons WHERE season_id = $1', [id]);
    if (seasonResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, msg: 'Season not found' });
    }

    const hasPurchases = await client.query('SELECT 1 FROM Purchases WHERE season_id = $1 LIMIT 1', [id]);
    const hasSales = await client.query('SELECT 1 FROM Sales WHERE season_id = $1 LIMIT 1', [id]);
    const hasExpenses = await client.query('SELECT 1 FROM Expenses WHERE season_id = $1 LIMIT 1', [id]);

    if (hasPurchases.rows.length > 0 || hasSales.rows.length > 0 || hasExpenses.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        success: false,
        msg: 'Cannot delete season because it has associated transactions.'
      });
    }

    const deletedSeason = await client.query('DELETE FROM Seasons WHERE season_id = $1 RETURNING *', [id]);
    await client.query('COMMIT');

    res.json({
      success: true,
      msg: 'Season deleted successfully',
      data: deletedSeason.rows[0]
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Delete season error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  } finally {
    client.release();
  }
});

// Report Route
app.get('/api/report', authMiddleware, async (req, res) => {
  try {
    const { season_id, item_id, start_date, end_date } = req.query;
    
    // Build the main query with better structure
    let baseQuery = `
      WITH combined_transactions AS (
        SELECT 
          'purchase' AS transaction_type, 
          purchase_id AS id, 
          date, 
          item_id, 
          quantity, 
          unit_price,
          (quantity * unit_price) as total_amount,
          vendor_name AS party_name, 
          season_id,
          i.item_name,
          s.season_name
        FROM Purchases p
        LEFT JOIN Items i ON p.item_id = i.item_id
        LEFT JOIN Seasons s ON p.season_id = s.season_id
        
        UNION ALL
        
        SELECT 
          'sale' AS transaction_type, 
          sale_id AS id, 
          date, 
          item_id, 
          quantity, 
          unit_price, 
          (quantity * unit_price) as total_amount,
          customer_name AS party_name, 
          season_id,
          i.item_name,
          s.season_name
        FROM Sales sa
        LEFT JOIN Items i ON sa.item_id = i.item_id
        LEFT JOIN Seasons s ON sa.season_id = s.season_id
        
        UNION ALL
        
        SELECT 
          'expense' AS transaction_type,
          expense_id AS id,
          date,
          item_id,
          NULL::numeric AS quantity,
          NULL::numeric AS unit_price,
          amount as total_amount,
          description AS party_name,
          season_id,
          i.item_name,
          s.season_name
        FROM Expenses e
        LEFT JOIN Items i ON e.item_id = i.item_id
        LEFT JOIN Seasons s ON e.season_id = s.season_id
      )
      SELECT * FROM combined_transactions
    `;

    let whereClauses = [];
    let params = [];
    let paramIndex = 1;

    if (season_id) {
      whereClauses.push(`season_id = $${paramIndex}`);
      params.push(season_id);
      paramIndex++;
    }

    if (item_id) {
      whereClauses.push(`item_id = $${paramIndex}`);
      params.push(item_id);
      paramIndex++;
    }

    if (start_date && end_date) {
      whereClauses.push(`date BETWEEN $${paramIndex} AND $${paramIndex + 1}`);
      params.push(start_date, end_date);
      paramIndex += 2;
    }

    if (whereClauses.length > 0) {
      baseQuery += ` WHERE ${whereClauses.join(' AND ')}`;
    }

    baseQuery += ' ORDER BY date DESC, id DESC';

    const reportData = await pool.query(baseQuery, params);

    // Separate data by transaction type for easier processing
    const purchases = reportData.rows.filter(row => row.transaction_type === 'purchase');
    const sales = reportData.rows.filter(row => row.transaction_type === 'sale');
    const expenses = reportData.rows.filter(row => row.transaction_type === 'expense');

    // Calculate totals
    const totalPurchases = purchases.reduce((sum, p) => sum + parseFloat(p.total_amount), 0);
    const totalSales = sales.reduce((sum, s) => sum + parseFloat(s.total_amount), 0);
    const totalExpenses = expenses.reduce((sum, e) => sum + parseFloat(e.total_amount), 0);

    res.json({
      success: true,
      data: {
        transactions: reportData.rows,
        purchases: purchases,
        sales: sales,
        expenses: expenses,
        summary: {
          totalPurchases,
          totalSales,
          totalExpenses,
          profit: totalSales - (totalPurchases + totalExpenses),
          transactionCount: reportData.rows.length
        },
        filters: {
          season_id,
          item_id,
          start_date,
          end_date
        }
      }
    });

  } catch (err) {
    console.error('Report error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});
// =================================================================
// >> SUPER ADMIN PROTECTED ROUTES <<
// =================================================================

// Users Routes (Super Admin only)
app.get('/api/users', [authMiddleware, superAdminMiddleware], async (req, res) => {
  try {
    const allUsers = await pool.query('SELECT user_id, username, role FROM Users ORDER BY user_id ASC');
    res.json({ success: true, data: allUsers.rows });
  } catch (err) {
    console.error('Get users error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});

app.post('/api/users', [authMiddleware, superAdminMiddleware], async (req, res) => {
  try {
    const { username, password, role } = req.body;

    if (!username || !password || !role) {
      return res.status(400).json({ success: false, msg: 'Please provide username, password, and role' });
    }

    if (!['Admin', 'Viewer'].includes(role)) {
      return res.status(400).json({ success: false, msg: 'Invalid role. Can only be Admin or Viewer.' });
    }

    const existingUser = await pool.query('SELECT * FROM Users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ success: false, msg: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await pool.query(
      'INSERT INTO Users (username, password, role) VALUES ($1, $2, $3) RETURNING user_id, username, role',
      [username, hashedPassword, role]
    );

    res.status(201).json({ success: true, data: newUser.rows[0] });
  } catch (err) {
    console.error('Add user error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});

app.put('/api/users/:id', [authMiddleware, superAdminMiddleware], async (req, res) => {
  try {
    const { id } = req.params;
    const { username, password, role } = req.body;

    if (!username || !role) {
      return res.status(400).json({ success: false, msg: 'Username and role are required' });
    }

    if (!['Admin', 'Viewer', 'Super Admin'].includes(role)) {
      return res.status(400).json({ success: false, msg: 'Invalid role' });
    }

    let query, params;

    if (password) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      query = 'UPDATE Users SET username = $1, password = $2, role = $3 WHERE user_id = $4 RETURNING user_id, username, role';
      params = [username, hashedPassword, role, id];
    } else {
      query = 'UPDATE Users SET username = $1, role = $2 WHERE user_id = $3 RETURNING user_id, username, role';
      params = [username, role, id];
    }

    const updatedUser = await pool.query(query, params);

    if (updatedUser.rows.length === 0) {
      return res.status(404).json({ success: false, msg: 'User not found' });
    }

    res.json({ success: true, data: updatedUser.rows[0] });
  } catch (err) {
    console.error('Update user error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  }
});
app.get('/api/season-items-count', authMiddleware, async (req, res) => {
  try {
    const { season_id } = req.query;
    
    if (!season_id) {
      return res.status(400).json({ success: false, msg: 'season_id is required' });
    }

    // Count unique items in purchases and sales for this season
    const query = `
      SELECT COUNT(DISTINCT item_id) as total_items
      FROM (
        SELECT item_id FROM Purchases WHERE season_id = $1
        UNION
        SELECT item_id FROM Sales WHERE season_id = $1
      ) AS season_items
    `;

    const result = await pool.query(query, [season_id]);
    const totalItems = parseInt(result.rows[0].total_items) || 0;

    res.json({
      success: true,
      data: { totalItems }
    });
  } catch (err) {
    console.error('Season items count error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error', error: err.message });
  }
});
/// --- FINAL CORRECTED USER DELETE ROUTE ---
app.delete('/api/users/:id', [authMiddleware, superAdminMiddleware], async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    // Prevent deletion of the current user
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ success: false, msg: 'You cannot delete your own account.' });
    }
    
    await client.query('BEGIN');

    // Directly attempt to delete the user
    const deletedUser = await client.query('DELETE FROM Users WHERE user_id = $1 RETURNING user_id, username, role', [id]);

    // Check if a user was actually found and deleted
    if (deletedUser.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, msg: 'User not found' });
    }
    
    await client.query('COMMIT');
    res.json({ success: true, msg: 'User deleted successfully', data: deletedUser.rows[0] });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Delete user error:', err.message);
    res.status(500).json({ success: false, msg: 'Server Error' });
  } finally {
    client.release();
  }
});
// =================================================================
// >> SERVER START <<
// =================================================================

// Server ko start karein
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✓ Server is running on http://localhost:${PORT}`);
  console.log(`✓ Health check available at: http://localhost:${PORT}/api/health`);
});