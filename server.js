require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors({
  origin: [
    'https://gestion-aluen.netlify.app',
    'http://localhost:3001',
    'http://127.0.0.1:5500',
    'null'
  ],
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true
}));
app.options('*', cors());
app.use(express.json());

// ── CONEXIÓN ──
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Atlas conectado — ALUEN'))
  .catch(err => { console.error('❌ Error de conexión:', err.message); process.exit(1); });

// ── JWT MIDDLEWARE ──
const JWT_SECRET = process.env.JWT_SECRET || 'aluen_secreto_dev';

function authRequired(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Token requerido' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// ── RUTA LOGIN ──
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });

  // 1. Verificar contra admin maestro del .env
  const masterUser = process.env.ADMIN_USER || 'aluen_admin';
  const masterPass = process.env.ADMIN_PASS || 'Aluen2024!';
  if (username === masterUser && password === masterPass) {
    const token = jwt.sign(
      { username, role: 'admin', nombre: 'Administrador',
        permisos: { dashboard:true, pedidos:true, ventas:true, inventario:true, productos:true, kpis:true, config:true, write:true } },
      JWT_SECRET, { expiresIn: '8h' }
    );
    return res.json({ token, username, nombre: 'Administrador', role: 'admin',
      permisos: { dashboard:true, pedidos:true, ventas:true, inventario:true, productos:true, kpis:true, config:true, write:true } });
  }

  // 2. Verificar contra usuarios en MongoDB
  try {
    const user = await Usuario.findOne({ username: username.trim() });
    if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    if (user.estado !== 'activo') return res.status(403).json({ error: 'Usuario inactivo. Contacta al administrador.' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const token = jwt.sign(
      { username: user.username, role: user.rol, nombre: user.nombre, userId: user._id, permisos: user.permisos || {} },
      JWT_SECRET, { expiresIn: '8h' }
    );
    return res.json({ token, username: user.username, nombre: user.nombre, role: user.rol, permisos: user.permisos || {} });
  } catch (e) {
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

// ── RUTA VERIFICAR TOKEN ──
app.get('/api/auth/verify', authRequired, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// ── SCHEMAS ──
const ProductoSchema = new mongoose.Schema({
  nombre:    { type: String, required: true },
  cat:       { type: String, default: '' },
  linea:     { type: String, default: '' },
  costo:     { type: Number, default: 0 },
  precio:    { type: Number, default: 0 },
  margenPct: { type: Number, default: 0 },
  desc:      { type: String, default: '' },
  invId:     { type: String, default: '' },
  imagen:    { type: String, default: '' },
}, { timestamps: true });

const PedidoSchema = new mongoose.Schema({
  fecha:     { type: String, required: true },
  cliente:   { type: String, required: true },
  tel:       { type: String, default: '' },
  productoId:{ type: mongoose.Schema.Types.ObjectId, ref: 'Producto' },
  cantidad:  { type: Number, default: 1 },
  precio:    { type: Number, default: 0 },
  total:     { type: Number, default: 0 },
  canal:     { type: String, default: 'Instagram' },
  estado:    { type: String, default: 'Pendiente', enum: ['Pendiente','En proceso','Entregado','Cancelado'] },
  notas:     { type: String, default: '' },
  items:          { type: Array, default: [] },
  clienteId:      { type: mongoose.Schema.Types.ObjectId, ref: 'Cliente', default: null },
  subtotal:        { type: Number, default: 0 },
  descuento:       { type: Number, default: 0 },
  codigoDescuento: { type: String, default: '' },
  pago:      { type: String, default: 'Efectivo' },
  ciudad:    { type: String, default: '' },
}, { timestamps: true });

const InventarioSchema = new mongoose.Schema({
  nombre:  { type: String, required: true },
  cat:     { type: String, default: 'Materia prima' },
  unidad:  { type: String, default: 'unidades' },
  qty:     { type: Number, default: 0 },
  min:     { type: Number, default: 5 },
  costo:   { type: Number, default: 0 },
  linea:   { type: String, default: '' },
  imagen:  { type: String, default: '' },
}, { timestamps: true });

const ClienteSchema = new mongoose.Schema({
  codigo:        { type: String, default: '' },
  nombres:       { type: String, required: true },
  apellidos:     { type: String, default: '' },
  tipoDoc:       { type: String, default: 'CC' },
  documento:     { type: String, default: '' },
  celular:       { type: String, default: '' },
  correo:        { type: String, default: '' },
  notas:         { type: String, default: '' },
  estado:        { type: String, default: 'activo', enum: ['activo','inactivo'] },
  puntos:        { type: Number, default: 0 },
  totalCompras:  { type: Number, default: 0 },
  totalGastado:  { type: Number, default: 0 },
  // compatibilidad pedidos anteriores
  nombre:        { type: String, default: '' },
  tel:           { type: String, default: '' },
  canal:         { type: String, default: '' },
}, { timestamps: true });

const UsuarioSchema = new mongoose.Schema({
  nombre:    { type: String, required: true },
  username:  { type: String, required: true, unique: true },
  password:  { type: String, required: true },
  rol:       { type: String, default: 'ventas', enum: ['admin','ventas','inventario','readonly'] },
  estado:    { type: String, default: 'activo', enum: ['activo','inactivo'] },
  email:     { type: String, default: '' },
  permisos:  { type: Object, default: {} },
}, { timestamps: true });

const Producto   = mongoose.model('Producto',   ProductoSchema);
const Pedido     = mongoose.model('Pedido',     PedidoSchema);
const Inventario = mongoose.model('Inventario', InventarioSchema);
const Cliente    = mongoose.model('Cliente',    ClienteSchema);
const Usuario    = mongoose.model('Usuario',    UsuarioSchema);

// ── HELPER CRUD ──
function crud(router, Model) {
  router.get('/',        async (_, res) => res.json(await Model.find().sort({ createdAt: -1 })));
  router.get('/:id',     async (req, res) => { const d = await Model.findById(req.params.id); d ? res.json(d) : res.status(404).json({ error: 'No encontrado' }); });
  router.post('/',       async (req, res) => { try { res.status(201).json(await Model.create(req.body)); } catch(e) { res.status(400).json({ error: e.message }); } });
  router.put('/:id',     async (req, res) => { try { res.json(await Model.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true })); } catch(e) { res.status(400).json({ error: e.message }); } });
  router.delete('/:id',  async (req, res) => { await Model.findByIdAndDelete(req.params.id); res.json({ ok: true }); });
  return router;
}

app.use('/api/productos',   authRequired, crud(express.Router(), Producto));
app.use('/api/inventario',  authRequired, crud(express.Router(), Inventario));
app.use('/api/clientes',    authRequired, crud(express.Router(), Cliente));

// ── PEDIDOS (con populate) ──
const rPedidos = express.Router();
rPedidos.get('/', async (_, res) => res.json(await Pedido.find().populate('productoId').sort({ createdAt: -1 })));
rPedidos.get('/:id', async (req, res) => { const d = await Pedido.findById(req.params.id).populate('productoId'); d ? res.json(d) : res.status(404).json({ error: 'No encontrado' }); });
rPedidos.post('/', async (req, res) => {
  try {
    const pedido = await Pedido.create(req.body);
    // Actualizar o crear cliente
    const { cliente, tel, canal, total } = req.body;
    await Cliente.findOneAndUpdate(
      { nombre: cliente },
      { $inc: { totalCompras: 1, totalGastado: total }, $set: { tel, canal } },
      { upsert: true, new: true }
    );
    res.status(201).json(pedido);
  } catch(e) { res.status(400).json({ error: e.message }); }
});
rPedidos.put('/:id', async (req, res) => { try { res.json(await Pedido.findByIdAndUpdate(req.params.id, req.body, { new: true })); } catch(e) { res.status(400).json({ error: e.message }); } });
rPedidos.delete('/:id', async (req, res) => { await Pedido.findByIdAndDelete(req.params.id); res.json({ ok: true }); });
app.use('/api/pedidos', authRequired, rPedidos);

// ── KPIs ──
app.get('/api/kpis', authRequired, async (_, res) => {
  try {
    const [pedidos, productos, inventario, clientes] = await Promise.all([
      Pedido.find().populate('productoId'),
      Producto.find(),
      Inventario.find(),
      Cliente.find(),
    ]);
    const entregados = pedidos.filter(p => p.estado === 'Entregado');
    const totalVentas = entregados.reduce((s, p) => s + p.total, 0);
    const unidades    = entregados.reduce((s, p) => s + p.cantidad, 0);
    const ticket      = entregados.length ? totalVentas / entregados.length : 0;
    const costos      = entregados.reduce((s, p) => s + (p.productoId ? p.productoId.costo * p.cantidad : 0), 0);
    const margenBruto = totalVentas - costos;
    const margenPct   = totalVentas ? (margenBruto / totalVentas) * 100 : 0;
    const stockBajo   = inventario.filter(i => i.qty <= i.min).length;
    const pending     = pedidos.filter(p => ['Pendiente','En proceso'].includes(p.estado)).length;
    const clientesRecurrentes = clientes.filter(c => c.totalCompras > 1).length;
    const canales = {};
    entregados.forEach(p => { canales[p.canal] = (canales[p.canal] || 0) + p.total; });
    const ventasPorProducto = {};
    entregados.forEach(p => {
      const nombre = p.productoId ? p.productoId.nombre : 'Sin producto';
      ventasPorProducto[nombre] = (ventasPorProducto[nombre] || 0) + p.total;
    });
    res.json({ totalVentas, unidades, ticket, costos, margenBruto, margenPct, stockBajo, pending, clientesRecurrentes, totalClientes: clientes.length, canales, ventasPorProducto });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── USUARIOS CRUD ──
const rUsuarios = express.Router();
rUsuarios.get('/', authRequired, async (req, res) => {
  const isAdmin = req.user.role === 'admin' || req.user.rol === 'admin';
  if(!isAdmin) return res.status(403).json({ error: 'Acceso restringido a administradores' });
  const u = await Usuario.find().select('-password').sort({ createdAt: -1 });
  res.json(u);
});
rUsuarios.post('/', authRequired, async (req, res) => {
  const isAdmin = req.user.role === 'admin' || req.user.rol === 'admin';
  if(!isAdmin) return res.status(403).json({ error: 'Acceso restringido a administradores' });
  try {
    const hashed = await bcrypt.hash(req.body.password, 10);
    const u = await Usuario.create({ ...req.body, password: hashed });
    res.status(201).json({ ...u.toObject(), password: undefined });
  } catch(e) { res.status(400).json({ error: e.message }); }
});
rUsuarios.put('/:id', authRequired, async (req, res) => {
  const isAdmin = req.user.role === 'admin' || req.user.rol === 'admin';
  if(!isAdmin) return res.status(403).json({ error: 'Acceso restringido a administradores' });
  const body = { ...req.body };
  if(body.password) body.password = await bcrypt.hash(body.password, 10);
  else delete body.password;
  const u = await Usuario.findByIdAndUpdate(req.params.id, body, { new: true }).select('-password');
  res.json(u);
});
rUsuarios.delete('/:id', authRequired, async (req, res) => {
  const isAdmin = req.user.role === 'admin' || req.user.rol === 'admin';
  if(!isAdmin) return res.status(403).json({ error: 'Acceso restringido a administradores' });
  await Usuario.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});
app.use('/api/usuarios', rUsuarios);

// ── HEALTH ──
app.get('/api/health', (_, res) => res.json({ status: 'ok', app: 'ALUEN API', time: new Date() }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => console.log(`🕯️  ALUEN API corriendo en puerto ${PORT}`));
