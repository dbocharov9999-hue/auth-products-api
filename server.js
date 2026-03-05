const express = require('express');
const { nanoid } = require('nanoid');
const bcrypt = require('bcrypt');
const cors = require('cors');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

let users = [];
let products = [];

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Auth Products API',
      version: '1.0.0',
      description: 'API для аутентификации и управления товарами',
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: 'Локальный сервер',
      },
    ],
  },
  apis: ['./server.js'],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

async function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function findUserByEmail(email) {
  return users.find(user => user.email === email);
}

function findProductById(id) {
  return products.find(product => product.id === id);
}

async function authenticateUser(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return res.status(401).json({ error: 'Требуется базовая аутентификация' });
  }

  try {
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [email, password] = credentials.split(':');

    const user = findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Пользователь не найден' });
    }

    const isValid = await verifyPassword(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Неверный пароль' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Ошибка аутентификации' });
  }
}

/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - email
 *         - first_name
 *         - last_name
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           example: user@example.com
 *         first_name:
 *           type: string
 *           example: Иван
 *         last_name:
 *           type: string
 *           example: Иванов
 *         password:
 *           type: string
 *           format: password
 *           example: qwerty123
 *     Product:
 *       type: object
 *       required:
 *         - title
 *         - category
 *         - description
 *         - price
 *       properties:
 *         title:
 *           type: string
 *           example: Смартфон XYZ
 *         category:
 *           type: string
 *           example: Электроника
 *         description:
 *           type: string
 *           example: Новейший смартфон с отличной камерой
 *         price:
 *           type: number
 *           example: 59999.99
 */

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Регистрация нового пользователя
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       201:
 *         description: Пользователь успешно создан
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                 email:
 *                   type: string
 *                 first_name:
 *                   type: string
 *                 last_name:
 *                   type: string
 *       400:
 *         description: Ошибка в данных
 */
app.post('/api/auth/register', async (req, res) => {
  const { email, first_name, last_name, password } = req.body;

  if (!email || !first_name || !last_name || !password) {
    return res.status(400).json({ error: 'Все поля обязательны' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Некорректный email' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  }

  if (findUserByEmail(email)) {
    return res.status(400).json({ error: 'Email уже существует' });
  }

  const hashedPassword = await hashPassword(password);
  
  const newUser = {
    id: nanoid(),
    email,
    first_name,
    last_name,
    password: hashedPassword,
  };

  users.push(newUser);

  const { password: _, ...userWithoutPassword } = newUser;
  res.status(201).json(userWithoutPassword);
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Вход в систему
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 example: qwerty123
 *     responses:
 *       200:
 *         description: Успешный вход
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 login:
 *                   type: boolean
 *                 user:
 *                   type: object
 *       401:
 *         description: Неверные учетные данные
 */
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email и пароль обязательны' });
  }

  const user = findUserByEmail(email);
  if (!user) {
    return res.status(401).json({ error: 'Неверный email или пароль' });
  }

  const isValid = await verifyPassword(password, user.password);
  if (!isValid) {
    return res.status(401).json({ error: 'Неверный email или пароль' });
  }

  const { password: _, ...userWithoutPassword } = user;
  res.status(200).json({ 
    login: true, 
    user: userWithoutPassword 
  });
});

/**
 * @swagger
 * /api/products:
 *   post:
 *     summary: Создать новый товар
 *     tags: [Products]
 *     security:
 *       - basicAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Product'
 *     responses:
 *       201:
 *         description: Товар успешно создан
 *       400:
 *         description: Ошибка в данных
 *       401:
 *         description: Не авторизован
 */
app.post('/api/products', authenticateUser, (req, res) => {
  const { title, category, description, price } = req.body;

  if (!title || !category || !description || price === undefined) {
    return res.status(400).json({ error: 'Все поля обязательны' });
  }

  if (typeof price !== 'number' || price <= 0) {
    return res.status(400).json({ error: 'Цена должна быть положительным числом' });
  }

  const newProduct = {
    id: nanoid(),
    title,
    category,
    description,
    price,
    user_id: req.user.id,
  };

  products.push(newProduct);
  res.status(201).json(newProduct);
});

/**
 * @swagger
 * /api/products:
 *   get:
 *     summary: Получить список всех товаров
 *     tags: [Products]
 *     responses:
 *       200:
 *         description: Список товаров
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Product'
 */
app.get('/api/products', (req, res) => {
  res.status(200).json(products);
});

/**
 * @swagger
 * /api/products/{id}:
 *   get:
 *     summary: Получить товар по ID
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: ID товара
 *     responses:
 *       200:
 *         description: Информация о товаре
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Product'
 *       404:
 *         description: Товар не найден
 */
app.get('/api/products/:id', (req, res) => {
  const product = findProductById(req.params.id);

  if (!product) {
    return res.status(404).json({ error: 'Товар не найден' });
  }

  res.status(200).json(product);
});

/**
 * @swagger
 * /api/products/{id}:
 *   put:
 *     summary: Обновить товар
 *     tags: [Products]
 *     security:
 *       - basicAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Product'
 *     responses:
 *       200:
 *         description: Товар обновлен
 *       400:
 *         description: Ошибка в данных
 *       401:
 *         description: Не авторизован
 *       403:
 *         description: Нет прав на редактирование
 *       404:
 *         description: Товар не найден
 */
app.put('/api/products/:id', authenticateUser, (req, res) => {
  const product = findProductById(req.params.id);

  if (!product) {
    return res.status(404).json({ error: 'Товар не найден' });
  }

  if (product.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Нет прав на редактирование' });
  }

  const { title, category, description, price } = req.body;

  if (title) product.title = title;
  if (category) product.category = category;
  if (description) product.description = description;
  if (price !== undefined) {
    if (typeof price !== 'number' || price <= 0) {
      return res.status(400).json({ error: 'Цена должна быть положительным числом' });
    }
    product.price = price;
  }

  res.status(200).json(product);
});

/**
 * @swagger
 * /api/products/{id}:
 *   delete:
 *     summary: Удалить товар
 *     tags: [Products]
 *     security:
 *       - basicAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Товар удален
 *       401:
 *         description: Не авторизован
 *       403:
 *         description: Нет прав на удаление
 *       404:
 *         description: Товар не найден
 */
app.delete('/api/products/:id', authenticateUser, (req, res) => {
  const productIndex = products.findIndex(p => p.id === req.params.id);

  if (productIndex === -1) {
    return res.status(404).json({ error: 'Товар не найден' });
  }

  if (products[productIndex].user_id !== req.user.id) {
    return res.status(403).json({ error: 'Нет прав на удаление' });
  }

  const deletedProduct = products[productIndex];
  products.splice(productIndex, 1);

  res.status(200).json({ 
    message: 'Товар удален',
    deletedProduct 
  });
});

app.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
  console.log(`Swagger UI: http://localhost:${PORT}/api-docs`);
  console.log('');
  console.log('Маршруты:');
  console.log('  POST   /api/auth/register');
  console.log('  POST   /api/auth/login');
  console.log('  POST   /api/products');
  console.log('  GET    /api/products');
  console.log('  GET    /api/products/:id');
  console.log('  PUT    /api/products/:id');
  console.log('  DELETE /api/products/:id');
});