const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = 3000; // Змяніце порт пры неабходнасці

require('dotenv').config();
const SECRET_KEY = process.env.SECRET_KEY;

// Сярэдзіны
app.use(cors({ 
  origin: 'https://vilijaclient.onrender.com', // Дазваляем запыты з вашага фронтэнда
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json()); // Для апрацоўкі JSON-запытаў

// Чытаем карыстальнікаў з файла db.json
const getUsers = () => {
  const data = fs.readFileSync('./db.json', 'utf8');
  return JSON.parse(data);
};

// Роўт для лагіна
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    // Чытаем усіх карыстальнікаў з db.json
    const users = getUsers();
    const user = users.find((u) => u.username === username);

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Параўноўваем уведзены пароль з захаваным хэшам
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Генерацыя JWT
    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Роўт для абароненага кантэнту
app.get('/protected', (req, res) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({ message: 'Authorization header required' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    res.status(200).json({ message: 'Protected content', user: decoded });
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: 'Invalid or expired token' });
  }
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
