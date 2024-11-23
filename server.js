const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const cors = require('cors'); // Для падтрымкі запытаў з фронтэнда

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key'; // Замяніце на надзейны ключ

// Сярэдзіны
app.use(cors({ origin: 'https://vilijaclient.onrender.com' })); // Дазваляем фронтэнд дамен
app.use(express.json()); // Для апрацоўкі JSON-запытаў

// Чытаем карыстальнікаў з db.json
const getUsers = () => {
  const data = fs.readFileSync('db.json', 'utf8');
  return JSON.parse(data);
};

// Роўт для лагіна
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    const users = getUsers();
    const user = users.find((u) => u.username === username);

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
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
