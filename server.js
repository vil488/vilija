const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const cors = require('cors');
const http = require('http'); // For creating HTTP server
const { Server } = require('socket.io'); // For WebSocket server

const app = express();
const server = http.createServer(app); // Create HTTP server
const io = require('socket.io')(server, {
    cors: {
        origin: 'https://vilijaclient.onrender.com',
        methods: ['GET', 'POST'],
    },
});

const PORT = 3000;
require('dotenv').config();
const SECRET_KEY = process.env.SECRET_KEY;

// Middlewares
app.use(cors({
  origin: 'https://vilijaclient.onrender.com',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json()); // For parsing JSON requests

// Read users from db.json
const getUsers = () => {
  try {
    const data = fs.readFileSync('./db.json', 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error('Error reading users from db.json:', err);
    return [];
  }
};

// Chat functionality
const getChatMessages = () => {
  // Пераканаемся, што файл існуе, калі не, ствараем яго
  if (!fs.existsSync('./dbc.json')) {
    fs.writeFileSync('./dbc.json', JSON.stringify({ messages: [] }, null, 2));
  }

  try {
    const data = fs.readFileSync('./dbc.json', 'utf8');
    console.log('File content:', data); // Лагуем змест файла

    // Калі файл пусты, вяртаем пусты масіў
    if (!data) {
      return [];
    }

    const db = JSON.parse(data);
    return db.messages || [];
  } catch (err) {
    console.error('Error reading chat messages:', err);
    return [];
  }
};

const saveChatMessages = (messages) => {
  const data = { messages };

  try {
    fs.writeFileSync('./dbc.json', JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('Error saving chat messages:', err);
  }
};

// Login route
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

    const token = jwt.sign({ username: user.username, color: user.color }, SECRET_KEY, { expiresIn: '1h' });

    res.status(200).json({ token, username: user.username, color: user.color });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// WebSocket authentication middleware
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }

  try {
    const user = jwt.verify(token, SECRET_KEY);
    socket.user = user; // Store user info in socket
    next();
  } catch (err) {
    next(new Error('Invalid token'));
  }
});

// WebSocket events
io.on('connection', (socket) => {
  console.log(`User connected: ${socket.user.username}`);

  // Адпраўляем гісторыю чата новаму падключэнню
  const chatHistory = getChatMessages();
  socket.emit('chat history', chatHistory);

  // Абработка ўваходных паведамленняў
  socket.on('message', (data) => {
    const message = {
      sender: socket.user.username,
      text: data.text,
      timestamp: new Date().toISOString(),
      color: socket.user.color, // Дадаем колер карыстальніка да паведамлення
    };

    const messages = getChatMessages();
    messages.push(message);
    saveChatMessages(messages);

    io.emit('message', message); // Рассылаем паведамленне ўсім падключаным кліентам
  });

  // Выход з чата
  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.user.username}`);
  });
});

// Маршрут для ачысткі ўсіх паведамленняў
app.delete('/clearMessages', (req, res) => {
  try {
    // Ачышчаем ўсе паведамленні
    const data = { messages: [] };
    fs.writeFileSync('./dbc.json', JSON.stringify(data, null, 2));

    // Адпраўляем адказ
    res.status(200).json({ success: true, message: 'Паведамленні былі выдаленыя' });
  } catch (err) {
    console.error('Error clearing messages:', err);
    res.status(500).json({ success: false, message: 'Не ўдалося выдаліць паведамленні' });
  }
});

// Start server
server.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
