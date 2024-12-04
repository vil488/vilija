const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const winston = require('winston');
require('dotenv').config();
const CryptoJS = require('crypto-js'); 
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: 'https://vilijaclient.onrender.com',
    methods: ['GET', 'POST', 'DELETE'],
  },
});

app.set('trust proxy', true);

const PORT = 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const FILE_PATH_USERS = './db.json';
const FILE_PATH_MESSAGES = './dbc.json';

// --- Middlewares ---
app.use(cors({
  origin: 'https://vilijaclient.onrender.com',
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());
app.use(compression());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 хвілін
  max: 100, // Максімум 100 запытаў за 15 хвілін
});
app.use(limiter);

// Лагаванне
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

// --- Utility functions ---
const getUsers = () => {
  try {
    const data = fs.readFileSync(FILE_PATH_USERS, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    logger.error('Error reading users:', err);
    return [];
  }
};

const getChatMessages = () => {
  try {
    if (!fs.existsSync(FILE_PATH_MESSAGES)) {
      fs.writeFileSync(FILE_PATH_MESSAGES, JSON.stringify({ messages: [] }, null, 2));
    }
    const data = fs.readFileSync(FILE_PATH_MESSAGES, 'utf8');
    return JSON.parse(data).messages || [];
  } catch (err) {
    logger.error('Error reading chat messages:', err);
    return [];
  }
};

const saveChatMessages = (messages) => {
  try {
    fs.writeFileSync(FILE_PATH_MESSAGES, JSON.stringify({ messages }, null, 2));
  } catch (err) {
    logger.error('Error saving chat messages:', err);
  }
};

// --- Routes ---
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

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

  const token = jwt.sign({ username: user.username, color: user.color, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
  res.status(200).json({ token, username: user.username, color: user.color, role: user.role });

});

// Абнаўленне токена
app.post('/refresh-token', (req, res) => {
  const oldToken = req.body.token;

  try {
    const decoded = jwt.verify(oldToken, SECRET_KEY);
    const newToken = jwt.sign({ username: decoded.username, color: decoded.color, role: decoded.role }, SECRET_KEY, { expiresIn: '1h' });
    res.status(200).json({ token: newToken });
  } catch (err) {
    res.status(401).json({ message: 'Token is invalid or expired' });
  }
});






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

      const SECRET_KEY_CHAT = process.env.SECRET_KEY_CHAT //той жа код што і ў крыстальніка для дышэфроўкі

      app.get('/get-key', (req, res) => {
        
        const keyToSend = process.env.SECRET_KEY_USER; //cам ключ шыфравання чату

        // Шыфраванне ключа
        const encryptedKey = CryptoJS.AES.encrypt(keyToSend, SECRET_KEY_CHAT).toString();

        // Адправіць зашыфраваны ключ фронтэнду
        res.json({ key: encryptedKey });
      });



// --- WebSocket functionality ---
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));

  try {
    const user = jwt.verify(token, SECRET_KEY);
    socket.user = user;
    next();
  } catch (err) {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  logger.info(`User connected: ${socket.user.username}`);

  const chatHistory = getChatMessages();
  socket.emit('chat history', chatHistory);

  socket.on('message', (data) => {
    const message = {
        sender: socket.user.username,
        text: data.text,
        color: socket.user.color,
        timestamp: new Date().toISOString(),
    };

    const messages = getChatMessages();
    messages.push(message);
    saveChatMessages(messages);

    io.emit('message', message); // Адпраўляем паведамленне ўсім кліентам
});


  socket.on('disconnect', () => {
    logger.info(`User disconnected: ${socket.user.username}`);
  });

  socket.on('load history', ({ offset }, callback) => {
    const limit = 20;
    const messages = getChatMessages()
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)) // Сартыруем ад апошніх да самых ранніх
        .slice(offset, offset + limit);
    callback(messages);
});


app.get('/check-admin', (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Атрымаць токен з загалоўка

  if (!token) {
      return res.status(401).json({ message: 'Access denied, no token provided' });
  }

  try {
      // Дэкодзіруем токен
      const decoded = jwt.verify(token, SECRET_KEY);
      console.log('Decoded Token:', decoded); // Дадаць лагі для праверкі
      // Калі роля карыстальніка "admin"
      if (decoded.role === 'admin') {
          return res.json({ isAdmin: true });
      } else {
          return res.json({ isAdmin: false });
      }
  } catch (err) {
      console.error('Token verification error:', err); // Дадаць лагі для памылак
      return res.status(400).json({ message: 'Invalid token' });
  }
});




});

// Атрымаць усе артыкулы
app.get('/articles', (req, res) => {
  fs.readFile('./dba.json', 'utf-8', (err, data) => {
    if (err) return res.status(500).json({ error: 'Error reading file' });
    res.send(JSON.parse(data));
  });
});

// Атрымаць адзін артыкул па ID
app.get('/articles/:id', (req, res) => {
  const articleId = parseInt(req.params.id);
  fs.readFile('./dba.json', 'utf-8', (err, data) => {
    if (err) return res.status(500).json({ error: 'Error reading file' });
    const articles = JSON.parse(data);
    const article = articles.find((a) => a.id === articleId);
    if (!article) return res.status(404).json({ error: 'Article not found' });
    res.send(article);
  });
});

// Дадаць новы артыкул
app.post('/newarticle', (req, res) => {
  const newArticle = req.body; // Атрымаць дадзеныя з цела запыту

  // Праверыць, ці ўсе неабходныя палі ёсць
  if (!newArticle.title || !newArticle.content || !newArticle.author || !newArticle.date) {
    return res.status(400).json({ error: 'All fields are required: title, content, author, date' });
  }

  // Чытаем існуючыя артыкулы
  fs.readFile('./dba.json', 'utf-8', (err, data) => {
    if (err) return res.status(500).json({ error: 'Error reading file' });

    let articles = JSON.parse(data);

    // Ствараем новы ID
    const newId = articles.length > 0 ? articles[articles.length - 1].id + 1 : 1;

    // Дадаем ID да новага артыкула
    newArticle.id = newId;

    // Дадаем новы артыкул у спіс
    articles.push(newArticle);

    // Захоўваем абноўлены спіс у файл
    fs.writeFile('./dba.json', JSON.stringify(articles, null, 2), (err) => {
      if (err) return res.status(500).json({ error: 'Error writing file' });
      res.status(201).json({ message: 'Article added successfully', article: newArticle });
    });
  });
});


// --- Start server ---
server.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
