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
        methods: ['GET', 'POST','DELETE'],
    },
});

const PORT = 3000;
require('dotenv').config();
const SECRET_KEY = process.env.SECRET_KEY;

// Middlewares
app.use(cors({
  origin: 'https://vilijaclient.onrender.com',
  methods: ['GET', 'POST', 'DELETE'],
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
    const filePath = './dbc.json';
  
    // Праверка, ці існуе файл, і яго чытанне
    if (!fs.existsSync(filePath)) {
      // Калі файл не існуе, ствараем новы з пустым масівам паведамленняў
      fs.writeFileSync(filePath, JSON.stringify({ messages: [] }, null, 2));
      return [];
    }
  
    try {
      const data = fs.readFileSync(filePath, 'utf8');
  
      // Правяраем, ці ёсць дадзеныя ў файле
      if (!data) {
        return [];
      }
  
      // Паспрабуем прачытаць і разбіць JSON
      const db = JSON.parse(data);
      return db.messages || [];  // Вяртаем паведамленні або пусты масіў
    } catch (err) {
      console.error('Error reading or parsing chat messages:', err);
      return []; // Калі ўзнікае памылка пры разбіванні JSON, вяртаем пусты масіў
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




const getPaginatedMessages = (offset, limit) => {
  try {
    const messages = getChatMessages(); // Загружаем усе паведамленні з файла
    const start = Math.max(messages.length - offset - limit, 0); // Вылічваем пачатак
    const end = messages.length - offset; // Вылічваем канец
    return messages.slice(start, end); // Вяртаем патрэбны фрагмент
  } catch (err) {
    console.error('Error getting paginated messages:', err);
    return [];
  }
};

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
        color: socket.user.color,  // Дадаем колер карыстальніка да паведамлення
        timestamp: new Date().toISOString(), 
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


  socket.on('load history', ({ offset }, callback) => {
    const limit = 20; // Колькасць паведамленняў за раз
    const messages = getPaginatedMessages(offset, limit); // Атрымліваем патрэбную частку
    callback(messages); // Адпраўляем іх кліенту
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





const FILE_PATH = './dba.json';

// Роўт для атрымання спісу ўсіх артыкулаў
app.get('/articles', (req, res) => {
    fs.readFile(FILE_PATH, 'utf-8', (err, data) => {
        if (err) {
            res.status(500).send({ error: 'Не ўдалося прачытаць файл' });
            return;
        }
        const articles = JSON.parse(data);
        res.send(articles);
    });
});

// Роўт для атрымання артыкула па ID
app.get('/articles/:id', (req, res) => {
    const articleId = parseInt(req.params.id);
    fs.readFile(FILE_PATH, 'utf-8', (err, data) => {
        if (err) {
            res.status(500).send({ error: 'Не ўдалося прачытаць файл' });
            return;
        }
        const articles = JSON.parse(data);
        const article = articles.find(a => a.id === articleId);
        if (!article) {
            res.status(404).send({ error: 'Артыкул не знойдзены' });
            return;
        }
        res.send(article);
    });
});


// Start server
server.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});




//РЭАЛІЗАЦЫЯ ШЫФРАВАННЯ

const forge = require('node-forge');

const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair({ bits: 2048 });
const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
const publicKeyPem = forge.pki.publicKeyToPem(publicKey);

// Захаваем RSA-ключы ў файл для наступнага выкарыстання
fs.writeFileSync('./rsa_private.pem', privateKeyPem);
fs.writeFileSync('./rsa_public.pem', publicKeyPem);

app.get('/rsa-public-key', (req, res) => {
  try {
      const publicKey = fs.readFileSync('./rsa_public.pem', 'utf8');
      res.send({ publicKey });
  } catch (err) {
      console.error('Error reading RSA public key:', err);
      res.status(500).send({ error: 'Не ўдалося атрымаць RSA публічны ключ' });
  }
});

socket.on('request aes key', (callback) => {
  const aesKey = CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Hex); // Генерацыя AES-ключа
  const publicKeyPem = fs.readFileSync('./rsa_public.pem', 'utf8'); // RSA-публічны ключ
  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);

  const encryptedAESKey = forge.util.encode64(publicKey.encrypt(aesKey, 'RSA-OAEP')); // Зашыфраваны AES-ключ
  callback(encryptedAESKey);
});
