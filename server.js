// functions/server.js

const express = require('express');
const app = express();

const cors = require('cors');
app.use(cors());  // Дадаём падтрымку CORS


// Наладжванне парсера JSON
app.use(express.json());

// Просты маршрут для праверкі
app.get('/', (req, res) => {
  res.send('Hello from Vilija Chat!');
});

// Лагіка для адпраўкі паведамлення
let messages = [];

app.post('/message', (req, res) => {
  const { message } = req.body;
  if (message) {
    messages.push(message);
    res.status(200).send({ success: true, message: 'Message received' });
  } else {
    res.status(400).send({ success: false, message: 'No message provided' });
  }
});

// Лагіка для атрымання ўсіх паведамленняў
app.get('/messages', (req, res) => {
  res.status(200).json(messages);
});

// Настройка порта
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
