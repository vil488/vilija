const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const User = require('./userModel'); // Падключэнне да мадэлі карыстальніка

const app = express();
const PORT = process.env.PORT || 5000; // Render аўтаматычна надае PORT

app.use(cors());
app.use(bodyParser.json());

// Падключэнне да MongoDB Atlas
require('dotenv').config();


const uri = process.env.MONGODB_URI;
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Падключана да MongoDB'))
  .catch(err => console.log('Памылка падключэння:', err));

// Рэгістрацыя карыстальніка
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.json({ success: false, message: 'Карыстальнік ужо існуе' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.json({ success: true, message: 'Карыстальнік паспяхова зарэгістраваны!' });
  } catch (error) {
    console.error(error);
    res.json({ success: false, message: 'Памылка рэгістрацыі' });
  }
});

// Лагін карыстальніка
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.json({ success: false, message: 'Няправільны лагін ці пароль' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      res.json({ success: true, message: 'Лагін паспяховы!' });
    } else {
      res.json({ success: false, message: 'Няправільны лагін ці пароль' });
    }
  } catch (error) {
    console.error(error);
    res.json({ success: false, message: 'Памылка з лагінам' });
  }
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер працуе на порце ${PORT}`);
});
