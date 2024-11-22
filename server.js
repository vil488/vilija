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


mongoose.connect('mongodb://localhost:27017/vilija')
  .then(() => console.log('Падключана да базы дадзеных'))
  .catch(err => console.error('Памылка падключэння:', err));

// Рэгістрацыя карыстальніка
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Праверка, ці ўжо існуе карыстальнік
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.json({ success: false, message: 'Карыстальнік ужо існуе' });
    }

    // Хэш пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Захаванне карыстальніка ў базу
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.json({ success: true, message: 'Карыстальнік паспяхова дададзены!' });
  } catch (error) {
    console.error(error);
    res.json({ success: false, message: 'Памылка дадання карыстальніка' });
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
