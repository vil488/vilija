const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Шлях да файла базы
const dbPath = path.join(__dirname, 'database.json');

// Каб парсіць JSON з цела запытаў
app.use(express.json());

// Маршрут для праверкі, ці працуе сервер
app.get('/', (req, res) => {
    res.send('Все добра, сервер працуе!');
});

// Маршрут для дадання новага карыстальніка
app.post('/add-user', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    // Загружаем дадзеныя з файла
    fs.readFile(dbPath, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ message: 'Server error' });

        const users = JSON.parse(data || '[]'); // Калі файл пусты, пераўтвараем у пусты масіў

        // Правяраем, ці ўжо існуе карыстальнік
        const userExists = users.some((user) => user.username === username);
        if (userExists) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Дадаем новага карыстальніка
        users.push({ username, password });

        // Запісваем у файл
        fs.writeFile(dbPath, JSON.stringify(users, null, 2), (err) => {
            if (err) return res.status(500).json({ message: 'Failed to save user' });
            res.status(201).json({ message: 'User added successfully' });
        });
    });
});

// Маршрут для праверкі лагіна
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    console.log("Received request to login");

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    // Загружаем дадзеныя з файла
    fs.readFile(dbPath, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ message: 'Server error' });

        const users = JSON.parse(data || '[]');
        const user = users.find((u) => u.username === username && u.password === password);

        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        res.status(200).json({ message: 'Login successful' });
    });
});

app.listen(PORT, () => {
    console.log(`Сервер працуе на порце ${PORT}`);
});
