const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000; // Вызначаем порт для Render або лакальна

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

    console.log("Received request to add user");

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    // Загружаем дадзеныя з файла
    fs.readFile(dbPath, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading file:', err);
            return res.status(500).json({ message: 'Server error' });
        }

        let users = [];
        try {
            users = JSON.parse(data || '[]'); // Калі файл пусты, пераўтвараем у пусты масіў
        } catch (parseError) {
            console.error('Error parsing JSON data:', parseError);
            return res.status(500).json({ message: 'Error parsing user data' });
        }

        // Правяраем, ці ўжо існуе карыстальнік
        const userExists = users.some((user) => user.username === username);
        if (userExists) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Дадаем новага карыстальніка
        users.push({ username, password });

        // Запісваем у файл
        fs.writeFile(dbPath, JSON.stringify(users, null, 2), (err) => {
            if (err) {
                console.error('Error saving user:', err);
                return res.status(500).json({ message: 'Failed to save user' });
            }
            console.log('User added successfully');
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
        if (err) {
            console.error('Error reading file:', err);
            return res.status(500).json({ message: 'Server error' });
        }

        let users = [];
        try {
            users = JSON.parse(data || '[]');
        } catch (parseError) {
            console.error('Error parsing JSON data:', parseError);
            return res.status(500).json({ message: 'Error parsing user data' });
        }

        const user = users.find((u) => u.username === username && u.password === password);

        if (!user) {
            console.log('Invalid login attempt');
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        console.log('Login successful');
        res.status(200).json({ message: 'Login successful' });
    });
});

// Пераканаемся, што слухаем на правільным порце і хостынгу
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер працуе на порце ${PORT}`);
});

