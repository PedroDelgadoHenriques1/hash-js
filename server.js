const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const fs = require('fs');

const app = express();
const PORT = 3000;
const DATA_FILE = 'users.json';

app.use(bodyParser.json());
app.use(express.static(__dirname)); // serve arquivos html e estaticos

let users = [];
if (fs.existsSync(DATA_FILE)) {
    users = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
}

function saveUsers() {
    fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
}


app.post('/register', async (req, res) => {
    const { name, password } = req.body;
    if (!name || !password) return res.status(400).send('Nome e senha são obrigatórios.');

    const existingUser = users.find(u => u.name === name);
    if (existingUser) {
        return res.status(400).send('Usuário já existe.');
    }

    const salt = name + Date.now();
    const hash = await bcrypt.hash(password + salt, 10);

    users.push({ name, hash, salt });
    saveUsers();
    res.send('Usuário cadastrado com sucesso!');
});

app.post('/login', async (req, res) => {
    const { name, password } = req.body;
    const user = users.find(u => u.name === name);

    if (!user) return res.status(404).send('Usuário não encontrado.');

    if (user.lockedUntil && Date.now() < user.lockedUntil) {
        return res.status(403).send('Conta bloqueada. Tente novamente mais tarde.');
    }

    const isValid = await bcrypt.compare(password + user.salt, user.hash);
    if (!isValid) {
        user.failedAttempts = (user.failedAttempts || 0) + 1;

        if (user.failedAttempts >= 5) {
            user.lockedUntil = Date.now() + 60000;
            saveUsers();
            return res.status(403).send('Muitas tentativas falhadas. Conta bloqueada por 1 minuto.');
        }

        saveUsers();
        return res.status(401).send('Senha incorreta.');
    }

    // se logar, reseta o counter
    user.failedAttempts = 0;
    user.lockedUntil = null; // e desbloqueia a conta
    saveUsers();

    currentUser = user.name;
    res.send('Login bem-sucedido!');
});


function isAuthenticated(req, res, next) {
    if (!currentUser) {
        return res.status(403).send('Você precisa estar logado para acessar essa página.');
    }
    next();
}

app.get('/dashboard.html', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/dashboard.html');
});

app.get('/users', isAuthenticated, (req, res) => {
    res.json(users);
});

app.get('/logout', (req, res) => {
    currentUser = null;
    res.redirect('/');
});

app.get('/check-auth', (req, res) => {
    if (!currentUser) {
        return res.status(401).send('Não autenticado.');
    }
    res.send('Autenticado');
});


app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
