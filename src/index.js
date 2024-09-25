const express = require("express");
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
const port = 3000;

const SECRET_KEY = 'may_the_force_be_with_you';

// Modelos
const User = mongoose.model('User', { 
    username: String,
    password: String 
});

const Filme = mongoose.model('Filme', { 
    title: String,
    description: String,
    image_url: String,
    trailer_url: String,
    year: Number,
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } // Relacionamento com User
});

// Função para gerar tokens JWT
const generateToken = (user) => {
    return jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '1h' });
};

// Middleware de autenticação
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) return res.status(401).send({ error: 'Token não fornecido' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).send({ error: 'Token inválido' });
        req.userId = decoded.id;
        next();
    });
};

// Rotas de autenticação
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Verifica se o usuário já existe
    const userExists = await User.findOne({ username });
    if (userExists) {
        return res.status(400).send({ error: 'Usuário já existe' });
    }

    // Criptografa a senha
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
        username,
        password: hashedPassword
    });

    await user.save();
    res.send({ user, token: generateToken(user) });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(400).send({ error: 'Usuário não encontrado' });

    // Verifica se a senha é válida
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).send({ error: 'Senha inválida' });

    res.send({ token: generateToken(user) });
});

// Protegendo as rotas com JWT
app.get('/films', authMiddleware, async (req, res) => {
    const films = await Filme.find().populate('user');
    res.send(films);
});

app.post('/films', authMiddleware, async (req, res) => {
    const film = new Filme({
        title: req.body.title,
        description: req.body.description,
        image_url: req.body.image_url,
        trailer_url: req.body.trailer_url,
        year: req.body.year,
        user: req.userId // Associa o filme ao usuário autenticado
    });

    await film.save();
    res.send(film);
});

// Inicia o servidor e conecta ao banco
app.listen(port, () => {
    mongoose.connect('mongodb+srv://luanamartinscomin:zUsHnfzf8JSMXZyM@clusterfree.53z0c.mongodb.net/?retryWrites=true&w=majority&appName=clusterfree');
    console.log('App running');
});
