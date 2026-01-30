const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || '*',
    credentials: true
}));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});

app.use(limiter);
app.use(express.json());

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Token mancante' });
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token non valido' });
        }
        req.user = user;
        next();
    });
}

app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Campi mancanti' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password troppo corta' });
        }
        const passwordHash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
            [username, email, passwordHash]
        );
        const initialState = {
            resources: { money: { value: 15000 }, parts: { value: 150 }, reputation: { value: 0 }, energy: { value: 100 } },
            workshop: { engine: { level: 0, unlocked: true }, electronics: { level: 0, unlocked: false }, body: { level: 0, unlocked: false }, aerodynamics: { level: 0, unlocked: false } },
            owned_cars: [],
            races: { completed: 0, wins: 0 },
            race_history: []
        };
        await pool.query(
            'INSERT INTO game_state (user_id, resources, workshop, owned_cars, races, race_history) VALUES ($1, $2, $3, $4, $5, $6)',
            [result.rows[0].id, JSON.stringify(initialState.resources), JSON.stringify(initialState.workshop), JSON.stringify(initialState.owned_cars), JSON.stringify(initialState.races), JSON.stringify(initialState.race_history)]
        );
        res.status(201).json({ message: 'Registrazione completata', user: result.rows[0] });
    } catch (error) {
        if (error.constraint === 'users_username_key') {
            return res.status(400).json({ error: 'Username già esistente' });
        }
        if (error.constraint === 'users_email_key') {
            return res.status(400).json({ error: 'Email già registrata' });
        }
        console.error(error);
        res.status(500).json({ error: 'Errore server' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Credenziali non valide' });
        }
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Credenziali non valide' });
        }
        await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
        const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Errore server' });
    }
});

app.get('/api/game/state', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM game_state WHERE user_id = $1', [req.user.userId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Stato gioco non trovato' });
        }
        const gameState = result.rows[0];
        res.json({
            resources: gameState.resources,
            workshop: gameState.workshop,
            ownedCars: gameState.owned_cars,
            drivers: gameState.drivers,
            currentDriver: gameState.current_driver,
            sponsors: gameState.sponsors,
            currentSponsor: gameState.current_sponsor,
            technologies: gameState.technologies,
            races: gameState.races,
            championship: gameState.championship,
            raceHistory: gameState.race_history,
            lastSave: gameState.last_save
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Errore caricamento' });
    }
});

app.post('/api/game/state', authenticateToken, async (req, res) => {
    try {
        const { gameState } = req.body;
        if (!gameState || typeof gameState !== 'object') {
            return res.status(400).json({ error: 'Dati non validi' });
        }
        if (gameState.resources?.money?.value > 50000000) {
            return res.status(400).json({ error: 'Valori sospetti' });
        }
        await pool.query(
            'UPDATE game_state SET resources = $1, workshop = $2, owned_cars = $3, drivers = $4, current_driver = $5, sponsors = $6, current_sponsor = $7, technologies = $8, races = $9, championship = $10, race_history = $11, last_save = NOW() WHERE user_id = $12',
            [JSON.stringify(gameState.resources), JSON.stringify(gameState.workshop), JSON.stringify(gameState.ownedCars), JSON.stringify(gameState.drivers), JSON.stringify(gameState.currentDriver), JSON.stringify(gameState.sponsors), JSON.stringify(gameState.currentSponsor), JSON.stringify(gameState.technologies), JSON.stringify(gameState.races), JSON.stringify(gameState.championship), JSON.stringify(gameState.raceHistory), req.user.userId]
        );
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Errore salvataggio' });
    }
});

app.get('/api/game/leaderboard', async (req, res) => {
    try {
        const result = await pool.query("SELECT u.username, (gs.races->>'wins')::int as wins, (gs.races->>'completed')::int as completed, (gs.resources->'reputation'->>'value')::int as reputation FROM game_state gs JOIN users u ON u.id = gs.user_id ORDER BY reputation DESC LIMIT 100");
        res.json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Errore classifica' });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
