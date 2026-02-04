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
app.use(express.json({ limit: '10mb' }));

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

// ===== NUOVO ENDPOINT: Server Status =====
app.get('/api/auth/status', async (req, res) => {
    try {
        // Conta utenti totali
        const result = await pool.query('SELECT COUNT(*) as count FROM users');
        const userCount = parseInt(result.rows[0].count) || 0;
        const maxUsers = 300;
        const registrationOpen = userCount < maxUsers;
        
        res.json({
            registrationOpen,
            userCount,
            maxUsers
        });
    } catch (error) {
        console.error('Errore /api/auth/status:', error);
        // In caso di errore, assumiamo server aperto per non bloccare ingiustamente
        res.json({
            registrationOpen: true,
            userCount: 0,
            maxUsers: 300
        });
    }
});

// ===== MODIFICATO: Registrazione con limite 300 utenti =====
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Validazione input
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Campi mancanti' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password troppo corta' });
        }
        
        // ⭐ NUOVO: Controlla limite 300 utenti
        const countResult = await pool.query('SELECT COUNT(*) as count FROM users');
        const userCount = parseInt(countResult.rows[0].count) || 0;
        
        if (userCount >= 300) {
            return res.status(403).json({ 
                error: 'Server al completo. Registrazioni chiuse (300/300).' 
            });
        }
        
        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);
        
        // Crea utente
        const result = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
            [username, email, passwordHash]
        );
        
        // Crea stato gioco iniziale
        const initialState = {
            resources: {
                money: { value: 15000, rate: 0, max: 999999 },
                parts: { value: 150, rate: 0, max: 999999 },
                reputation: { value: 0, rate: 0, max: 10000 },
                energy: { value: 100, rate: 0, max: 100 }
            },
            workshop: {
                engine: { level: 0, unlocked: true },
                electronics: { level: 0, unlocked: false },
                body: { level: 0, unlocked: false },
                aerodynamics: { level: 0, unlocked: false }
            },
            ownedCars: [],
            drivers: [
                { unlocked: true },
                { unlocked: true },
                { unlocked: false },
                { unlocked: false },
                { unlocked: false }
            ],
            currentDriver: null,
            sponsors: [
                { unlocked: true },
                { unlocked: true },
                { unlocked: false },
                { unlocked: false },
                { unlocked: false },
                { unlocked: false },
                { unlocked: false },
                { unlocked: false },
                { unlocked: false },
                { unlocked: false }
            ],
            currentSponsor: null,
            technologies: [
                { id: 'turbo', researched: false },
                { id: 'carbon', researched: false },
                { id: 'ecu', researched: false },
                { id: 'aero', researched: false },
                { id: 'suspension', researched: false },
                { id: 'nitro', researched: false },
                { id: 'weight', researched: false },
                { id: 'cooling', researched: false }
            ],
            races: {
                completed: 0,
                wins: 0,
                lastRaceTime: 0,
                cooldown: 30000
            },
            championship: {
                active: false,
                currentRace: 0,
                totalRaces: 5,
                wins: 0,
                results: [],
                entryFee: 7000,
                prizePool: 5000
            },
            raceHistory: [],
            lastSaveTime: Date.now()
        };
        
        await pool.query(
            'INSERT INTO game_state (user_id, resources, workshop, owned_cars, drivers, current_driver, sponsors, current_sponsor, technologies, races, championship, race_history, last_save) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())',
            [
                result.rows[0].id,
                JSON.stringify(initialState.resources),
                JSON.stringify(initialState.workshop),
                JSON.stringify(initialState.ownedCars),
                JSON.stringify(initialState.drivers),
                JSON.stringify(initialState.currentDriver),
                JSON.stringify(initialState.sponsors),
                JSON.stringify(initialState.currentSponsor),
                JSON.stringify(initialState.technologies),
                JSON.stringify(initialState.races),
                JSON.stringify(initialState.championship),
                JSON.stringify(initialState.raceHistory)
            ]
        );
        
        console.log(`✅ Nuovo utente registrato: ${username} (${userCount + 1}/300)`);
        
        res.status(201).json({ message: 'Registrazione completata', user: result.rows[0] });
    } catch (error) {
        if (error.constraint === 'users_username_key') {
            return res.status(400).json({ error: 'Username già esistente' });
        }
        if (error.constraint === 'users_email_key') {
            return res.status(400).json({ error: 'Email già registrata' });
        }
        console.error('Errore registrazione:', error);
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
        const result = await pool.query(
            'SELECT * FROM game_state WHERE user_id = $1',
            [req.user.userId]
        );
        
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
            lastSaveTime: gameState.last_save ? new Date(gameState.last_save).getTime() : Date.now()
        });
    } catch (error) {
        console.error('Errore GET /api/game/state:', error);
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
            `UPDATE game_state SET 
                resources = $1,
                workshop = $2,
                owned_cars = $3,
                drivers = $4,
                current_driver = $5,
                sponsors = $6,
                current_sponsor = $7,
                technologies = $8,
                races = $9,
                championship = $10,
                race_history = $11,
                last_save = NOW()
             WHERE user_id = $12`,
            [
                JSON.stringify(gameState.resources),
                JSON.stringify(gameState.workshop),
                JSON.stringify(gameState.ownedCars),
                JSON.stringify(gameState.drivers),
                JSON.stringify(gameState.currentDriver),
                JSON.stringify(gameState.sponsors),
                JSON.stringify(gameState.currentSponsor),
                JSON.stringify(gameState.technologies),
                JSON.stringify(gameState.races),
                JSON.stringify(gameState.championship),
                JSON.stringify(gameState.raceHistory),
                req.user.userId
            ]
        );
        
        res.json({ success: true, timestamp: Date.now() });
    } catch (error) {
        console.error('Errore POST /api/game/state:', error);
        res.status(500).json({ error: 'Errore salvataggio' });
    }
});

app.get('/api/game/leaderboard', authenticateToken, async (req, res) => {
    try {
        const allPlayers = await pool.query(
            `SELECT u.username, 
                    COALESCE((gs.resources->'reputation'->>'value')::int, 0) as reputation
             FROM game_state gs 
             JOIN users u ON u.id = gs.user_id 
             ORDER BY reputation DESC`
        );

        const leaderboard = allPlayers.rows;
        const top20 = leaderboard.slice(0, 20);

        const currentUsername = req.user.username;
        const userIndex = leaderboard.findIndex(p => p.username === currentUsername);
        
        let userRank = null;
        if (userIndex >= 20) {
            userRank = {
                rank: userIndex + 1,
                username: currentUsername,
                reputation: leaderboard[userIndex].reputation
            };
        }

        res.json({ leaderboard: top20, userRank: userRank });

    } catch (error) {
        console.error('Errore classifica:', error);
        res.status(500).json({ error: 'Errore caricamento classifica' });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Database connected`);
});
