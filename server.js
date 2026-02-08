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

app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const passwordHash = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email', [username, email, passwordHash]);
        const initialState = {resources: {money: { value: 15000, rate: 0, max: 999999 }, parts: { value: 150, rate: 0, max: 999999 }, reputation: { value: 0, rate: 0, max: 10000 }, energy: { value: 100, rate: 0, max: 100 }}, workshop: {engine: { level: 0, unlocked: true }, electronics: { level: 0, unlocked: false }, body: { level: 0, unlocked: false }, aerodynamics: { level: 0, unlocked: false }}, ownedCars: [], drivers: [{ unlocked: true }, { unlocked: true }, { unlocked: false }, { unlocked: false }, { unlocked: false }], currentDriver: null, sponsors: [{ unlocked: true }, { unlocked: true }, { unlocked: false }, { unlocked: false }, { unlocked: false }, { unlocked: false }, { unlocked: false }, { unlocked: false }, { unlocked: false }, { unlocked: false }], currentSponsor: null, technologies: [{ id: 'turbo', researched: false }, { id: 'carbon', researched: false }, { id: 'ecu', researched: false }, { id: 'aero', researched: false }, { id: 'suspension', researched: false }, { id: 'nitro', researched: false }, { id: 'weight', researched: false }, { id: 'cooling', researched: false }], races: {completed: 0, wins: 0, lastRaceTime: 0, cooldown: 30000}, championship: {active: false, currentRace: 0, totalRaces: 5, wins: 0, results: [], entryFee: 7000, prizePool: 5000}, raceHistory: [], lastSaveTime: Date.now()};
        await pool.query('INSERT INTO game_state (user_id, resources, workshop, owned_cars, drivers, current_driver, sponsors, current_sponsor, technologies, races, championship, race_history, last_save) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())', [result.rows[0].id, JSON.stringify(initialState.resources), JSON.stringify(initialState.workshop), JSON.stringify(initialState.ownedCars), JSON.stringify(initialState.drivers), JSON.stringify(initialState.currentDriver), JSON.stringify(initialState.sponsors), JSON.stringify(initialState.currentSponsor), JSON.stringify(initialState.technologies), JSON.stringify(initialState.races), JSON.stringify(initialState.championship), JSON.stringify(initialState.raceHistory)]);
        res.status(201).json({ message: 'Registrazione completata', user: result.rows[0] });
    } catch (error) {
        if (error.constraint === 'users_username_key') return res.status(400).json({ error: 'Username già esistente' });
        if (error.constraint === 'users_email_key') return res.status(400).json({ error: 'Email già registrata' });
        console.error('Errore registrazione:', error);
        res.status(500).json({ error: 'Errore server' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Credenziali non valide' });
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Credenziali non valide' });
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
        if (result.rows.length === 0) return res.status(404).json({ error: 'Stato gioco non trovato' });
        const gameState = result.rows[0];
        res.json({resources: gameState.resources, workshop: gameState.workshop, ownedCars: gameState.owned_cars, drivers: gameState.drivers, currentDriver: gameState.current_driver, sponsors: gameState.sponsors, currentSponsor: gameState.current_sponsor, technologies: gameState.technologies, races: gameState.races, championship: gameState.championship, raceHistory: gameState.race_history, lastSaveTime: gameState.last_save ? new Date(gameState.last_save).getTime() : Date.now()});
    } catch (error) {
        console.error('Errore GET /api/game/state:', error);
        res.status(500).json({ error: 'Errore caricamento' });
    }
});

app.post('/api/game/state', authenticateToken, async (req, res) => {
    try {
        const { gameState } = req.body;
        if (!gameState || typeof gameState !== 'object') return res.status(400).json({ error: 'Dati non validi' });
        if (gameState.resources?.money?.value > 50000000) return res.status(400).json({ error: 'Valori sospetti' });
        await pool.query(`UPDATE game_state SET resources = $1, workshop = $2, owned_cars = $3, drivers = $4, current_driver = $5, sponsors = $6, current_sponsor = $7, technologies = $8, races = $9, championship = $10, race_history = $11, last_save = NOW() WHERE user_id = $12`, [JSON.stringify(gameState.resources), JSON.stringify(gameState.workshop), JSON.stringify(gameState.ownedCars), JSON.stringify(gameState.drivers), JSON.stringify(gameState.currentDriver), JSON.stringify(gameState.sponsors), JSON.stringify(gameState.currentSponsor), JSON.stringify(gameState.technologies), JSON.stringify(gameState.races), JSON.stringify(gameState.championship), JSON.stringify(gameState.raceHistory), req.user.userId]);
        res.json({ success: true, timestamp: Date.now() });
    } catch (error) {
        console.error('Errore POST /api/game/state:', error);
        res.status(500).json({ error: 'Errore salvataggio' });
    }
});

app.get('/api/game/leaderboard', authenticateToken, async (req, res) => {
    try {
        const allPlayers = await pool.query(`SELECT u.id as user_id, u.username, COALESCE((gs.resources->'reputation'->>'value')::int, 0) as reputation FROM game_state gs JOIN users u ON u.id = gs.user_id ORDER BY reputation DESC`);
        const leaderboard = allPlayers.rows;
        const top20 = leaderboard.slice(0, 20);
        const currentUsername = req.user.username;
        const userIndex = leaderboard.findIndex(p => p.username === currentUsername);
        let userRank = null;
        if (userIndex >= 20) {
            userRank = {rank: userIndex + 1, username: currentUsername, reputation: leaderboard[userIndex].reputation};
        }
        res.json({ leaderboard: top20, userRank: userRank });
    } catch (error) {
        console.error('Errore classifica:', error);
        res.status(500).json({ error: 'Errore caricamento classifica' });
    }
});

app.post('/api/pvp/challenge', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const attackerId = req.user.userId;
        const { defenderId } = req.body;
        
        if (!defenderId) {await client.query('ROLLBACK'); return res.status(400).json({ error: 'Defender ID mancante' });}
        if (attackerId === defenderId) {await client.query('ROLLBACK'); return res.status(400).json({ error: 'Non puoi sfidare te stesso' });}
        
        const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
        const existingChallenge = await client.query('SELECT * FROM pvp_challenges WHERE attacker_id = $1 AND created_at >= $2', [attackerId, todayStart]);
        if (existingChallenge.rows.length > 0) {await client.query('ROLLBACK'); return res.status(429).json({error: 'Hai già sfidato un giocatore oggi', nextChallengeTime: new Date(todayStart.getTime() + 24 * 60 * 60 * 1000).toISOString()});}
        
        const attackerResult = await client.query(`SELECT u.username, gs.* FROM users u JOIN game_state gs ON gs.user_id = u.id WHERE u.id = $1`, [attackerId]);
        if (attackerResult.rows.length === 0) {await client.query('ROLLBACK'); return res.status(404).json({ error: 'Attaccante non trovato' });}
        
        const attackerData = attackerResult.rows[0];
        const attackerUsername = attackerData.username;
        const attackerState = {
            resources: attackerData.resources,
            ownedCars: attackerData.owned_cars,
            technologies: attackerData.technologies
        };
        
        if (attackerState.resources.energy.value < 20) {await client.query('ROLLBACK'); return res.status(400).json({ error: 'Energia insufficiente (richiesta: 20)' });}
        
        const defenderResult = await client.query(`SELECT u.username, gs.* FROM users u JOIN game_state gs ON gs.user_id = u.id WHERE u.id = $1`, [defenderId]);
        if (defenderResult.rows.length === 0) {await client.query('ROLLBACK'); return res.status(404).json({ error: 'Difensore non trovato' });}
        
        const defenderData = defenderResult.rows[0];
        const defenderUsername = defenderData.username;
        const defenderState = {
            resources: defenderData.resources,
            ownedCars: defenderData.owned_cars,
            technologies: defenderData.technologies
        };
        
        if (!attackerState.ownedCars || attackerState.ownedCars.length === 0) {await client.query('ROLLBACK'); return res.status(400).json({ error: 'Devi possedere almeno un\'auto' });}
        if (!defenderState.ownedCars || defenderState.ownedCars.length === 0) {await client.query('ROLLBACK'); return res.status(400).json({ error: 'Il difensore non ha auto disponibili' });}
        
        // ✅ FIX: Usa sempre indice 0 (prima auto) invece di selected_car_index
        const attackerCar = attackerState.ownedCars[0];
        const defenderCar = defenderState.ownedCars[0];
        
        const calculatePower = (car, technologies) => {
            let power = 0;
            ['engine', 'body', 'electronics', 'aero'].forEach(stat => {
                let statValue = car.stats[stat] + (car.upgrades[stat] * 10);
                if (technologies && Array.isArray(technologies)) {
                    technologies.forEach(tech => {
                        if (tech.researched) {
                            if (tech.bonus && tech.bonus.stat === stat) {
                                statValue += tech.bonus.value;
                            } else if (tech.bonus && tech.bonus.type === 'allStats') {
                                statValue += tech.bonus.value;
                            }
                        }
                    });
                }
                power += statValue;
            });
            return power * (car.condition / 100);
        };
        
        const attackerPower = calculatePower(attackerCar, attackerState.technologies);
        const defenderPower = calculatePower(defenderCar, defenderState.technologies);
        const win = attackerPower > (defenderPower * 1.05);
        
        let rewards = win 
            ? {money: Math.floor(defenderState.resources.money.value * 0.05), parts: Math.floor(defenderState.resources.parts.value * 0.05), reputation: Math.floor(defenderState.resources.reputation.value * 0.05)} 
            : {money: Math.floor(attackerState.resources.money.value * 0.10), parts: Math.floor(attackerState.resources.parts.value * 0.10), reputation: Math.floor(attackerState.resources.reputation.value * 0.10)};
        
        if (win) {
            // Converti rewards in interi per evitare errori PostgreSQL
            const rewardMoney = Math.floor(rewards.money);
            const rewardParts = Math.floor(rewards.parts);
            const rewardRep = Math.floor(rewards.reputation);
    
            await client.query(`UPDATE game_state SET resources = jsonb_set(jsonb_set(jsonb_set(resources, '{money,value}', to_jsonb(GREATEST(0, (resources->'money'->>'value')::int - $1))), '{parts,value}', to_jsonb(GREATEST(0, (resources->'parts'->>'value')::int - $2))), '{reputation,value}', to_jsonb(GREATEST(0, (resources->'reputation'->>'value')::int - $3))) WHERE user_id = $4`, [rewardMoney, rewardParts, rewardRep, defenderId]);
            await client.query(`UPDATE game_state SET resources = jsonb_set(jsonb_set(jsonb_set(jsonb_set(resources, '{money,value}', to_jsonb((resources->'money'->>'value')::int + $1)), '{parts,value}', to_jsonb((resources->'parts'->>'value')::int + $2)), '{reputation,value}', to_jsonb((resources->'reputation'->>'value')::int + $3)), '{energy,value}', to_jsonb(GREATEST(0, (resources->'energy'->>'value')::int - 20))) WHERE user_id = $4`, [rewardMoney, rewardParts, rewardRep, attackerId]);
        } else {
        // Converti rewards in interi per evitare errori PostgreSQL
            const rewardMoney = Math.floor(rewards.money);
            const rewardParts = Math.floor(rewards.parts);
            const rewardRep = Math.floor(rewards.reputation);
    
            await client.query(`UPDATE game_state SET resources = jsonb_set(jsonb_set(jsonb_set(jsonb_set(resources, '{money,value}', to_jsonb(GREATEST(0, (resources->'money'->>'value')::int - $1))), '{parts,value}', to_jsonb(GREATEST(0, (resources->'parts'->>'value')::int - $2))), '{reputation,value}', to_jsonb(GREATEST(0, (resources->'reputation'->>'value')::int - $3))), '{energy,value}', to_jsonb(GREATEST(0, (resources->'energy'->>'value')::int - 20))) WHERE user_id = $4`, [rewardMoney, rewardParts, rewardRep, attackerId]);
            await client.query(`UPDATE game_state SET resources = jsonb_set(jsonb_set(jsonb_set(resources, '{money,value}', to_jsonb((resources->'money'->>'value')::int + $1)), '{parts,value}', to_jsonb((resources->'parts'->>'value')::int + $2)), '{reputation,value}', to_jsonb((resources->'reputation'->>'value')::int + $3)) WHERE user_id = $4`, [rewardMoney, rewardParts, rewardRep, defenderId]);
}
        
        await client.query(`INSERT INTO pvp_challenges (attacker_id, defender_id, attacker_username, defender_username, attacker_car, defender_car, attacker_power, defender_power, winner_id, rewards, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())`, [attackerId, defenderId, attackerUsername, defenderUsername, attackerCar.name, defenderCar.name, Math.floor(attackerPower), Math.floor(defenderPower), win ? attackerId : defenderId, JSON.stringify(rewards)]);
        
        await client.query('COMMIT');
        
        const updatedState = await client.query('SELECT * FROM game_state WHERE user_id = $1', [attackerId]);
        const newState = {
            resources: updatedState.rows[0].resources,
            workshop: updatedState.rows[0].workshop,
            ownedCars: updatedState.rows[0].owned_cars,
            drivers: updatedState.rows[0].drivers,
            currentDriver: updatedState.rows[0].current_driver,
            sponsors: updatedState.rows[0].sponsors,
            currentSponsor: updatedState.rows[0].current_sponsor,
            technologies: updatedState.rows[0].technologies,
            races: updatedState.rows[0].races,
            championship: updatedState.rows[0].championship,
            raceHistory: updatedState.rows[0].race_history
        };
        
        res.json({
            success: true,
            win: win,
            attacker: { username: attackerUsername, car: attackerCar.name, power: Math.floor(attackerPower) },
            defender: { username: defenderUsername, car: defenderCar.name, power: Math.floor(defenderPower) },
            rewards: rewards,
            newState: newState
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Errore PvP:', error);
        res.status(500).json({ error: 'Errore durante la sfida: ' + error.message });
    } finally {
        client.release();
    }
});

app.get('/api/pvp/can-challenge', authenticateToken, async (req, res) => {
    try {
        const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
        const result = await pool.query('SELECT created_at FROM pvp_challenges WHERE attacker_id = $1 AND created_at >= $2 ORDER BY created_at DESC LIMIT 1', [req.user.userId, todayStart]);
        const canChallenge = result.rows.length === 0;
        res.json({canChallenge: canChallenge, nextChallengeTime: canChallenge ? null : new Date(todayStart.getTime() + 24 * 60 * 60 * 1000), lastChallengeTime: result.rows.length > 0 ? result.rows[0].created_at : null});
    } catch (error) {
        console.error('Errore can-challenge:', error);
        res.status(500).json({ error: 'Errore controllo sfida' });
    }
});

app.get('/health', (req, res) => { res.json({ status: 'ok', timestamp: new Date().toISOString() }); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => { console.log(`🚀 Server running on port ${PORT}`); console.log(`📊 Database connected`); });
