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

// =====================================================
// FUNZIONI SICUREZZA
// =====================================================

// 1. VALIDAZIONE RIGOROSA RISORSE
function validateResources(resources, previousResources) {
    const MAX_VALUES = {
        money: 100000000,
        parts: 1000000,
        reputation: 10000,
        energy: 100
    };
    
    const MAX_GAIN_PER_SAVE = {
        money: 50000,
        parts: 5000,
        reputation: 500,
        energy: 100
    };
    
    for (const key of ['money', 'parts', 'reputation', 'energy']) {
        const current = resources[key]?.value || 0;
        const previous = previousResources[key]?.value || 0;
        const gain = current - previous;
        
        if (current > MAX_VALUES[key]) {
            return { valid: false, reason: `${key} troppo alto: ${current}` };
        }
        
        if (gain > MAX_GAIN_PER_SAVE[key]) {
            return { valid: false, reason: `Incremento ${key} sospetto: +${gain}` };
        }
        
        if (current < 0) {
            return { valid: false, reason: `${key} negativo` };
        }
    }
    
    return { valid: true };
}

// 2. VALIDAZIONE LOGICA GAMEPLAY
function validateGameLogic(newState, oldState) {
    if (newState.races?.wins > newState.races?.completed) {
        return { valid: false, reason: 'Wins > completed races' };
    }
    
    if (newState.workshop) {
        for (const section of Object.values(newState.workshop)) {
            if (section.level > 10) {
                return { valid: false, reason: 'Workshop level > 10' };
            }
        }
    }
    
    if (newState.trackTraining) {
        for (const training of Object.values(newState.trackTraining)) {
            if (training.level > 10) {
                return { valid: false, reason: 'Training level > 10' };
            }
        }
    }
    
    if (newState.ownedCars?.length > 50) {
        return { valid: false, reason: 'Too many cars' };
    }
    
    return { valid: true };
}

// 3. RATE LIMITING PER UTENTE
const userSaveTimestamps = new Map();

function checkUserRateLimit(userId) {
    const now = Date.now();
    const userHistory = userSaveTimestamps.get(userId) || [];
    const recentSaves = userHistory.filter(t => now - t < 60000);
    
    if (recentSaves.length >= 30) {
        return { allowed: false, reason: 'Too many saves per minute' };
    }
    
    recentSaves.push(now);
    userSaveTimestamps.set(userId, recentSaves);
    return { allowed: true };
}

// 4. LOGGING ATTIVITÀ SOSPETTE
async function logSuspiciousActivity(userId, reason, data) {
    console.warn(`⚠️ SUSPICIOUS: User ${userId} - ${reason}`, data);
    
    try {
        await pool.query(
            'INSERT INTO suspicious_logs (user_id, reason, data, created_at) VALUES ($1, $2, $3, NOW())',
            [userId, reason, JSON.stringify(data)]
        );
    } catch (err) {
        // Ignora se tabella non esiste
    }
}

// =====================================================
// MIDDLEWARE AUTENTICAZIONE
// =====================================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token mancante' });
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token non valido' });
        req.user = user;
        next();
    });
}

// =====================================================
// ENDPOINTS AUTENTICAZIONE
// =====================================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const passwordHash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
            [username, email, passwordHash]
        );
        
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
                { unlocked: true }, { unlocked: true }, { unlocked: false },
                { unlocked: false }, { unlocked: false }
            ],
            currentDriver: null,
            sponsors: [
                { unlocked: true }, { unlocked: true }, { unlocked: false },
                { unlocked: false }, { unlocked: false }, { unlocked: false },
                { unlocked: false }, { unlocked: false }, { unlocked: false },
                { unlocked: false }
            ],
            currentSponsor: null,
            technologies: [
                { id: 'turbo', researched: false }, { id: 'carbon', researched: false },
                { id: 'ecu', researched: false }, { id: 'aero', researched: false },
                { id: 'suspension', researched: false }, { id: 'nitro', researched: false },
                { id: 'weight', researched: false }, { id: 'cooling', researched: false }
            ],
            races: { completed: 0, wins: 0, lastRaceTime: 0, cooldown: 30000 },
            championship: {
                active: false, currentRace: 0, totalRaces: 5, wins: 0, results: [],
                entryFee: 500, prizePool: 10000
            },
            raceHistory: [],
            trackTraining: {
                engine: { level: 0 }, electronics: { level: 0 },
                body: { level: 0 }, aero: { level: 0 },
                money: { level: 0 }, parts: { level: 0 }
            },
            trackQueue: null,
            missions: {
                races200: { progress: 0, completed: false },
                wins100: { progress: 0, completed: false },
                losses100: { progress: 0, completed: false },
                training60: { progress: 0, completed: false },
                allTech: { progress: 0, completed: false },
                pvp50: { progress: 0, completed: false },
                cars10: { progress: 0, completed: false },
                reputation1000: { progress: 0, completed: false },
                upgrades100: { progress: 0, completed: false },
                championship10: { progress: 0, completed: false }
            },
            pvpStats: { wins: 0, losses: 0, total: 0 },
            upgradesCount: 0,
            championshipsWon: 0,
            eventProgress: {},
            lastSaveTime: Date.now()
        };
        
        await pool.query(`
            INSERT INTO game_state (
                user_id, resources, workshop, owned_cars, drivers, current_driver,
                sponsors, current_sponsor, technologies, races, championship, race_history,
                track_training, track_queue, missions, pvp_stats, upgrades_count, championships_won,
                event_progress, reputation_weekly, last_save
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, NOW())
        `, [
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
            JSON.stringify(initialState.raceHistory),
            JSON.stringify(initialState.trackTraining),
            JSON.stringify(initialState.trackQueue),
            JSON.stringify(initialState.missions),
            JSON.stringify(initialState.pvpStats),
            0, 0,
            JSON.stringify(initialState.eventProgress),
            0
        ]);
        
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
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            token,
            user: { id: user.id, username: user.username, email: user.email }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Errore server' });
    }
});

// =====================================================
// ENDPOINTS GAME STATE (CON VALIDAZIONE SICURA)
// =====================================================

app.get('/api/game/state', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM game_state WHERE user_id = $1', [req.user.userId]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Stato gioco non trovato' });
        
        const gs = result.rows[0];
        res.json({
            resources: gs.resources,
            workshop: gs.workshop,
            ownedCars: gs.owned_cars,
            drivers: gs.drivers,
            currentDriver: gs.current_driver,
            sponsors: gs.sponsors,
            currentSponsor: gs.current_sponsor,
            technologies: gs.technologies,
            races: gs.races,
            championship: gs.championship,
            raceHistory: gs.race_history,
            trackTraining: gs.track_training || {
                engine: {level:0}, electronics: {level:0}, body: {level:0},
                aero: {level:0}, money: {level:0}, parts: {level:0}
            },
            trackQueue: gs.track_queue || null,
            missions: gs.missions || {},
            pvpStats: gs.pvp_stats || { wins: 0, losses: 0, total: 0 },
            upgradesCount: gs.upgrades_count || 0,
            championshipsWon: gs.championships_won || 0,
            eventProgress: gs.event_progress || {},
            lastSaveTime: gs.last_save ? new Date(gs.last_save).getTime() : Date.now()
        });
    } catch (error) {
        console.error('Errore GET /api/game/state:', error);
        res.status(500).json({ error: 'Errore caricamento' });
    }
});

// ✅ ENDPOINT SALVATAGGIO CON VALIDAZIONE COMPLETA
app.post('/api/game/state', authenticateToken, async (req, res) => {
    try {
        const { gameState } = req.body;
        const userId = req.user.userId;
        
        if (!gameState || typeof gameState !== 'object') {
            return res.status(400).json({ error: 'Dati non validi' });
        }
        
        // 1. Rate limiting per utente
        const rateLimitCheck = checkUserRateLimit(userId);
        if (!rateLimitCheck.allowed) {
            await logSuspiciousActivity(userId, 'Rate limit exceeded', { saves: 30 });
            return res.status(429).json({ error: 'Troppi salvataggi. Aspetta 1 minuto.' });
        }
        
        // 2. Carica stato precedente
        const previousResult = await pool.query(
            'SELECT * FROM game_state WHERE user_id = $1',
            [userId]
        );
        
        if (previousResult.rows.length === 0) {
            return res.status(404).json({ error: 'Stato precedente non trovato' });
        }
        
        const previousState = previousResult.rows[0];
        
        // 3. Validazione risorse
        const resourceValidation = validateResources(
            gameState.resources,
            previousState.resources
        );
        
        if (!resourceValidation.valid) {
            await logSuspiciousActivity(userId, 'Resource validation failed', {
                reason: resourceValidation.reason,
                newMoney: gameState.resources.money?.value,
                oldMoney: previousState.resources.money?.value,
                newParts: gameState.resources.parts?.value,
                oldParts: previousState.resources.parts?.value
            });
            return res.status(400).json({ error: 'Valori non validi: ' + resourceValidation.reason });
        }
        
        // 4. Validazione logica gameplay
        const logicValidation = validateGameLogic(gameState, previousState);
        
        if (!logicValidation.valid) {
            await logSuspiciousActivity(userId, 'Logic validation failed', {
                reason: logicValidation.reason
            });
            return res.status(400).json({ error: 'Dati incongruenti: ' + logicValidation.reason });
        }
        
        // 5. Salva se tutto OK
        await pool.query(`
            UPDATE game_state SET
                resources = $1, workshop = $2, owned_cars = $3, drivers = $4, current_driver = $5,
                sponsors = $6, current_sponsor = $7, technologies = $8, races = $9, championship = $10,
                race_history = $11, track_training = $12, track_queue = $13, missions = $14,
                pvp_stats = $15, upgrades_count = $16, championships_won = $17, event_progress = $18, last_save = NOW()
            WHERE user_id = $19
        `, [
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
            JSON.stringify(gameState.trackTraining || {}),
            JSON.stringify(gameState.trackQueue || null),
            JSON.stringify(gameState.missions || {}),
            JSON.stringify(gameState.pvpStats || {}),
            gameState.upgradesCount || 0,
            gameState.championshipsWon || 0,
            JSON.stringify(gameState.eventProgress || {}),
            userId
        ]);
        
        res.json({ success: true, timestamp: Date.now() });
        
    } catch (error) {
        console.error('Errore POST /api/game/state:', error);
        res.status(500).json({ error: 'Errore salvataggio' });
    }
});

// =====================================================
// ENDPOINTS CLASSIFICHE
// =====================================================

app.get('/api/game/leaderboard', authenticateToken, async (req, res) => {
    try {
        const allPlayers = await pool.query(`
            SELECT u.id as user_id, u.username,
                   COALESCE((gs.resources->'reputation'->>'value')::int, 0) as reputation
            FROM game_state gs
            JOIN users u ON u.id = gs.user_id
            ORDER BY reputation DESC
        `);
        
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
        
        res.json({ leaderboard: top20, userRank });
    } catch (error) {
        console.error('Errore classifica:', error);
        res.status(500).json({ error: 'Errore caricamento classifica' });
    }
});

app.get('/api/game/leaderboard-weekly', authenticateToken, async (req, res) => {
    try {
        const now = new Date();
        const currentDay = now.getDay();
        const daysToMonday = currentDay === 0 ? 6 : currentDay - 1;
        
        const weekStart = new Date(now);
        weekStart.setDate(now.getDate() - daysToMonday);
        weekStart.setHours(8, 0, 0, 0);
        
        if (now < weekStart) weekStart.setDate(weekStart.getDate() - 7);
        
        const firstWeek = new Date('2026-02-17T08:00:00Z');
        const weekNumber = Math.floor((weekStart - firstWeek) / (7 * 24 * 60 * 60 * 1000)) + 1;
        
        const allPlayers = await pool.query(`
            SELECT u.id as user_id, u.username,
                   COALESCE(gs.reputation_weekly, 0) as reputation
            FROM game_state gs
            JOIN users u ON u.id = gs.user_id
            ORDER BY reputation DESC
            LIMIT 100
        `);
        
        const leaderboard = allPlayers.rows;
        const top20 = leaderboard.slice(0, 20);
        
        const winnersResult = await pool.query(`
            SELECT week_number, first_place, second_place, third_place
            FROM weekly_winners
            ORDER BY week_number DESC
            LIMIT 1
        `);
        
        const lastWinners = winnersResult.rows.length > 0 ? winnersResult.rows[0] : null;
        
        res.json({
            weekNumber,
            weekStart: weekStart.toISOString(),
            leaderboard: top20,
            lastWinners
        });
    } catch (error) {
        console.error('Errore classifica settimanale:', error);
        res.status(500).json({ error: 'Errore caricamento classifica settimanale' });
    }
});

// =====================================================
// ENDPOINTS PVP
// =====================================================

app.post('/api/pvp/challenge', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const attackerId = req.user.userId;
        const { defenderId } = req.body;
        
        if (!defenderId) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Defender ID mancante' });
        }
        if (attackerId === defenderId) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Non puoi sfidare te stesso' });
        }
        
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);
        const existingChallenges = await client.query(
            'SELECT * FROM pvp_challenges WHERE attacker_id = $1 AND created_at >= $2',
            [attackerId, todayStart]
        );
        
        if (existingChallenges.rows.length >= 3) {
            await client.query('ROLLBACK');
            return res.status(429).json({
                error: 'Hai esaurito le sfide giornaliere (3/3)',
                challengesUsed: existingChallenges.rows.length,
                challengesMax: 3,
                nextChallengeTime: new Date(todayStart.getTime() + 24 * 60 * 60 * 1000).toISOString()
            });
        }
        
        const attackerResult = await client.query(`
            SELECT u.username, gs.*
            FROM users u
            JOIN game_state gs ON gs.user_id = u.id
            WHERE u.id = $1
        `, [attackerId]);
        
        if (attackerResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Attaccante non trovato' });
        }
        
        const attackerData = attackerResult.rows[0];
        const attackerUsername = attackerData.username;
        const attackerState = {
            resources: attackerData.resources,
            ownedCars: attackerData.owned_cars,
            technologies: attackerData.technologies,
            trackTraining: attackerData.track_training || {}
        };
        
        if (attackerState.resources.energy.value < 20) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Energia insufficiente (richiesta: 20)' });
        }
        
        const defenderResult = await client.query(`
            SELECT u.username, gs.*
            FROM users u
            JOIN game_state gs ON gs.user_id = u.id
            WHERE u.id = $1
        `, [defenderId]);
        
        if (defenderResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Difensore non trovato' });
        }
        
        const defenderData = defenderResult.rows[0];
        const defenderUsername = defenderData.username;
        const defenderState = {
            resources: defenderData.resources,
            ownedCars: defenderData.owned_cars,
            technologies: defenderData.technologies,
            trackTraining: defenderData.track_training || {}
        };
        
        if (!attackerState.ownedCars || attackerState.ownedCars.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Devi possedere almeno un\'auto' });
        }
        if (!defenderState.ownedCars || defenderState.ownedCars.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Il difensore non ha auto disponibili' });
        }
        
        const attackerCar = attackerState.ownedCars[0];
        const defenderCar = defenderState.ownedCars[0];
        
        const calculatePower = (car, technologies, trackTraining) => {
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
                
                if (trackTraining && trackTraining[stat]) {
                    statValue += trackTraining[stat].level || 0;
                }
                
                power += statValue;
            });
            return power * (car.condition / 100);
        };
        
        const attackerPower = calculatePower(attackerCar, attackerState.technologies, attackerState.trackTraining);
        const defenderPower = calculatePower(defenderCar, defenderState.technologies, defenderState.trackTraining);
        const win = attackerPower > (defenderPower * 1.05);
        
        const attackerMoney = parseInt(attackerState.resources.money.value) || 0;
        const attackerParts = parseInt(attackerState.resources.parts.value) || 0;
        const attackerRep = parseInt(attackerState.resources.reputation.value) || 0;
        const attackerEnergy = parseInt(attackerState.resources.energy.value) || 0;
        const defenderMoney = parseInt(defenderState.resources.money.value) || 0;
        const defenderParts = parseInt(defenderState.resources.parts.value) || 0;
        const defenderRep = parseInt(defenderState.resources.reputation.value) || 0;
        
        let rewardMoney, rewardParts, rewardRep;
        
        if (win) {
            rewardMoney = Math.floor(defenderMoney * 0.05);
            rewardParts = Math.floor(defenderParts * 0.05);
            rewardRep = Math.floor(defenderRep * 0.05);
            
            const newDefenderMoney = Math.max(0, defenderMoney - rewardMoney);
            const newDefenderParts = Math.max(0, defenderParts - rewardParts);
            const newDefenderRep = Math.max(0, defenderRep - rewardRep);
            const newAttackerMoney = attackerMoney + rewardMoney;
            const newAttackerParts = attackerParts + rewardParts;
            const newAttackerRep = Math.min(10000, attackerRep + rewardRep);
            const newAttackerEnergy = Math.max(0, attackerEnergy - 20);
            
            await client.query(`
                UPDATE game_state SET
                    resources = jsonb_set(
                        jsonb_set(
                            jsonb_set(resources, '{money,value}', ($1)::int::text::jsonb),
                            '{parts,value}', ($2)::int::text::jsonb
                        ),
                        '{reputation,value}', ($3)::int::text::jsonb
                    )
                WHERE user_id = $4
            `, [newDefenderMoney, newDefenderParts, newDefenderRep, defenderId]);
            
            await client.query(`
                UPDATE game_state SET
                    resources = jsonb_set(
                        jsonb_set(
                            jsonb_set(
                                jsonb_set(resources, '{money,value}', ($1)::int::text::jsonb),
                                '{parts,value}', ($2)::int::text::jsonb
                            ),
                            '{reputation,value}', ($3)::int::text::jsonb
                        ),
                        '{energy,value}', ($4)::int::text::jsonb
                    ),
                    reputation_weekly = COALESCE(reputation_weekly, 0) + $6
                WHERE user_id = $5
            `, [newAttackerMoney, newAttackerParts, newAttackerRep, newAttackerEnergy, attackerId, rewardRep]);
            
        } else {
            rewardMoney = Math.floor(attackerMoney * 0.10);
            rewardParts = Math.floor(attackerParts * 0.10);
            rewardRep = Math.floor(attackerRep * 0.10);
            
            const newAttackerMoney = Math.max(0, attackerMoney - rewardMoney);
            const newAttackerParts = Math.max(0, attackerParts - rewardParts);
            const newAttackerRep = Math.max(0, attackerRep - rewardRep);
            const newAttackerEnergy = Math.max(0, attackerEnergy - 20);
            const newDefenderMoney = defenderMoney + rewardMoney;
            const newDefenderParts = defenderParts + rewardParts;
            const newDefenderRep = Math.min(10000, defenderRep + rewardRep);
            
            await client.query(`
                UPDATE game_state SET
                    resources = jsonb_set(
                        jsonb_set(
                            jsonb_set(
                                jsonb_set(resources, '{money,value}', ($1)::int::text::jsonb),
                                '{parts,value}', ($2)::int::text::jsonb
                            ),
                            '{reputation,value}', ($3)::int::text::jsonb
                        ),
                        '{energy,value}', ($4)::int::text::jsonb
                    ),
                    reputation_weekly = GREATEST(0, COALESCE(reputation_weekly, 0) - $6)
                WHERE user_id = $5
            `, [newAttackerMoney, newAttackerParts, newAttackerRep, newAttackerEnergy, attackerId, rewardRep]);
            
            await client.query(`
                UPDATE game_state SET
                    resources = jsonb_set(
                        jsonb_set(
                            jsonb_set(resources, '{money,value}', ($1)::int::text::jsonb),
                            '{parts,value}', ($2)::int::text::jsonb
                        ),
                        '{reputation,value}', ($3)::int::text::jsonb
                    ),
                    reputation_weekly = COALESCE(reputation_weekly, 0) + $5
                WHERE user_id = $4
            `, [newDefenderMoney, newDefenderParts, newDefenderRep, defenderId, rewardRep]);
        }
        
        const rewards = {
            money: win ? rewardMoney : -rewardMoney,
            parts: win ? rewardParts : -rewardParts,
            reputation: win ? rewardRep : -rewardRep
        };
        
        await client.query(`
            INSERT INTO pvp_challenges (
                attacker_id, defender_id, attacker_username, defender_username,
                attacker_car, defender_car, attacker_power, defender_power,
                winner_id, rewards, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
        `, [
            attackerId, defenderId, attackerUsername, defenderUsername,
            attackerCar.name, defenderCar.name,
            Math.floor(attackerPower), Math.floor(defenderPower),
            win ? attackerId : defenderId,
            JSON.stringify(rewards)
        ]);
        
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
            raceHistory: updatedState.rows[0].race_history,
            trackTraining: updatedState.rows[0].track_training,
            trackQueue: updatedState.rows[0].track_queue,
            missions: updatedState.rows[0].missions,
            pvpStats: updatedState.rows[0].pvp_stats
        };
        
        res.json({
            success: true,
            victory: win,
            attackerPower: Math.floor(attackerPower),
            defenderPower: Math.floor(defenderPower),
            defenderCar: defenderCar,
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
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);
        
        const result = await pool.query(
            'SELECT created_at FROM pvp_challenges WHERE attacker_id = $1 AND created_at >= $2 ORDER BY created_at DESC',
            [req.user.userId, todayStart]
        );
        
        const challengesUsed = result.rows.length;
        const canChallenge = challengesUsed < 3;
        
        res.json({
            canChallenge,
            challengesUsed,
            challengesMax: 3,
            nextChallengeTime: canChallenge ? null : new Date(todayStart.getTime() + 24 * 60 * 60 * 1000),
            lastChallengeTime: result.rows.length > 0 ? result.rows[0].created_at : null
        });
    } catch (error) {
        console.error('Errore can-challenge:', error);
        res.status(500).json({ error: 'Errore controllo sfida' });
    }
});

// =====================================================
// RESET SETTIMANALE
// =====================================================

async function checkWeeklyReset() {
    try {
        const now = new Date();
        const isMonday = now.getDay() === 1;
        const hour = now.getHours();
        const minute = now.getMinutes();
        
        if (isMonday && hour === 8 && minute === 0) {
            console.log('🏆 Reset settimanale in corso...');
            
            const top3Result = await pool.query(`
                SELECT user_id, reputation_weekly, u.username
                FROM game_state gs
                JOIN users u ON u.id = gs.user_id
                ORDER BY reputation_weekly DESC
                LIMIT 3
            `);
            
            if (top3Result.rows.length > 0) {
                const weekNumber = Math.floor((now - new Date('2026-02-17T08:00:00Z')) / (7 * 24 * 60 * 60 * 1000)) + 1;
                
                await pool.query(`
                    INSERT INTO weekly_winners (week_number, first_place, second_place, third_place)
                    VALUES ($1, $2, $3, $4)
                `, [
                    weekNumber,
                    top3Result.rows[0]?.username || null,
                    top3Result.rows[1]?.username || null,
                    top3Result.rows[2]?.username || null
                ]);
                
                if (top3Result.rows[0]) {
                    await pool.query(`
                        UPDATE game_state SET
                            resources = jsonb_set(
                                jsonb_set(resources, '{money,value}',
                                    (((resources->'money'->>'value')::int + 5000)::text)::jsonb
                                ),
                                '{reputation,value}',
                                (LEAST(10000, ((resources->'reputation'->>'value')::int + 500))::text)::jsonb
                            )
                        WHERE user_id = $1
                    `, [top3Result.rows[0].user_id]);
                }
                
                if (top3Result.rows[1]) {
                    await pool.query(`
                        UPDATE game_state SET
                            resources = jsonb_set(
                                jsonb_set(resources, '{money,value}',
                                    (((resources->'money'->>'value')::int + 3000)::text)::jsonb
                                ),
                                '{reputation,value}',
                                (LEAST(10000, ((resources->'reputation'->>'value')::int + 300))::text)::jsonb
                            )
                        WHERE user_id = $1
                    `, [top3Result.rows[1].user_id]);
                }
                
                if (top3Result.rows[2]) {
                    await pool.query(`
                        UPDATE game_state SET
                            resources = jsonb_set(
                                jsonb_set(resources, '{money,value}',
                                    (((resources->'money'->>'value')::int + 1000)::text)::jsonb
                                ),
                                '{reputation,value}',
                                (LEAST(10000, ((resources->'reputation'->>'value')::int + 100))::text)::jsonb
                            )
                        WHERE user_id = $1
                    `, [top3Result.rows[2].user_id]);
                }
            }
            
            await pool.query('UPDATE game_state SET reputation_weekly = 0');
            console.log('✅ Reset settimanale completato');
        }
    } catch (error) {
        console.error('❌ Errore reset settimanale:', error);
    }
}

setInterval(checkWeeklyReset, 60000);

// =====================================================
// HEALTH CHECK
// =====================================================

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// =====================================================
// START SERVER
// =====================================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Database connected`);
    console.log(`🏆 Weekly reset scheduler active`);
    console.log(`🔒 Security validations enabled`);
});
