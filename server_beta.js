// =====================================================
// SERVER_BETA.JS - API Simulatore COMPLETO
// =====================================================

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

// Dipendenze iniettate dal server principale
let authenticateToken = null;
let pool = null;

// Carica circuiti
const circuitsPath = path.join(__dirname, 'beta_circuits.json');
let circuits = [];
try {
    const fileContent = fs.readFileSync(circuitsPath, 'utf8');
    circuits = JSON.parse(fileContent).circuits;
    console.log('✅ Circuiti beta caricati:', circuits.length);
} catch (error) {
    console.error('❌ Errore caricamento circuiti:', error.message);
}

// Funzione per ottenere circuito settimanale
const getWeeklyCircuit = () => {
    const now = new Date();
    const weekNumber = Math.floor((now - new Date(now.getFullYear(), 0, 1)) / 604800000);
    const index = weekNumber % circuits.length;
    return circuits[index];
};

// Calcola numero settimana
const getWeekNumber = () => {
    const now = new Date();
    return Math.floor((now - new Date(now.getFullYear(), 0, 1)) / 604800000);
};

// =====================================================
// GET /api/beta/weekly-challenge
// =====================================================
router.get('/weekly-challenge', (req, res, next) => {
    if (!authenticateToken) return res.status(500).json({ error: 'Auth not initialized' });
    authenticateToken(req, res, next);
}, async (req, res) => {
    try {
        const userId = req.user?.userId;
        const circuit = getWeeklyCircuit();
        const weekNumber = getWeekNumber();

        let hasRaced = false;
        let result = null;
        let leaderboard = [];

        try {
            // Controlla se ha già corso
            const resultCheck = await pool.query(`
                SELECT total_time, best_lap, position, dnf, dnf_lap
                FROM beta_race_results
                WHERE user_id = $1 AND week_number = $2
            `, [userId, weekNumber]);

            hasRaced = resultCheck.rows.length > 0;
            
            if (hasRaced) {
                const r = resultCheck.rows[0];
                result = {
                    totalTime: parseFloat(r.total_time) || 0,
                    bestLap: parseFloat(r.best_lap),
                    position: r.position,
                    dnf: r.dnf,
                    dnfLap: r.dnf_lap,
                    reward: { money: 0, parts: 0 }
                };
            }

            // Classifica
            const leaderboardResult = await pool.query(`
                SELECT 
                    u.username,
                    u.id as user_id,
                    brr.total_time,
                    brr.best_lap,
                    brr.car_name
                FROM beta_race_results brr
                JOIN users u ON u.id = brr.user_id
                WHERE brr.week_number = $1 AND brr.dnf = FALSE
                ORDER BY brr.total_time ASC
                LIMIT 50
            `, [weekNumber]);

            leaderboard = leaderboardResult.rows.map(r => ({
                username: r.username,
                userId: r.user_id,
                totalTime: parseFloat(r.total_time),
                bestLap: parseFloat(r.best_lap),
                carName: r.car_name
            }));
        } catch (dbError) {
            console.error('⚠️ Errore DB (tabella potrebbe non esistere):', dbError.message);
            // Continua senza dati DB
        }

        res.json({ circuit, hasRaced, result, leaderboard });

    } catch (error) {
        console.error('❌ Errore weekly-challenge:', error);
        res.status(500).json({ error: error.message });
    }
});

// =====================================================
// POST /api/beta/run-simulation
// =====================================================
router.post('/run-simulation', (req, res, next) => {
    if (!authenticateToken) return res.status(500).json({ error: 'Auth not initialized' });
    authenticateToken(req, res, next);
}, async (req, res) => {
    try {
        const userId = req.user?.userId;
        const { carIndex, setup } = req.body;
        const weekNumber = getWeekNumber();

        // Controlla se ha già corso (se tabella esiste)
        try {
            const existingResult = await pool.query(`
                SELECT id FROM beta_race_results WHERE user_id = $1 AND week_number = $2
            `, [userId, weekNumber]);
            
            if (existingResult.rows.length > 0) {
                return res.status(400).json({ error: 'Hai già corso questa settimana!' });
            }
        } catch (dbError) {
            console.error('⚠️ Tabella beta_race_results non esiste ancora. Crearla su Supabase!');
            // Continua comunque (per testare)
        }

        // Carica auto dal DB
        const gameStateResult = await pool.query('SELECT game_state FROM game_state WHERE user_id = $1', [userId]);
        const gameState = gameStateResult.rows[0]?.game_state || {};
        const ownedCars = gameState.ownedCars || [];
        
        if (!ownedCars[carIndex]) {
            return res.status(400).json({ error: 'Auto non trovata' });
        }
        
        const car = ownedCars[carIndex];
        const power = (car.stats.engine + car.stats.electronics + car.stats.body + car.stats.aero) || 350;
        const circuit = getWeeklyCircuit();
        
        // CALCOLO FISICA
        const baseWeight = 1000 + (car.stats.body * 2);
        let maxSpeed = (power / (baseWeight + setup.fuel)) * 200;
        maxSpeed -= setup.downforce * 0.5;
        if (setup.gearRatio === 'short') maxSpeed -= 10;
        if (setup.gearRatio === 'long') maxSpeed += 10;
        
        let grip = 1.0;
        if (setup.tires === 'soft') grip = 1.05;
        if (setup.tires === 'hard') grip = 0.98;
        grip += (2.2 - setup.tirePressure) * 0.05;
        
        let fuelPerLap = 2.5;
        fuelPerLap += circuit.tightCorners * 0.15;
        fuelPerLap += setup.downforce * 0.02;
        if (setup.tires === 'soft') fuelPerLap *= 1.1;
        if (setup.engineMap === 'power') fuelPerLap *= 1.15;
        if (setup.engineMap === 'eco') fuelPerLap *= 0.9;
        
        let tireWearPerLap = setup.tires === 'soft' ? 0.005 : setup.tires === 'hard' ? 0.002 : 0.003;
        tireWearPerLap += circuit.tightCorners * 0.0005;
        
        // Simula gara
        let totalTime = 0;
        let bestLap = 999;
        let fuel = setup.fuel;
        let tireWear = 0;
        let dnf = false;
        let dnfLap = 0;
        
        for (let lap = 1; lap <= circuit.laps; lap++) {
            if (fuel < fuelPerLap) {
                dnf = true;
                dnfLap = lap;
                break;
            }
            
            const currentGrip = grip * (1 - tireWear);
            const currentWeight = baseWeight + fuel;
            
            let lapTime = 60 + Math.random() * 5;
            lapTime *= (circuit.length / 5000);
            lapTime *= (1200 / currentWeight);
            lapTime *= (1 / currentGrip);
            lapTime += (100 - setup.downforce) * 0.05;
            lapTime -= maxSpeed * 0.01;
            
            if (circuit.bumps >= 3 && setup.suspension === -30) {
                lapTime += 0.5;
            }
            
            totalTime += lapTime;
            if (lapTime < bestLap) bestLap = lapTime;
            
            fuel -= fuelPerLap;
            tireWear += tireWearPerLap;
        }
        
        // Calcola posizione
        const avgTime = (circuit.length / 1000) * circuit.laps * 70;
        const variance = (totalTime - avgTime) / avgTime;
        let position = Math.floor(25 + variance * 50);
        position = Math.max(1, Math.min(50, position));
        
        // Premi
        let reward = { money: 0, parts: 0 };
        if (!dnf) {
            if (position === 1) reward = { money: 50000, parts: 1000 };
            else if (position === 2) reward = { money: 30000, parts: 600 };
            else if (position === 3) reward = { money: 15000, parts: 300 };
            else if (position <= 10) reward = { money: 5000, parts: 100 };
            else if (position <= 50) reward = { money: 1000, parts: 50 };
        }
        
        // Salva nel DB (se tabella esiste)
        try {
            await pool.query(`
                INSERT INTO beta_race_results 
                (user_id, week_number, circuit_id, total_time, best_lap, position, dnf, dnf_lap, setup, car_name, car_power)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            `, [
                userId, weekNumber, circuit.id,
                dnf ? null : totalTime, bestLap, position, dnf, dnfLap,
                JSON.stringify(setup), car.name, power
            ]);
            
            // Aggiungi premi
            if (reward.money > 0 || reward.parts > 0) {
                await pool.query(`
                    UPDATE game_state SET
                        resources = jsonb_set(
                            jsonb_set(resources, '{money,value}', 
                                (FLOOR((resources->'money'->>'value')::numeric)::bigint + $1)::text::jsonb),
                            '{parts,value}', 
                                (FLOOR((resources->'parts'->>'value')::numeric)::bigint + $2)::text::jsonb)
                    WHERE user_id = $3
                `, [reward.money, reward.parts, userId]);
            }
        } catch (dbError) {
            console.error('⚠️ Errore salvataggio DB:', dbError.message);
            // Continua senza salvare
        }
        
        // Ricarica classifica
        let leaderboard = [];
        try {
            const leaderboardResult = await pool.query(`
                SELECT u.username, u.id as user_id, brr.total_time, brr.best_lap, brr.car_name
                FROM beta_race_results brr
                JOIN users u ON u.id = brr.user_id
                WHERE brr.week_number = $1 AND brr.dnf = FALSE
                ORDER BY brr.total_time ASC
                LIMIT 50
            `, [weekNumber]);
            
            leaderboard = leaderboardResult.rows.map(r => ({
                username: r.username,
                userId: r.user_id,
                totalTime: parseFloat(r.total_time),
                bestLap: parseFloat(r.best_lap),
                carName: r.car_name
            }));
        } catch (dbError) {
            console.error('⚠️ Errore caricamento classifica');
        }
        
        console.log('✅ Simulazione completata - Pos:', position, 'DNF:', dnf);
        
        res.json({
            result: {
                totalTime: dnf ? 0 : totalTime,
                bestLap,
                position,
                dnf,
                dnfLap,
                reward
            },
            leaderboard
        });
        
    } catch (error) {
        console.error('❌ Errore run-simulation:', error);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
module.exports.setDependencies = (authFn, dbPool) => {
    authenticateToken = authFn;
    pool = dbPool;
};
