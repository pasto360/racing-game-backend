// SERVER_BETA.JS - VERSIONE FINALE v2
const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

let authenticateToken = null;
let pool = null;

const circuitsPath = path.join(__dirname, 'beta_circuits.json');
let circuits = [];
try {
    circuits = JSON.parse(fs.readFileSync(circuitsPath, 'utf8')).circuits;
    console.log('✅ Circuiti beta caricati:', circuits.length);
} catch (error) {
    console.error('❌ Errore caricamento circuiti:', error.message);
}

// Circuito cambia ogni LUNEDÌ
const getWeeklyCircuit = () => {
    const now = new Date();
    const startOfYear = new Date(now.getFullYear(), 0, 1);
    const weekNumber = Math.floor((now - startOfYear) / 604800000);
    return circuits[weekNumber % circuits.length];
};

const getWeekNumber = () => {
    const now = new Date();
    const startOfYear = new Date(now.getFullYear(), 0, 1);
    return Math.floor((now - startOfYear) / 604800000);
};

// GET /api/beta/weekly-challenge
router.get('/weekly-challenge', (req, res, next) => {
    if (!authenticateToken) return res.status(500).json({ error: 'Auth not initialized' });
    authenticateToken(req, res, next);
}, async (req, res) => {
    try {
        const userId = req.user?.userId;
        const circuit = getWeeklyCircuit();
        const weekNumber = getWeekNumber();

        // Check giornaliero: 1 tentativo al giorno
        const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
        
        const todayCheck = await pool.query(`
            SELECT COUNT(*) as count FROM beta_race_results
            WHERE user_id = $1 AND week_number = $2 AND DATE(created_at) = $3
        `, [userId, weekNumber, today]);
        
        const hasRacedToday = parseInt(todayCheck.rows[0]?.count) > 0;

        // Carica TUTTI i tentativi della settimana
        const allResults = await pool.query(`
            SELECT total_time, best_lap, position, dnf, dnf_lap, created_at
            FROM beta_race_results
            WHERE user_id = $1 AND week_number = $2
            ORDER BY created_at DESC
        `, [userId, weekNumber]);

        const attempts = allResults.rows.map(r => ({
            totalTime: parseFloat(r.total_time) || 0,
            bestLap: parseFloat(r.best_lap),
            position: r.position,
            dnf: r.dnf,
            dnfLap: r.dnf_lap,
            date: r.created_at
        }));

        // Classifica mondiale (resetta ogni lunedì)
        const leaderboard = await pool.query(`
            SELECT u.username, u.id as user_id, MIN(brr.total_time) as total_time, MIN(brr.best_lap) as best_lap
            FROM beta_race_results brr
            JOIN users u ON u.id = brr.user_id
            WHERE brr.week_number = $1 AND brr.dnf = FALSE
            GROUP BY u.username, u.id
            ORDER BY total_time ASC
            LIMIT 50
        `, [weekNumber]);

        console.log('📊 GET - userId:', userId, 'hasRacedToday:', hasRacedToday, 'attempts:', attempts.length);

        res.json({
            circuit,
            hasRacedToday,
            attempts,
            weekNumber, // Esposto per frontend
            leaderboard: leaderboard.rows.map(r => ({
                username: r.username,
                userId: r.user_id,
                totalTime: parseFloat(r.total_time),
                bestLap: parseFloat(r.best_lap)
            }))
        });

    } catch (error) {
        console.error('❌ Errore GET:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/beta/run-simulation
router.post('/run-simulation', (req, res, next) => {
    if (!authenticateToken) return res.status(500).json({ error: 'Auth not initialized' });
    authenticateToken(req, res, next);
}, async (req, res) => {
    try {
        const userId = req.user?.userId;
        const { setup } = req.body;
        const weekNumber = getWeekNumber();
        
        // Check giornaliero
        const today = new Date().toISOString().split('T')[0];
        
        const todayCheck = await pool.query(`
            SELECT COUNT(*) as count FROM beta_race_results
            WHERE user_id = $1 AND week_number = $2 AND DATE(created_at) = $3
        `, [userId, weekNumber, today]);
        
        if (parseInt(todayCheck.rows[0]?.count) > 0) {
            console.log('❌ POST - userId:', userId, 'già corso oggi');
            return res.status(400).json({ error: 'Hai già corso oggi! Riprova domani.' });
        }

        console.log('✅ POST - userId:', userId, 'simulazione START');

        const power = 380;
        const baseWeight = 1250;
        const circuit = getWeeklyCircuit();

        // FISICA COMPLETA
        let maxSpeed = (power / (baseWeight + setup.fuel)) * 200;
        maxSpeed -= setup.downforce * 0.5;
        
        let grip = 1.0;
        if (setup.tires === 'soft') grip = 1.05;
        if (setup.tires === 'hard') grip = 0.98;
        
        // Consumo carburante (mappatura 1-10)
        let fuelPerLap = 3.4;
        fuelPerLap += circuit.tightCorners * 0.08;
        fuelPerLap += setup.downforce * 0.015;
        if (setup.tires === 'soft') fuelPerLap *= 1.08;
        fuelPerLap *= (0.85 + (setup.engineMap - 1) * 0.05); // 1=85%, 10=130%
        
        let tireWearPerLap = (setup.tires === 'soft' ? 0.005 : setup.tires === 'hard' ? 0.002 : 0.003);
        
        let totalTime = 0;
        let bestLap = 999;
        let fuel = setup.fuel;
        let tireWear = 0;
        let dnf = false;
        let dnfLap = 0;
        
        // Aggressività pilota (1-10)
        const errorChance = (setup.aggression - 1) / 9 * 0.8; // 1=0%, 10=80%
        
        for (let lap = 1; lap <= circuit.laps; lap++) {
            if (fuel < fuelPerLap) {
                dnf = true;
                dnfLap = lap;
                break;
            }
            
            const currentGrip = grip * (1 - tireWear);
            const currentWeight = baseWeight + fuel;
            
            // Tempo base
            let lapTime = 60 + Math.random() * 5;
            lapTime *= (circuit.length / 5000);
            lapTime *= (1200 / currentWeight);
            lapTime *= (1 / currentGrip);
            lapTime += (100 - setup.downforce) * 0.05;
            lapTime -= maxSpeed * 0.01;
            
            // Aggressività: più aggressivo = più veloce MA rischio errori
            lapTime *= (1.1 - setup.aggression * 0.01); // 1=109%, 10=100%
            
            // Rischio errore
            if (Math.random() < errorChance) {
                const timeLost = 0.5 + Math.random() * 0.5; // 0.5-1.0 sec
                lapTime += timeLost;
                console.log(`   ⚠️ Giro ${lap}: errore pilota! +${timeLost.toFixed(2)}s`);
            }
            
            totalTime += lapTime;
            if (lapTime < bestLap) bestLap = lapTime;
            
            fuel -= fuelPerLap;
            tireWear += tireWearPerLap;
        }
        
        const avgTime = (circuit.length / 1000) * circuit.laps * 70;
        const variance = dnf ? 999 : (totalTime - avgTime) / avgTime;
        let position = Math.floor(25 + variance * 50);
        position = Math.max(1, Math.min(50, position));

        // Salva nel DB
        await pool.query(`
            INSERT INTO beta_race_results 
            (user_id, week_number, circuit_id, total_time, best_lap, position, dnf, dnf_lap, setup, car_name, car_power)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        `, [
            userId, weekNumber, circuit.id,
            dnf ? null : totalTime, bestLap, position, dnf, dnfLap,
            JSON.stringify(setup), 'Thunderbolt R-9', power
        ]);

        console.log('✅ POST - Salvato! DNF:', dnf, 'Tempo:', totalTime.toFixed(2));

        res.json({
            success: true,
            result: {
                totalTime: dnf ? 0 : totalTime,
                bestLap,
                position,
                dnf,
                dnfLap,
                date: new Date()
            }
        });
        
    } catch (error) {
        console.error('❌ Errore POST:', error);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
module.exports.setDependencies = (authFn, dbPool) => {
    authenticateToken = authFn;
    pool = dbPool;
};
