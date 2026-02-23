// SERVER_BETA.JS - 1 TENTATIVO AL GIORNO
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

const getWeeklyCircuit = () => {
    const now = new Date();
    const weekNumber = Math.floor((now - new Date(now.getFullYear(), 0, 1)) / 604800000);
    return circuits[weekNumber % circuits.length];
};

const getWeekNumber = () => {
    const now = new Date();
    return Math.floor((now - new Date(now.getFullYear(), 0, 1)) / 604800000);
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
        
        const now = new Date();
        const todayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0));

        let hasRacedToday = false;
        let attempts = [];
        let bestAttempt = null;
        let leaderboard = [];

        try {
            // Check tentativo di oggi (UTC)
            const todayCheck = await pool.query(`
                SELECT id FROM beta_race_results
                WHERE user_id = $1 AND week_number = $2 AND created_at >= $3
            `, [userId, weekNumber, todayStart.toISOString()]);
            
            hasRacedToday = todayCheck.rows.length > 0;
            
            console.log('🔍 Check oggi - userId:', userId, 'week:', weekNumber, 'todayStart:', todayStart.toISOString());
            console.log('🔍 Risultati trovati:', todayCheck.rows.length, '→ hasRacedToday:', hasRacedToday);

            // Carica TUTTI i tentativi della settimana (ordinati dal più recente)
            const allAttempts = await pool.query(`
                SELECT total_time, best_lap, position, dnf, dnf_lap, created_at
                FROM beta_race_results
                WHERE user_id = $1 AND week_number = $2
                ORDER BY created_at DESC
            `, [userId, weekNumber]);

            const attempts = allAttempts.rows.map(r => ({
                totalTime: parseFloat(r.total_time) || 0,
                bestLap: parseFloat(r.best_lap),
                position: r.position,
                dnf: r.dnf,
                dnfLap: r.dnf_lap,
                date: r.created_at,
                reward: { money: 0, parts: 0 }
            }));
            
            // Miglior risultato (non-DNF con tempo minore)
            const validAttempts = attempts.filter(a => !a.dnf && a.totalTime > 0);
            const bestAttempt = validAttempts.length > 0 
                ? validAttempts.reduce((min, a) => a.totalTime < min.totalTime ? a : min)
                : null;

            // Classifica: MIGLIOR tempo per utente
            const leaderboardResult = await pool.query(`
                SELECT 
                    u.username, 
                    u.id as user_id, 
                    MIN(brr.total_time) as total_time, 
                    MIN(brr.best_lap) as best_lap,
                    COUNT(*) as attempts
                FROM beta_race_results brr
                JOIN users u ON u.id = brr.user_id
                WHERE brr.week_number = $1 AND brr.dnf = FALSE
                GROUP BY u.username, u.id
                ORDER BY total_time ASC
                LIMIT 50
            `, [weekNumber]);

            leaderboard = leaderboardResult.rows.map(r => ({
                username: r.username,
                userId: r.user_id,
                totalTime: parseFloat(r.total_time),
                bestLap: parseFloat(r.best_lap),
                attempts: parseInt(r.attempts),
                carName: 'Thunderbolt R-9'
            }));
            
            console.log('📊 Classifica caricata:', leaderboard.length, 'utenti');
        } catch (dbError) {
            console.log('⚠️ DB error (ignorato):', dbError.message);
        }

        res.json({ 
            circuit, 
            hasRacedToday, 
            attempts,
            bestResult: bestAttempt,
            attemptsThisWeek: attempts.length,
            leaderboard 
        });

    } catch (error) {
        console.error('❌ Errore weekly-challenge:', error);
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
        
        // ✅ Check giornaliero con timezone UTC (evita bypass)
        const now = new Date();
        const todayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0));

        console.log('🏁 Simulazione userId:', userId, '- Oggi UTC:', todayStart.toISOString());

        // Check se ha già corso OGGI
        try {
            const todayResult = await pool.query(`
                SELECT id FROM beta_race_results 
                WHERE user_id = $1 AND week_number = $2 AND created_at >= $3
            `, [userId, weekNumber, todayStart.toISOString()]);
            
            if (todayResult.rows.length > 0) {
                return res.status(400).json({ error: 'Hai già corso oggi! Riprova domani per migliorare il tuo tempo.' });
            }
        } catch (dbError) {
            console.log('⚠️ Check giornaliero ignorato');
        }

        const power = 380;
        const baseWeight = 1250;
        const circuit = getWeeklyCircuit();

        // FISICA (identica)
        let maxSpeed = (power / (baseWeight + setup.fuel)) * 200;
        maxSpeed -= setup.downforce * 0.5;
        if (setup.gearRatio === 'short') maxSpeed -= 10;
        if (setup.gearRatio === 'long') maxSpeed += 10;
        
        let grip = 1.0;
        if (setup.tires === 'soft') grip = 1.05;
        if (setup.tires === 'hard') grip = 0.98;
        grip += (2.2 - setup.tirePressure) * 0.05;
        
        // ✅ Consumo base: 3.4 L/giro (modificato da setup)
        let fuelPerLap = 3.4;
        fuelPerLap += circuit.tightCorners * 0.08;  // Curve strette aumentano consumo
        fuelPerLap += setup.downforce * 0.015;       // Deportanza aumenta consumo
        if (setup.tires === 'soft') fuelPerLap *= 1.08;     // Gomme morbide +8%
        if (setup.engineMap === 'power') fuelPerLap *= 1.12; // Mappatura aggressiva +12%
        if (setup.engineMap === 'eco') fuelPerLap *= 0.92;   // Mappatura eco -8%
        
        let tireWearPerLap = (setup.tires === 'soft' ? 0.005 : setup.tires === 'hard' ? 0.002 : 0.003);
        tireWearPerLap += circuit.tightCorners * 0.0005;
        
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
            
            if (circuit.bumps >= 3 && setup.suspension === -30) lapTime += 0.5;
            
            totalTime += lapTime;
            if (lapTime < bestLap) bestLap = lapTime;
            
            fuel -= fuelPerLap;
            tireWear += tireWearPerLap;
        }
        
        // Calcola posizione STIMATA (la vera classifica si basa sul tempo reale)
        const avgTime = (circuit.length / 1000) * circuit.laps * 70;
        const variance = dnf ? 999 : (totalTime - avgTime) / avgTime;
        let estimatedPosition = Math.floor(25 + variance * 50);
        estimatedPosition = Math.max(1, Math.min(50, estimatedPosition));
        
        // ⚠️ PREMI SOLO A FINE SETTIMANA (lunedì reset)
        // Non dare premi ora - saranno assegnati dal reset settimanale al top 3
        const reward = { money: 0, parts: 0 };
        
        // Salva tentativo
        try {
            await pool.query(`
                INSERT INTO beta_race_results 
                (user_id, week_number, circuit_id, total_time, best_lap, position, dnf, dnf_lap, setup, car_name, car_power)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            `, [
                userId, weekNumber, circuit.id,
                dnf ? null : totalTime, bestLap, estimatedPosition, dnf, dnfLap,
                JSON.stringify(setup), 'Thunderbolt R-9', power
            ]);
            
            console.log('✅ Risultato salvato - DNF:', dnf, 'Tempo:', totalTime);
        } catch (dbError) {
            console.error('⚠️ Salvataggio DB fallito:', dbError.message);
        }
        
        // Ricarica classifica
        let leaderboard = [];
        try {
            const leaderboardResult = await pool.query(`
                SELECT 
                    u.username, 
                    u.id as user_id, 
                    MIN(brr.total_time) as total_time, 
                    MIN(brr.best_lap) as best_lap
                FROM beta_race_results brr
                JOIN users u ON u.id = brr.user_id
                WHERE brr.week_number = $1 AND brr.dnf = FALSE
                GROUP BY u.username, u.id
                ORDER BY total_time ASC
                LIMIT 50
            `, [weekNumber]);
            
            leaderboard = leaderboardResult.rows.map(r => ({
                username: r.username,
                userId: r.user_id,
                totalTime: parseFloat(r.total_time),
                bestLap: parseFloat(r.best_lap),
                carName: 'Beta Racer'
            }));
        } catch (dbError) {}
        
        console.log('✅ Simulazione OK - Tempo:', totalTime.toFixed(3), 'DNF:', dnf);
        
        res.json({
            result: {
                totalTime: dnf ? 0 : totalTime,
                bestLap,
                position: estimatedPosition,
                dnf,
                dnfLap,
                date: new Date().toISOString(),
                reward: { money: 0, parts: 0 } // Premi solo a fine settimana
            },
            leaderboard
        });
        
    } catch (error) {
        console.error('❌ Errore simulazione:', error);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
module.exports.setDependencies = (authFn, dbPool) => {
    authenticateToken = authFn;
    pool = dbPool;
};
