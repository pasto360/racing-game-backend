// =====================================================
// SERVER_BETA.JS - API Simulatore (MVP)
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
    circuits = JSON.parse(fs.readFileSync(circuitsPath, 'utf8')).circuits;
} catch (error) {
    console.error('❌ Errore caricamento circuiti:', error);
}

// Funzione per ottenere circuito settimanale
const getWeeklyCircuit = () => {
    const now = new Date();
    const weekNumber = Math.floor((now - new Date(now.getFullYear(), 0, 1)) / 604800000);
    const index = weekNumber % circuits.length;
    return circuits[index];
};

// =====================================================
// GET /api/beta/weekly-challenge
// Ritorna circuito + stato utente
// =====================================================
router.get('/weekly-challenge', (req, res, next) => {
    if (!authenticateToken) return res.status(500).json({ error: 'Auth not initialized' });
    authenticateToken(req, res, next);
}, async (req, res) => {
    try {
        const userId = req.user?.userId;
        const circuit = getWeeklyCircuit();

        // TODO: Query DB per hasRaced, result, leaderboard
        // Per MVP ritorna dati mock
        
        res.json({
            circuit,
            hasRaced: false,
            result: null,
            leaderboard: []
        });

    } catch (error) {
        console.error('Errore weekly-challenge:', error);
        res.status(500).json({ error: error.message });
    }
});

// =====================================================
// POST /api/beta/run-simulation
// Esegue simulazione e salva risultato
// =====================================================
router.post('/run-simulation', (req, res, next) => {
    if (!authenticateToken) return res.status(500).json({ error: 'Auth not initialized' });
    authenticateToken(req, res, next);
}, async (req, res) => {
    try {
        const userId = req.user?.userId;
        const { carIndex, setup } = req.body;
        
        // Carica game state utente (simulato per MVP)
        const car = { stats: { engine: 100, body: 80, electronics: 70, aero: 60 } };
        const power = 350; // Simulato
        
        const circuit = getWeeklyCircuit();
        
        // =====================================================
        // CALCOLO FISICA (semplificato MVP)
        // =====================================================
        
        const baseWeight = 1000 + (car.stats.body * 2);
        const totalWeight = baseWeight + setup.fuel;
        
        // Velocità max
        let maxSpeed = (power / totalWeight) * 200;
        maxSpeed -= setup.downforce * 0.5;
        if (setup.gearRatio === 'short') maxSpeed -= 10;
        if (setup.gearRatio === 'long') maxSpeed += 10;
        
        // Grip
        let grip = 1.0;
        if (setup.tires === 'soft') grip = 1.05;
        if (setup.tires === 'hard') grip = 0.98;
        grip += (2.2 - setup.tirePressure) * 0.05;
        
        // Consumo carburante/giro
        let fuelPerLap = 2.5;
        fuelPerLap += circuit.tightCorners * 0.15;
        fuelPerLap += setup.downforce * 0.02;
        if (setup.tires === 'soft') fuelPerLap *= 1.1;
        
        // Degrado gomme/giro
        let tireWearPerLap = 0.003;
        if (setup.tires === 'soft') tireWearPerLap = 0.005;
        if (setup.tires === 'hard') tireWearPerLap = 0.002;
        tireWearPerLap += circuit.tightCorners * 0.0005;
        
        // Simula gara
        let totalTime = 0;
        let bestLap = 999;
        let fuel = setup.fuel;
        let tireWear = 0;
        let dnf = false;
        let dnfLap = 0;
        
        for (let lap = 1; lap <= circuit.laps; lap++) {
            // Check carburante
            if (fuel < fuelPerLap) {
                dnf = true;
                dnfLap = lap;
                break;
            }
            
            // Calcola tempo giro
            const currentGrip = grip * (1 - tireWear);
            const currentWeight = baseWeight + fuel;
            
            let lapTime = 60 + Math.random() * 5; // Base 60-65 sec
            lapTime *= (circuit.length / 5000); // Scala per lunghezza
            lapTime *= (1200 / currentWeight); // Peso
            lapTime *= (1 / currentGrip); // Grip
            lapTime += (100 - setup.downforce) * 0.05; // Deportanza in curve
            lapTime -= maxSpeed * 0.01; // Velocità in rettilineo
            
            // Penalità dossi
            if (circuit.bumps >= 3 && setup.suspension === -30) {
                lapTime += 0.5;
            }
            
            totalTime += lapTime;
            if (lapTime < bestLap) bestLap = lapTime;
            
            // Consuma
            fuel -= fuelPerLap;
            tireWear += tireWearPerLap;
        }
        
        // Calcola posizione (mock - servirebbe DB)
        const position = Math.floor(Math.random() * 50) + 1;
        
        // Premi
        let reward = { money: 0, parts: 0 };
        if (!dnf) {
            if (position === 1) reward = { money: 50000, parts: 1000 };
            else if (position === 2) reward = { money: 30000, parts: 600 };
            else if (position === 3) reward = { money: 15000, parts: 300 };
            else if (position <= 10) reward = { money: 5000, parts: 100 };
            else if (position <= 50) reward = { money: 1000, parts: 50 };
        }
        
        const result = {
            totalTime: dnf ? 0 : totalTime,
            bestLap,
            position,
            dnf,
            dnfLap,
            reward
        };
        
        // TODO: Salva in DB
        
        res.json({
            result,
            leaderboard: [] // TODO: Query DB
        });
        
    } catch (error) {
        console.error('Errore run-simulation:', error);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
module.exports.setDependencies = (authFn, dbPool) => {
    authenticateToken = authFn;
    pool = dbPool;
};

