// =====================================================
// BETA.JS - Simulatore Gara (MVP)
// =====================================================

const BetaModule = (() => {

    const getApiUrl = () => {
        // Usa API_URL globale dal gioco principale (già configurato in index.html)
        return window.API_URL || 'http://localhost:3000';
    };

    const api = async (endpoint, options = {}) => {
        const token = window.authToken || localStorage.getItem('authToken');
        const response = await fetch(`${getApiUrl()}/api/beta/${endpoint}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
                ...(options.headers || {})
            }
        });
        if (!response.ok) throw new Error(`API Error: ${response.status}`);
        return response.json();
    };

    let state = {
        circuit: null,
        selectedCar: null,
        setup: {
            tires: 'medium',
            downforce: 50,
            fuel: 50,
            tirePressure: 2.2,
            suspension: 0,
            gearRatio: 'medium',
            brakeBias: 55,
            engineMap: 'balanced'
        },
        attemptsUsed: 0, // 0-3 tentativi giornalieri
        results: [], // Array risultati (max 3)
        leaderboard: []
    };

    const render = async (container, gameInstance) => {
        try {
            // ✅ Ricarica dati solo se non abbiamo già un risultato
            if (!state.hasRaced || !state.circuit) {
                const data = await api('weekly-challenge');
                
                state.circuit = data.circuit;
                state.hasRaced = data.hasRaced;
                state.result = data.result;
                state.leaderboard = data.leaderboard;
            }

            if (gameInstance.ownedCars && gameInstance.ownedCars.length > 0 && !state.selectedCar) {
                state.selectedCar = gameInstance.ownedCars[0];
            }

            container.innerHTML = `
                ${renderCircuit()}
                ${!state.hasRaced ? renderSetup(gameInstance) : ''}
                ${state.hasRaced && state.result ? renderResults() : ''}
                ${renderLeaderboard()}
            `;
            
            console.log('📊 Stato render - hasRaced:', state.hasRaced, 'result:', !!state.result);

            attachListeners(gameInstance);

        } catch (error) {
            console.error('Errore:', error);
            container.innerHTML = `
                <div class="beta-empty">
                    <span class="beta-icon">❌</span>
                    <h3>Errore Caricamento</h3>
                    <p>${error.message}</p>
                </div>
            `;
        }
    };

    const renderCircuit = () => {
        const c = state.circuit;
        if (!c) return '';

        return `
            <div class="circuit-header">
                <div class="circuit-name">🏁 ${c.name}</div>
                <div class="circuit-country">${c.country}</div>
                <p style="color: rgba(255,255,255,0.7); font-style: italic;">${c.description}</p>
                
                <div class="circuit-stats">
                    <div class="circuit-stat">
                        <div class="circuit-stat-label">Lunghezza</div>
                        <div class="circuit-stat-value">${(c.length / 1000).toFixed(1)} km</div>
                    </div>
                    <div class="circuit-stat">
                        <div class="circuit-stat-label">Giri</div>
                        <div class="circuit-stat-value">${c.laps}</div>
                    </div>
                    <div class="circuit-stat">
                        <div class="circuit-stat-label">Curve Strette</div>
                        <div class="circuit-stat-value">${c.tightCorners} 🔴</div>
                    </div>
                    <div class="circuit-stat">
                        <div class="circuit-stat-label">Curve Medie</div>
                        <div class="circuit-stat-value">${c.mediumCorners} 🟡</div>
                    </div>
                    <div class="circuit-stat">
                        <div class="circuit-stat-label">Curve Veloci</div>
                        <div class="circuit-stat-value">${c.fastCorners} 🟢</div>
                    </div>
                    <div class="circuit-stat">
                        <div class="circuit-stat-label">Rettilinei</div>
                        <div class="circuit-stat-value">${c.longStraights + c.shortStraights}</div>
                    </div>
                </div>

                ${state.attemptsUsed < 3 ? `
                    <div style="margin-top: 20px; padding: 15px; background: rgba(0,217,255,0.1); border-radius: 8px; border-left: 4px solid #00d9ff;">
                        <strong style="color: #00d9ff;">🏁 Tentativi: ${3 - state.attemptsUsed}/3 disponibili</strong><br>
                        <span style="color: rgba(255,255,255,0.7); font-size: 0.9rem;">
                            Reset giornaliero. Vale il miglior tempo!
                        </span>
                    </div>
                ` : `
                    <div style="margin-top: 20px; padding: 15px; background: rgba(255,69,0,0.1); border-radius: 8px; border-left: 4px solid #ff4500;">
                        <strong style="color: #ff4500;">❌ Tentativi esauriti (3/3)</strong><br>
                        <span style="color: rgba(255,255,255,0.7); font-size: 0.9rem;">
                            Nuovi tentativi domani
                        </span>
                    </div>
                `}
            </div>
        `;
    };

    const renderSetup = (game) => {
        if (!game.ownedCars || game.ownedCars.length === 0) {
            return '<div class="setup-section"><p style="text-align:center;color:rgba(255,255,255,0.5);">⚠️ Serve almeno un\'auto</p></div>';
        }

        const car = state.selectedCar;
        const power = game.getCarPower(car);

        return `
            <div class="setup-section">
                <div class="setup-title">🏎️ Auto</div>
                
                <div style="background: rgba(0,0,0,0.3); padding: 20px; border-radius: 10px; margin-bottom: 20px;">
                    <select id="car-selector" style="width: 100%; padding: 12px; background: rgba(255,255,255,0.1); color: #fff; border: 2px solid rgba(0,217,255,0.3); border-radius: 8px; font-family: Orbitron; font-size: 1rem; cursor: pointer;">
                        ${game.ownedCars.map((c, i) => `
                            <option value="${i}" ${c === car ? 'selected' : ''} style="background: #1a1a1a; color: #fff;">
                                ${c.name} - ${game.getCarPower(c)} HP
                            </option>
                        `).join('')}
                    </select>
                    <div style="margin-top: 15px; padding: 15px; background: rgba(0,217,255,0.1); border-radius: 8px; text-align: center;">
                        <div style="font-family: Orbitron; font-size: 1.5rem; color: #ffa500; margin-bottom: 5px;">
                            ${car.name}
                        </div>
                        <div style="color: rgba(255,255,255,0.7);">
                            ${power} HP • ${1000 + (car.stats.body * 2)} kg
                        </div>
                    </div>
                </div>

                <div class="setup-title">⚙️ Setup</div>

                <div class="setup-param">
                    <div class="setup-param-label">
                        <span>🏁 Gomme</span>
                    </div>
                    <div class="setup-radio-group">
                        <div class="setup-radio">
                            <input type="radio" name="tires" id="tires-hard" value="hard" ${state.setup.tires === 'hard' ? 'checked' : ''}>
                            <label for="tires-hard">Dure</label>
                        </div>
                        <div class="setup-radio">
                            <input type="radio" name="tires" id="tires-medium" value="medium" ${state.setup.tires === 'medium' ? 'checked' : ''}>
                            <label for="tires-medium">Medie</label>
                        </div>
                        <div class="setup-radio">
                            <input type="radio" name="tires" id="tires-soft" value="soft" ${state.setup.tires === 'soft' ? 'checked' : ''}>
                            <label for="tires-soft">Morbide</label>
                        </div>
                    </div>
                </div>

                <div class="setup-param">
                    <div class="setup-param-label">
                        <span>✈️ Deportanza</span>
                        <span id="downforce-val">${state.setup.downforce}%</span>
                    </div>
                    <input type="range" class="setup-slider" id="downforce" min="0" max="100" value="${state.setup.downforce}">
                </div>

                <div class="setup-param">
                    <div class="setup-param-label">
                        <span>⛽ Carburante</span>
                        <span id="fuel-val">${state.setup.fuel} L</span>
                    </div>
                    <input type="range" class="setup-slider" id="fuel" min="20" max="100" value="${state.setup.fuel}">
                </div>

                <div class="setup-param">
                    <div class="setup-param-label">
                        <span>💨 Pressione</span>
                        <span id="pressure-val">${state.setup.tirePressure} bar</span>
                    </div>
                    <input type="range" class="setup-slider" id="pressure" min="1.8" max="2.5" step="0.1" value="${state.setup.tirePressure}">
                </div>

                <div class="setup-param">
                    <div class="setup-param-label">
                        <span>🔧 Sospensioni</span>
                        <span id="suspension-val">${state.setup.suspension > 0 ? '+' : ''}${state.setup.suspension} mm</span>
                    </div>
                    <input type="range" class="setup-slider" id="suspension" min="-30" max="30" step="10" value="${state.setup.suspension}">
                </div>

                <div class="setup-param">
                    <div class="setup-param-label">
                        <span>⚙️ Rapporto</span>
                    </div>
                    <div class="setup-radio-group">
                        <div class="setup-radio">
                            <input type="radio" name="gear" id="gear-short" value="short" ${state.setup.gearRatio === 'short' ? 'checked' : ''}>
                            <label for="gear-short">Corto</label>
                        </div>
                        <div class="setup-radio">
                            <input type="radio" name="gear" id="gear-medium" value="medium" ${state.setup.gearRatio === 'medium' ? 'checked' : ''}>
                            <label for="gear-medium">Medio</label>
                        </div>
                        <div class="setup-radio">
                            <input type="radio" name="gear" id="gear-long" value="long" ${state.setup.gearRatio === 'long' ? 'checked' : ''}>
                            <label for="gear-long">Lungo</label>
                        </div>
                    </div>
                </div>

                <button class="simulate-btn" id="run-btn">🏁 AVVIA SIMULAZIONE</button>
            </div>
        `;
    };

    const renderResults = () => {
        const r = state.result;
        if (!r) return '';

        const formatTime = (s) => {
            const m = Math.floor(s / 60);
            const sec = (s % 60).toFixed(3);
            return `${m}:${sec.padStart(6, '0')}`;
        };

        return `
            <div class="results-container">
                <div class="results-title">🏁 RISULTATO FINALE</div>
                <div class="results-main">
                    <div class="result-stat">
                        <div class="result-stat-label">Tempo Totale</div>
                        <div class="result-stat-value">${r.dnf ? 'DNF' : formatTime(r.totalTime)}</div>
                    </div>
                    <div class="result-stat">
                        <div class="result-stat-label">Miglior Giro</div>
                        <div class="result-stat-value">${formatTime(r.bestLap)}</div>
                    </div>
                    <div class="result-stat">
                        <div class="result-stat-label">Posizione</div>
                        <div class="result-stat-value">${r.position}°</div>
                    </div>
                    <div class="result-stat">
                        <div class="result-stat-label">Premio</div>
                        <div class="result-stat-value" style="font-size: 1.2rem;">
                            ${r.reward.money > 0 ? `💰 ${r.reward.money.toLocaleString()}<br>` : ''}
                            ${r.reward.parts > 0 ? `🔩 ${r.reward.parts.toLocaleString()}` : ''}
                            ${r.reward.money === 0 && r.reward.parts === 0 ? '-' : ''}
                        </div>
                    </div>
                </div>
                ${r.dnf ? `
                    <div style="background: rgba(255,69,0,0.2); border: 2px solid #ff4500; border-radius: 8px; padding: 20px; text-align: center; margin-top: 20px;">
                        <div style="font-size: 2rem; margin-bottom: 10px;">❌</div>
                        <div style="font-family: Orbitron; font-size: 1.3rem; color: #ff4500; margin-bottom: 5px;">DNF - NON CLASSIFICATO</div>
                        <div style="color: rgba(255,255,255,0.7);">Carburante esaurito al giro ${r.dnfLap}/${state.circuit.laps}</div>
                    </div>
                ` : ''}
            </div>
        `;
    };

    const renderLeaderboard = () => {
        if (!state.leaderboard || state.leaderboard.length === 0) {
            return '<div class="leaderboard"><div class="leaderboard-title">🏆 Classifica</div><p style="text-align:center;color:rgba(255,255,255,0.5);padding:40px;">Nessun risultato</p></div>';
        }

        const formatTime = (s) => {
            const m = Math.floor(s / 60);
            const sec = (s % 60).toFixed(3);
            return `${m}:${sec.padStart(6, '0')}`;
        };

        const userId = window.game?.userId;

        return `
            <div class="leaderboard">
                <div class="leaderboard-title">🏆 Classifica Mondiale</div>
                ${state.leaderboard.slice(0, 20).map((e, i) => {
                    const pos = i + 1;
                    const isCurrent = e.userId === userId;
                    let icon = pos;
                    if (pos === 1) icon = '🥇';
                    else if (pos === 2) icon = '🥈';
                    else if (pos === 3) icon = '🥉';

                    return `
                        <div class="leaderboard-entry ${isCurrent ? 'current-user' : ''}">
                            <div class="leaderboard-position">${icon}</div>
                            <div class="leaderboard-username">${e.username} ${isCurrent ? '(Tu)' : ''}</div>
                            <div class="leaderboard-time">${formatTime(e.totalTime)}</div>
                        </div>
                    `;
                }).join('')}
            </div>
        `;
    };

    const attachListeners = (game) => {
        // Car selector
        const carSelector = document.getElementById('car-selector');
        if (carSelector) {
            console.log('✅ Selector auto trovato');
            carSelector.addEventListener('change', (e) => {
                const newIndex = parseInt(e.target.value);
                state.selectedCar = game.ownedCars[newIndex];
                console.log('🚗 Auto cambiata:', state.selectedCar.name);
                // Re-render per aggiornare stats
                render(document.getElementById('betaContainer'), game);
            });
        }

        // Sliders
        const downforce = document.getElementById('downforce');
        if (downforce) {
            downforce.addEventListener('input', (e) => {
                state.setup.downforce = parseInt(e.target.value);
                document.getElementById('downforce-val').textContent = `${state.setup.downforce}%`;
            });
        }

        const fuel = document.getElementById('fuel');
        if (fuel) {
            fuel.addEventListener('input', (e) => {
                state.setup.fuel = parseInt(e.target.value);
                document.getElementById('fuel-val').textContent = `${state.setup.fuel} L`;
            });
        }

        const pressure = document.getElementById('pressure');
        if (pressure) {
            pressure.addEventListener('input', (e) => {
                state.setup.tirePressure = parseFloat(e.target.value);
                document.getElementById('pressure-val').textContent = `${state.setup.tirePressure} bar`;
            });
        }

        const suspension = document.getElementById('suspension');
        if (suspension) {
            suspension.addEventListener('input', (e) => {
                state.setup.suspension = parseInt(e.target.value);
                const sign = state.setup.suspension > 0 ? '+' : '';
                document.getElementById('suspension-val').textContent = `${sign}${state.setup.suspension} mm`;
            });
        }

        // Radio
        document.querySelectorAll('input[name="tires"]').forEach(r => {
            r.addEventListener('change', (e) => state.setup.tires = e.target.value);
        });

        document.querySelectorAll('input[name="gear"]').forEach(r => {
            r.addEventListener('change', (e) => state.setup.gearRatio = e.target.value);
        });

        // Run button
        const btn = document.getElementById('run-btn');
        if (btn) {
            console.log('✅ Pulsante simulazione trovato, attacco listener');
            btn.addEventListener('click', () => {
                console.log('🏁 Click su AVVIA SIMULAZIONE');
                runSimulation(game);
            });
        } else {
            console.error('❌ Pulsante run-btn non trovato!');
        }
    };

    const runSimulation = async (game) => {
        console.log('🚀 runSimulation chiamata!');
        const btn = document.getElementById('run-btn');
        if (!btn) {
            console.error('❌ Pulsante non trovato in runSimulation');
            return;
        }

        console.log('✅ Avvio simulazione...');
        console.log('Setup:', state.setup);
        console.log('Auto:', state.selectedCar?.name);
        
        btn.disabled = true;
        btn.textContent = '⏳ SIMULAZIONE...';

        try {
            const carIndex = game.ownedCars.indexOf(state.selectedCar);
            console.log('📤 Invio richiesta simulazione, carIndex:', carIndex);
            
            const result = await api('run-simulation', {
                method: 'POST',
                body: JSON.stringify({ carIndex, setup: state.setup })
            });

            console.log('📥 Risultato ricevuto:', result);

            state.attemptsUsed++;
            state.results.push(result.result);
            state.leaderboard = result.leaderboard;

            // Aggiungi premi
            if (result.result.reward.money > 0) {
                game.resources.money.value += result.result.reward.money;
            }
            if (result.result.reward.parts > 0) {
                game.resources.parts.value += result.result.reward.parts;
            }
            game.render();
            
            console.log('💾 Salvo stato...');
            await window.saveGameToServer(true);

            // Re-render
            console.log('🎨 Re-render pagina beta');
            await render(document.getElementById('betaContainer'), game);

        } catch (error) {
            console.error('❌ Errore simulazione:', error);
            console.error('Stack:', error.stack);
            alert('❌ Errore: ' + error.message);
            btn.disabled = false;
            btn.textContent = '🏁 AVVIA SIMULAZIONE';
        }
    };

    return { render, api, runSimulation };

})();
