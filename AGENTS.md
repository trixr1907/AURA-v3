# AURA v3 Enterprise — Agent Operating Guidelines & Rules (Lean ECC)

## 🎯 Kern-Philosophie (Plan -> Test -> Implement -> Verify)
1. **Erst verstehen & planen:** Analysiere bestehenden Code und Abhängigkeiten, bevor Dateien verändert werden.
2. **Test-Driven Development (TDD):** Neue Logik in `aura/` wird immer von einem Unit- oder Integrationstest in `tests/test_v3_*.py` begleitet.
3. **Keine Behauptung ohne echten Terminal-Beweis:** Melde eine Aufgabe niemals als 'erledigt', ohne den tatsächlichen CLI-Output eines erfolgreichen Tests oder Healthchecks vorzulegen.
4. **Zero Legacy / Zero Fluff:** Verwende ausschließlich den modularen Python-Kern (`aura/`), das moderne Terminal und Docker Compose. Bringe niemals alte Monolithen oder Wegwerf-Skripte zurück.

## 🛡️ Quant- & Systemsicherheit (Fail-Closed)
- **Paper-Trading-Integrität:** Das System simuliert Aufträge serverseitig mit echtem Bitget-Feed. Keine echten Börsen-Orders ohne explizite Freigabe.
- **Rechnerische Ehrlichkeit:** Maskiere niemals negative PnL oder Risikokennzahlen. Kennzahlen müssen auf den Cent mit den Daten übereinstimmen.
- **Secret Hygiene:** Niemals API-Keys, Private Keys oder Session-Tokens in Commits ablegen.

## 🏗️ Architektur-Garantien
- **Control Plane (`aura-api`):** FastAPI, Uvicorn, Token-Session-Auth auf Port 8000.
- **Execution Engine (`aura-worker`):** Autonomer Headless Runner, DB-Poller, Bitget-WebSockets/REST.
- **Storage:** SQLite im WAL-Modus auf `/data/aura_state.db`.
- **UI:** `aura_ux_preview.html` als reaktives Frontend direkt auf Root `/`.
