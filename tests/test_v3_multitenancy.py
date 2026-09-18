from __future__ import annotations
from pathlib import Path
import pytest
from aura.store.db import connect, current_version
from aura.runner.paper_engine import PaperTradingEngine, EngineConfig

SPEC = {'minNotional': 5.0, 'minQty': 0.001, 'priceTick': 0.1, 'qtyStep': 0.001}

def test_multitenancy_isolation(tmp_path: Path):
    db_file = tmp_path / 'tenant_test.db'
    conn = connect(db_file)
    assert current_version(conn) == 7

    eng_master = PaperTradingEngine(conn=conn, account_id='master')
    eng_buddy = PaperTradingEngine(conn=conn, account_id='buddy')

    assert eng_master.equity == 10000.0
    assert eng_buddy.equity == 10000.0

    eng_master.open_trade('BTCUSDT', '1h', 1, 80000.0, 79000.0, 81000.0, 82000.0, spec=SPEC)
    eng_buddy.open_trade('SOLUSDT', '1h', 1, 100.0, 95.0, 110.0, 115.0, spec=dict(SPEC, priceTick=0.01))

    assert 'BTCUSDT' in [p.symbol for p in eng_master.open_positions.values()]
    assert 'SOLUSDT' not in [p.symbol for p in eng_master.open_positions.values()]
    assert 'SOLUSDT' in [p.symbol for p in eng_buddy.open_positions.values()]

    re_master = PaperTradingEngine(conn=conn, account_id='master')
    re_buddy = PaperTradingEngine(conn=conn, account_id='buddy')
    assert list(re_master.open_positions.values())[0].symbol == 'BTCUSDT'
    assert list(re_buddy.open_positions.values())[0].symbol == 'SOLUSDT'
