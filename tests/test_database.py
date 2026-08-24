from dracxx.database.db import init_db, get_session, FindingRow


def test_db_init_and_write():
    init_db()
    session = get_session()
    try:
        row = FindingRow(session_id="test", finding_id="F-TEST", title="t",
                          severity="LOW", confidence="INFO", target="x", asset="x", scanner="test")
        session.add(row)
        session.commit()
        found = session.query(FindingRow).filter_by(finding_id="F-TEST").first()
        assert found is not None
    finally:
        session.query(FindingRow).filter_by(finding_id="F-TEST").delete()
        session.commit()
        session.close()
