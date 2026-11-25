"""Natijani bazaga saqlash: sonlar real ma’lumot bilan bir xil qoladi."""

from sqlalchemy import func, select

from bulutskan.core.consensus import ConsensusLabel
from bulutskan.security.workspace import new_uid
from bulutskan.storage.repo import save_outcome, scan_by_uid
from bulutskan.storage.tables import FindingGroupRow, FindingRow, Scan, ToolRunRow, group_members
from tests.conftest import ch3_row
from tests.helpers import iac_outcome, image_outcome


def _save(db, outcome):
    uid = new_uid()
    with db.session() as s:
        scan = Scan(uid=uid, kind=outcome.kind.value, target=outcome.target, status="running")
        s.add(scan)
        s.flush()
        save_outcome(s, scan, outcome)
    return uid


def test_image_outcome_roundtrip(db) -> None:
    outcome = image_outcome("nginx:1.21")
    uid = _save(db, outcome)
    row = ch3_row("nginx:1.21")
    with db.session() as s:
        scan = scan_by_uid(s, uid)
        assert scan is not None and scan.status == "done"
        assert abs(scan.jaccard["trivy|grype"] - row["j"]) < 1e-12
        assert abs(scan.jaccard_core - row["j_core"]) < 1e-12
        assert scan.consensus["confirmed"] == row["common"]
        assert scan.consensus["key_sets"] == {"trivy": row["t_n"], "grype": row["g_n"]}
        assert scan.eol["is_eol"] is True
        n_findings = s.scalar(select(func.count()).select_from(FindingRow).where(FindingRow.scan_id == scan.id))
        assert n_findings == sum(len(r.report.findings) for r in outcome.tool_runs if r.report)
        n_groups = s.scalar(select(func.count()).select_from(FindingGroupRow).where(FindingGroupRow.scan_id == scan.id))
        assert n_groups == row["common"] + row["only_t"] + row["only_g"]
        confirmed = s.scalar(select(func.count()).select_from(FindingGroupRow).where(
            FindingGroupRow.scan_id == scan.id, FindingGroupRow.consensus == ConsensusLabel.CONFIRMED.value))
        assert confirmed == row["common"]
        assert s.scalar(select(func.count()).select_from(group_members)) >= n_groups
        runs = list(s.scalars(select(ToolRunRow).where(ToolRunRow.scan_id == scan.id)))
        assert {r.tool for r in runs} == {"trivy", "grype"}
        assert scan.summary["severity_table"]["trivy"]["CRITICAL"] == sum(
            1 for f in outcome.reports[outcome.tool_runs[0].tool].findings if f.severity.value == "CRITICAL")


def test_iac_outcome_keeps_ground_truth(db, summary) -> None:
    uid = _save(db, iac_outcome())
    with db.session() as s:
        scan = scan_by_uid(s, uid)
        assert scan is not None
        gt = scan.ground_truth
        assert gt["complete"] is True
        assert gt["tools"]["Checkov"]["tp"] == summary["iac_summary"]["Checkov"]["tp"]
        assert gt["missed_by_all"] == summary["missed_by_all"]


def test_deleting_scan_cascades(db) -> None:
    uid = _save(db, image_outcome("alpine:3.20"))
    with db.session() as s:
        scan = scan_by_uid(s, uid)
        s.delete(scan)
    with db.session() as s:
        assert s.scalar(select(func.count()).select_from(FindingRow)) == 0
        assert s.scalar(select(func.count()).select_from(FindingGroupRow)) == 0
