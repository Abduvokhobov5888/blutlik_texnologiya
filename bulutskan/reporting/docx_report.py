"""O‘zbek tilidagi DOCX hisobot (python-docx).

Bo‘limlar: umumiy xulosa, EOL ogohlantirishi, jiddiylik bo‘yicha jadval,
konsensus va Jaccard, ground truth (namoyish fayllari), ishlamagan vositalar,
tuzatish tavsiyalari, vosita versiyalari va digestlari, metodologiya.
"""

from __future__ import annotations

import io
from datetime import timedelta
from typing import Any

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor
from docx.table import Table

from bulutskan import __version__
from bulutskan.core.eol import EOL_WARNING_UZ
from bulutskan.reporting.scan_view import CONSENSUS_UZ, CPE_UZ, STATUS_UZ, ScanView, severity_order
from bulutskan.scanner.runs import FAILURE_CODES

RED = RGBColor(0xB0, 0x1B, 0x1B)
GREY = RGBColor(0x55, 0x5B, 0x66)
SEV_UZ = {"CRITICAL": "Kritik", "HIGH": "Yuqori", "MEDIUM": "O‘rta", "LOW": "Past", "INFO": "Axborot",
          "UNKNOWN": "Noma’lum"}


def _num(value: float | None, digits: int = 3) -> str:
    return "—" if value is None else f"{value:.{digits}f}".replace(".", ",")


def _local(dt: Any) -> str:
    return (dt + timedelta(hours=5)).strftime("%Y-%m-%d %H:%M") + " (UTC+5)" if dt else "—"


def _shade(cell: Any, hex_color: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tc_pr.append(shd)


def _table(doc: Any, header: list[str], rows: list[list[str]]) -> Table:
    table: Table = doc.add_table(rows=1, cols=len(header))
    table.style = "Table Grid"
    for i, text in enumerate(header):
        cell = table.rows[0].cells[i]
        cell.text = text
        cell.paragraphs[0].runs[0].bold = True
        _shade(cell, "E8EEF7")
    for row in rows:
        cells = table.add_row().cells  # type: ignore[no-untyped-call]
        for i, text in enumerate(row):
            cells[i].text = str(text)
    return table


def build_docx(view: ScanView) -> bytes:
    """Hisobotni DOCX baytlari sifatida qaytaradi."""
    scan = view.scan
    doc = Document()
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10.5)

    counter = [0]

    def heading(text: str) -> None:
        counter[0] += 1
        doc.add_heading(f"{counter[0]}. {text}", level=1)

    title = doc.add_heading("BulutSkan tekshiruv hisoboti", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.LEFT
    kind = "IaC fayllari" if scan.kind == "iac" else "Konteyner obrazi"
    meta = [
        ("Obyekt", scan.target),
        ("Turi", kind + (" (namoyish: III bob eksperimenti)" if scan.is_demo else "")),
        ("Holati", STATUS_UZ.get(scan.status, scan.status)),
        ("Boshlangan", _local(scan.created_at)),
        ("Tugagan", _local(scan.finished_at)),
        ("Tekshiruv ID", scan.uid),
        ("Foydalanuvchi", view.owner or "—"),
        ("Hisobot", f"BulutSkan {__version__}"),
    ]
    _table(doc, ["Maydon", "Qiymat"], [[k, v] for k, v in meta])

    summary = scan.summary or {}
    consensus = scan.consensus or {}
    gbs = view.groups_by_severity
    heading("Umumiy xulosa")
    lines = [
        f"Jami {summary.get('groups_total', 0)} ta noyob topilma (konsensus guruhi): "
        f"kritik — {gbs.get('CRITICAL', 0)}, yuqori — {gbs.get('HIGH', 0)}, o‘rta — {gbs.get('MEDIUM', 0)}, "
        f"past — {gbs.get('LOW', 0)}, noma’lum — {gbs.get('UNKNOWN', 0)}.",
        f"Tasdiqlangan (kamida ikki vosita topgan): {consensus.get('confirmed', 0)}; "
        f"tekshirish talab etiladi: {consensus.get('needs_review', 0)}"
        + (f"; CPE asosida: {consensus.get('cpe_suspect', 0)}" if scan.kind == "image" else "") + ".",
    ]
    if scan.jaccard:
        pairs = ", ".join(f"{k.replace('|', ' – ').replace('all', 'uchala vosita')}: {_num(v)}"
                          for k, v in scan.jaccard.items())
        lines.append(f"Vositalar mosligi (Jaccard): {pairs}"
                     + (f"; asosiy Jaccard: {_num(scan.jaccard_core)}" if scan.jaccard_core is not None else "") + ".")
    if scan.failures:
        lines.append("Tekshiruv qisman: " + ", ".join(f["tool"] for f in scan.failures)
                     + " ishlamadi (“Ishlamagan vositalar” bo‘limiga qarang).")
    if scan.purged_at:
        lines.append("Saqlash muddati o‘tgani uchun topilmalar tafsilotlari o‘chirilgan; faqat xulosa qolgan.")
    for line in lines:
        doc.add_paragraph(line, style="List Bullet")

    if view.is_eol:
        heading("Eskirgan bazaviy obraz")
        p = doc.add_paragraph()
        run = p.add_run(EOL_WARNING_UZ)
        run.bold = True
        run.font.size = Pt(13)
        run.font.color.rgb = RED
        for reason in (scan.eol or {}).get("reasons", []):
            doc.add_paragraph(str(reason.get("detail", "")), style="List Bullet")
        for entry in (scan.eol or {}).get("entries", []):
            doc.add_paragraph(f"{entry.get('name')}: qo‘llab-quvvatlash {entry.get('eol')} da tugagan",
                              style="List Bullet")
    else:
        heading("Bazaviy obraz")
        doc.add_paragraph("Eskirgan bazaviy obraz aniqlanmadi." if scan.kind == "image"
                          else "IaC tekshiruvi: bazaviy obraz tekshiruvi qo‘llanmaydi.")

    heading("Jiddiylik bo‘yicha jadval")
    sev = severity_order()
    rows = [[tool] + [str(counts.get(s, 0)) for s in sev] for tool, counts in view.severity_table.items()]
    rows.append(["Konsensus guruhlari"] + [str(gbs.get(s, 0)) for s in sev])
    _table(doc, ["Vosita"] + [SEV_UZ[s] for s in sev], rows)
    note = doc.add_paragraph("“Noma’lum” — vosita darajani bermagan (Checkov’ning ochiq versiyasi). Platforma uni "
                             "o‘ylab topmaydi; guruh darajasi boshqa vositalar bergan ma’lum darajadan olinadi.")
    note.runs[0].font.color.rgb = GREY

    heading("Konsensus")
    doc.add_paragraph(
        "Bir xil zaiflik (CVE) yoki xato toifasini kamida ikkita vosita topgan bo‘lsa — “Tasdiqlangan”, bittasi "
        "topgan bo‘lsa — “Tekshirish talab etiladi”. Grype faqat CPE yoki binar fayl orqali topgan zaiflik "
        f"alohida belgilanadi: “{CPE_UZ}”."
    )
    if scan.jaccard:
        _table(doc, ["Juftlik", "Jaccard"],
               [[k.replace("|", " – ").replace("all", "uchala vosita"), _num(v)] for k, v in scan.jaccard.items()])
    top = [g for g in view.groups if g.severity in ("CRITICAL", "HIGH")][:30]
    if top:
        doc.add_paragraph("Kritik va yuqori darajali topilmalar (ko‘pi bilan 30 ta):")
        _table(doc, ["Daraja", "Topilma", "Vositalar", "Belgi"],
               [[SEV_UZ.get(g.severity, g.severity), (g.key if scan.kind == "image" else g.title)[:120],
                 g.tools.replace(",", ", "),
                 CONSENSUS_UZ.get(g.consensus, g.consensus) + (f"; {CPE_UZ}" if g.cpe_suspect else "")]
                for g in top])

    gt = scan.ground_truth or {}
    if gt:
        heading("Ground truth bo‘yicha baholash (namoyish fayllari)")
        if not gt.get("complete", True):
            p = doc.add_paragraph("Natija to‘liq emas: biror vosita ishlamagan, III bob bilan solishtirib bo‘lmaydi.")
            p.runs[0].font.color.rgb = RED
        _table(doc, ["Vosita", "Topildi", "Recall", "Precision", "F1"],
               [[n, f"{t['tp']}/{t['gt']}", _num(t["recall"]), _num(t["precision"]), _num(t["f1"])]
                for n, t in gt.get("tools", {}).items()])
        if gt.get("missed_by_all"):
            doc.add_paragraph("Hech bir vosita topmagan xatolar: " + ", ".join(gt["missed_by_all"]))

    heading("Ishlamagan vositalar")
    if scan.failures:
        _table(doc, ["Vosita", "Sabab", "Chiqish kodi", "Tushuntirish"],
               [[f["tool"], FAILURE_CODES.get(f.get("reason_code") or "exit_code", ""),
                 str(f.get("returncode", "—")), (f.get("error") or "")[:400]] for f in scan.failures])
    else:
        doc.add_paragraph("Barcha vositalar muvaffaqiyatli ishladi.")

    heading("Tuzatish tavsiyalari")
    if scan.kind == "image":
        if view.fixes:
            doc.add_paragraph("Quyidagi paketlarni ko‘rsatilgan versiyaga yangilang (eng jiddiylari birinchi):")
            _table(doc, ["Paket", "O‘rnatilgan", "Tuzatilgan versiya", "Daraja", "Zaifliklar"],
                   [[f["package"], f["installed"] or "—", ", ".join(f["fixed"])[:80], SEV_UZ.get(f["severity"], ""),
                     str(len(f["ids"]))] for f in view.fixes[:40]])
        else:
            doc.add_paragraph("Tuzatilgan versiyasi e’lon qilingan zaiflik topilmadi.")
        if view.is_eol:
            doc.add_paragraph("Bazaviy obrazni qo‘llab-quvvatlanadigan versiyaga almashtiring: eskirgan obrazda "
                              "skanerlar natijalari to‘liq emas.", style="List Bullet")
    else:
        confirmed = [g for g in view.groups if not g.uncategorized and g.consensus == "confirmed"][:40]
        if confirmed:
            doc.add_paragraph("Tasdiqlangan xatolar (avval shularni tuzating):")
            _table(doc, ["Toifa", "Fayl", "Tavsif", "Vositalar"],
                   [[f"{g.category} {g.title}", (g.targets[0] if g.targets else ""), g.description or "",
                     g.tools.replace(",", ", ")] for g in confirmed])
        else:
            doc.add_paragraph("Tasdiqlangan xato topilmadi.")

    heading("Vosita versiyalari va digestlari")
    _table(doc, ["Vosita", "Versiya", "Obraz (digest)", "Davomiyligi, s", "Topilmalar", "Baza sanasi"],
           [[r.tool, r.tool_version or "—", r.image_ref or "—", _num(r.duration_s, 1), str(r.finding_count),
             str(((r.metadata_json or {}).get("db") or {}).get("built")
                 or (scan.integrity or {}).get("databases", {}).get("trivy" if r.tool == "trivy" else r.tool) or "—")]
            for r in view.tool_runs])
    doc.add_paragraph("Vositalar faqat sha256 digest orqali, tarmoqsiz (--network none), faqat o‘qish rejimidagi "
                      "konteynerlarda ishga tushirilgan.")

    heading("Metodologiya")
    doc.add_paragraph(
        "Natijalar Checkov, KICS va Trivy (IaC) hamda Trivy va Grype (obrazlar) hisobotlarini yagona modelga "
        "keltirish, takrorlarni birlashtirish va vositalararo konsensus orqali olingan. Hisob-kitob "
        "dissertatsiyaning III bobidagi analyze.py va stats3.py skriptlari bilan bir xil."
    )
    p = doc.add_paragraph("Ma’lumotlar O‘zbekiston hududidan chiqmaydi.")
    p.runs[0].italic = True
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
