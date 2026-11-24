"""IaC topilmalarini xato toifalariga ajratish (``ground_truth.csv``).

Turli vositalarning qoida ID lari bir-biriga mos kelmaydi: Checkov
``CKV_AWS_20``, KICS UUID, Trivy ``AWS-0086``. Shu sababli ular xato
toifasi orqali moslashtiriladi. Toifalar va ularning regexlari
dissertatsiyaning ``ground_truth.csv`` faylidan olinadi.

Modulda ikki rejim bor:

* :func:`evaluate_ground_truth` — ``analyze.py`` ning IaC qismi aynan
  ko‘chirilgan. U namoyish fayllaridagi (``resources/iac``) 40 ta
  ataylab qilingan xato bo‘yicha aniqlik va to‘liqlikni hisoblaydi.
* :func:`categorize` — foydalanuvchi yuklagan ixtiyoriy fayllar uchun.
  Xuddi shu regex va istisno qoidalari ishlatiladi. Ground truth’dagi
  resurs tokeni o‘rniga resurs turi tekshiriladi: masalan, TF-10 (RDS
  shifrlash) faqat ``aws_db_instance`` turidagi bloklarga qo‘llanadi.
"""

from __future__ import annotations

import csv
import itertools
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bulutskan.core.models import Finding
from bulutskan.core.normalize import match_path

RESOURCES = Path(__file__).resolve().parent.parent / "resources"
DEFAULT_GROUND_TRUTH = RESOURCES / "ground_truth.csv"
DEFAULT_IAC_ROOT = RESOURCES / "iac"

# Terraform blokining sarlavhasi (analyze.py dagi regex bilan bir xil).
_TF_BLOCK = re.compile(r'\s*(resource|provider|variable|data)\s+"([^"]+)"(?:\s+"([^"]+)")?')

FAMILY_TERRAFORM = "terraform"
FAMILY_KUBERNETES = "kubernetes"
FAMILY_DOCKERFILE = "dockerfile"

_FAMILY_BY_PREFIX = {"TF": FAMILY_TERRAFORM, "K8S": FAMILY_KUBERNETES, "DF": FAMILY_DOCKERFILE}


@dataclass(frozen=True)
class TfBlock:
    """Terraform faylidagi yuqori darajali blok."""

    kind: str  # resource, provider, variable, data
    type: str  # aws_s3_bucket yoki provider nomi
    name: str | None  # resurs nomi (provider uchun yo‘q)

    @property
    def label(self) -> str:
        """``analyze.py`` dagi kabi: resurs nomi, bo‘lmasa tur."""
        return self.name or self.type


@dataclass(frozen=True)
class GroundTruthRule:
    """``ground_truth.csv`` ning bitta qatori."""

    id: str
    category: str
    insecure_file: str
    insecure_token: str
    secure_file: str
    secure_token: str
    regex: str
    exclude: str
    description: str
    resource_type: str | None = None  # resurs tokeni turidan olinadi

    @property
    def family(self) -> str:
        """Fayl oilasi: terraform, kubernetes yoki dockerfile."""
        return _FAMILY_BY_PREFIX[self.id.split("-", 1)[0]]

    def text_matches(self, text: str) -> bool:
        """Qoida ID + nomi matni regexga mos va istisnoga mos emas."""
        if not re.search(self.regex, text, re.I):
            return False
        return not (self.exclude and re.search(self.exclude, text, re.I))


@dataclass
class GroundTruth:
    """Toifalar to‘plami va namoyish fayllarining blok xaritalari."""

    rules: list[GroundTruthRule]
    #: GT fayl yo‘li → (qator raqami → blok). Faqat Terraform fayllari.
    block_maps: dict[str, dict[int, TfBlock | None]] = field(default_factory=dict)

    @classmethod
    def load(
        cls,
        csv_path: str | Path = DEFAULT_GROUND_TRUTH,
        iac_root: str | Path = DEFAULT_IAC_ROOT,
    ) -> GroundTruth:
        """CSV va namoyish fayllaridan to‘plamni yuklaydi."""
        with Path(csv_path).open(encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh, delimiter=";"))
        root = Path(iac_root)
        files = {r["insecure_file"] for r in rows} | {r["secure_file"] for r in rows}
        block_maps = {
            p: tf_block_map((root / p).read_text(encoding="utf-8"))
            for p in sorted(files)
            if p.endswith(".tf") and (root / p).is_file()
        }
        rules: list[GroundTruthRule] = []
        for r in rows:
            token = r["insecure_token"].strip()
            rtype = _token_type(token, block_maps.get(r["insecure_file"], {})) if token else None
            rules.append(
                GroundTruthRule(
                    id=r["id"].strip(),
                    category=r["category"].strip(),
                    insecure_file=r["insecure_file"].strip(),
                    insecure_token=token,
                    secure_file=r["secure_file"].strip(),
                    secure_token=r["secure_token"].strip(),
                    regex=r["regex"],
                    exclude=r["exclude"],
                    description=r["tavsif"].strip(),
                    resource_type=rtype,
                )
            )
        return cls(rules=rules, block_maps=block_maps)

    def by_id(self) -> dict[str, GroundTruthRule]:
        """ID → qoida."""
        return {r.id: r for r in self.rules}


def tf_block_map(source: str) -> dict[int, TfBlock | None]:
    """Terraform fayli qatorlarini ular tegishli yuqori darajali blokka bog‘laydi.

    ``analyze.tf_line_map`` mantiqi: blok sarlavhasi qator boshidan
    (bo‘shliqsiz) yozilgan bo‘lishi kerak; birinchi blokdan oldingi
    qatorlar hech qaysi blokka tegishli emas.
    """
    result: dict[int, TfBlock | None] = {}
    current: TfBlock | None = None
    for number, line in enumerate(source.splitlines(), 1):
        m = _TF_BLOCK.match(line)
        if m and not line.startswith(" "):
            current = TfBlock(kind=m.group(1), type=m.group(2), name=m.group(3))
        result[number] = current
    return result


def _token_type(token: str, block_map: Mapping[int, TfBlock | None]) -> str | None:
    for block in block_map.values():
        if block is not None and block.name == token:
            return block.type
    return None


def _token_pattern(token: str) -> re.Pattern[str]:
    # analyze.token_hit: oldida harf/raqam/_ bo‘lmasin, keyin harf/raqam bo‘lmasin.
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9])")


def _finding_text(f: Finding) -> str:
    return f"{f.rule_id} {f.title}".lower()


def _resource_text(f: Finding) -> str:
    return " ".join(x for x in (f.resource, f.resource_name) if x)


def token_hit(token: str, finding: Finding, gt: GroundTruth) -> bool:
    """Topilma ground truth’dagi resurs tokeniga tegishlimi (``analyze.token_hit``)."""
    if not token:
        return True
    pat = _token_pattern(token)
    if pat.search(_resource_text(finding)):
        return True
    path = match_path(finding.target)
    for gt_path, block_map in gt.block_maps.items():
        if path.endswith(gt_path) and finding.line_start:
            block = block_map.get(finding.line_start)
            if block is not None and pat.search(block.label):
                return True
    return False


def gt_match(finding: Finding, rule: GroundTruthRule, side: str, gt: GroundTruth) -> bool:
    """``analyze.match``: topilma ``side`` (insecure/secure) faylidagi xatoga mosmi."""
    file = rule.insecure_file if side == "insecure" else rule.secure_file
    token = rule.insecure_token if side == "insecure" else rule.secure_token
    if not match_path(finding.target).endswith(match_path(file)):
        return False
    if not rule.text_matches(_finding_text(finding)):
        return False
    return token_hit(token, finding, gt)


# ---------------------------------------------------------------- baholash


@dataclass(frozen=True)
class ToolEvaluation:
    """Bitta vositaning ground truth bo‘yicha natijasi."""

    tool: str
    gt: int
    tp: int
    fp: int
    recall: float
    precision: float
    f1: float
    detected_ids: tuple[str, ...]
    fp_ids: tuple[str, ...]
    groups: dict[str, dict[str, int]]
    findings_total: int
    findings_insecure: int
    findings_secure: int
    findings_unmatched_insecure: int
    matched_rules: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class GroundTruthEvaluation:
    """Barcha vositalar natijasi, juftliklar mosligi va hech kim topmagan xatolar."""

    tools: dict[str, ToolEvaluation]
    overlap: dict[str, dict[str, float]]
    missed_by_all: tuple[str, ...]


def evaluate_ground_truth(
    findings_by_tool: Mapping[str, Sequence[Finding]],
    gt: GroundTruth,
) -> GroundTruthEvaluation:
    """``analyze.py`` ning IaC baholash qismi.

    Har bir GT xatosi uchun: xatoli faylda kamida bitta mos topilma bo‘lsa
    TP, xavfsiz faylda bo‘lsa FP. Topilmalar deduplikatsiyasiz beriladi.
    """
    tools: dict[str, ToolEvaluation] = {}
    for tool, fs in findings_by_tool.items():
        tp: dict[str, bool] = {}
        fp: dict[str, bool] = {}
        used: set[int] = set()
        matched: dict[str, tuple[str, ...]] = {}
        for rule in gt.rules:
            hits = [i for i, x in enumerate(fs) if gt_match(x, rule, "insecure", gt)]
            fhits = [i for i, x in enumerate(fs) if gt_match(x, rule, "secure", gt)]
            tp[rule.id] = bool(hits)
            fp[rule.id] = bool(fhits)
            used.update(hits)
            matched[rule.id] = tuple(sorted({f"{fs[i].rule_id} {fs[i].title}" for i in hits}))
        n = len(gt.rules)
        tp_n = sum(tp.values())
        fp_n = sum(fp.values())
        precision = tp_n / (tp_n + fp_n) if tp_n + fp_n else 0.0
        recall = tp_n / n if n else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        groups: dict[str, dict[str, int]] = {}
        for prefix in ("TF", "K8S", "DF"):
            ids = [r.id for r in gt.rules if r.id.startswith(prefix)]
            groups[prefix] = {
                "n": len(ids),
                "tp": sum(tp[i] for i in ids),
                "fp": sum(fp[i] for i in ids),
            }
        paths = [match_path(x.target) for x in fs]
        tools[tool] = ToolEvaluation(
            tool=tool,
            gt=n,
            tp=tp_n,
            fp=fp_n,
            recall=recall,
            precision=precision,
            f1=f1,
            detected_ids=tuple(sorted(k for k, v in tp.items() if v)),
            fp_ids=tuple(sorted(k for k, v in fp.items() if v)),
            groups=groups,
            findings_total=len(fs),
            findings_insecure=sum(1 for p in paths if "/insecure/" in p),
            findings_secure=sum(1 for p in paths if "/secure/" in p),
            findings_unmatched_insecure=sum(
                1 for i, p in enumerate(paths) if "/insecure/" in p and i not in used
            ),
            matched_rules=matched,
        )
    overlap: dict[str, dict[str, float]] = {}
    for a, b in itertools.combinations(tools, 2):
        sa, sb = set(tools[a].detected_ids), set(tools[b].detected_ids)
        union = sa | sb
        overlap[f"{a} vs {b}"] = {
            "both": len(sa & sb),
            "only_a": len(sa - sb),
            "only_b": len(sb - sa),
            "jaccard": len(sa & sb) / len(union) if union else 0.0,
        }
    detected_any: set[str] = set().union(*(set(t.detected_ids) for t in tools.values()))
    missed = tuple(sorted({r.id for r in gt.rules} - detected_any)) if tools else ()
    return GroundTruthEvaluation(tools=tools, overlap=overlap, missed_by_all=missed)


# ------------------------------------------------- ixtiyoriy fayllar uchun


def file_family(path: str) -> str | None:
    """Fayl yo‘lidan uning oilasini aniqlaydi."""
    p = match_path(path)
    name = p.rsplit("/", 1)[-1]
    if p.endswith((".tf", ".tf.json", ".tfvars", ".hcl")):
        return FAMILY_TERRAFORM
    if name in {"dockerfile", "containerfile"} or name.startswith("dockerfile.") or name.endswith(
        ".dockerfile"
    ):
        return FAMILY_DOCKERFILE
    if p.endswith((".yaml", ".yml", ".json")):
        return FAMILY_KUBERNETES
    return None


_RESOURCE_ADDRESS = re.compile(r"^([A-Za-z0-9_\-]+)[.\[]")


def finding_block(
    finding: Finding,
    block_maps: Mapping[str, Mapping[int, TfBlock | None]],
) -> TfBlock | None:
    """Terraform topilmasi tegishli blokni topadi.

    Avval tekshirilgan faylning qator xaritasi ishlatiladi, u bo‘lmasa resurs
    manzili (``aws_s3_bucket.nom`` yoki ``aws_s3_bucket[nom]``) tahlil qilinadi.
    """
    path = match_path(finding.target)
    block_map = block_maps.get(path)
    if block_map is not None and finding.line_start:
        block = block_map.get(finding.line_start)
        if block is not None:
            return block
    for candidate in (finding.resource, finding.resource_name):
        m = _RESOURCE_ADDRESS.match(candidate or "")
        if m:
            return TfBlock(kind="resource", type=m.group(1), name=None)
    return None


def categorize(
    finding: Finding,
    gt: GroundTruth,
    block_maps: Mapping[str, Mapping[int, TfBlock | None]] | None = None,
) -> list[str]:
    """Topilmaga mos keladigan toifa ID larini qaytaradi.

    ``block_maps`` — tekshirilgan Terraform fayllarining qator xaritalari
    (kalit :func:`match_path` ko‘rinishidagi yo‘l). Resurs tokeni bo‘lgan
    GT qoidasi faqat shu tokenning resurs turi bilan boshlanadigan bloklarga
    qo‘llanadi (``aws_s3_bucket`` → ``aws_s3_bucket_acl`` ham mos).
    """
    family = file_family(finding.target)
    if family is None:
        return []
    text = _finding_text(finding)
    block: TfBlock | None = None
    block_resolved = False
    matched: list[str] = []
    for rule in gt.rules:
        if rule.family != family or not rule.text_matches(text):
            continue
        if rule.resource_type:
            if not block_resolved:
                block = finding_block(finding, block_maps or {})
                block_resolved = True
            if block is None or not block.type.startswith(rule.resource_type):
                continue
        matched.append(rule.id)
    return matched


def build_block_maps(sources: Mapping[str, str]) -> dict[str, dict[int, TfBlock | None]]:
    """Tekshirilgan fayllar matnidan (yo‘l → matn) Terraform qator xaritalari."""
    return {
        match_path(path): tf_block_map(source)
        for path, source in sources.items()
        if file_family(path) == FAMILY_TERRAFORM
    }


def load_sources(root: str | Path, paths: Iterable[str]) -> dict[str, str]:
    """``root`` ichidagi fayllarni o‘qiydi (o‘qib bo‘lmaganlari o‘tkazib yuboriladi)."""
    base = Path(root)
    out: dict[str, str] = {}
    for rel in paths:
        candidate = (base / rel).resolve()
        if base.resolve() not in candidate.parents or not candidate.is_file():
            continue
        try:
            out[rel] = candidate.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    return out


def describe(rule_ids: Iterable[str], gt: GroundTruth) -> list[dict[str, Any]]:
    """Toifa ID lari uchun nom va tavsif (interfeys va hisobot uchun)."""
    index = gt.by_id()
    return [
        {"id": i, "category": index[i].category, "description": index[i].description}
        for i in rule_ids
        if i in index
    ]
