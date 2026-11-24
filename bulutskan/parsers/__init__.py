"""Checkov, KICS, Trivy va Grype JSON hisobotlari parserlari.

Har bir parser vosita hisobotini :class:`bulutskan.core.models.ToolReport`
ko‘rinishiga keltiradi. Mantiq dissertatsiyaning ``analyze.py`` va
``stats3.py`` skriptlaridan ko‘chirilgan va kengaytirilgan.
"""

from bulutskan.parsers.base import ParseError, load_json
from bulutskan.parsers.checkov import parse_checkov
from bulutskan.parsers.grype import parse_grype
from bulutskan.parsers.kics import parse_kics
from bulutskan.parsers.trivy import parse_trivy_config, parse_trivy_image

__all__ = [
    "ParseError",
    "load_json",
    "parse_checkov",
    "parse_grype",
    "parse_kics",
    "parse_trivy_config",
    "parse_trivy_image",
]
