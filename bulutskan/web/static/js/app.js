/* BulutSkan: diagrammalar. Inline skript yo‘q (CSP: script-src 'self').
   Ma’lumotlar data-json atributida: HTMX (allowScriptTags=false) almashtirilgan
   qismdagi barcha <script> teglarini, shu jumladan application/json ni ham o‘chiradi. */
(function () {
  "use strict";
  var COLORS = { CRITICAL: "#8e1027", HIGH: "#d1382a", MEDIUM: "#d9900a", LOW: "#2f6fed", INFO: "#6b7487", UNKNOWN: "#b4bac6" };
  var charts = {};

  function data(id) {
    var el = document.getElementById(id);
    if (!el) return null;
    try { return JSON.parse(el.getAttribute("data-json")); } catch (e) { return null; }
  }
  function draw(id, config) {
    var canvas = document.getElementById(id);
    if (!canvas || typeof Chart === "undefined") return;
    if (charts[id]) charts[id].destroy();
    charts[id] = new Chart(canvas, config);
  }
  function dashboard() {
    var d = data("dashboard-data");
    if (!d) return;
    draw("chart-tools", { type: "bar", data: { labels: d.tools.labels, datasets: d.tools.severities.map(function (s) {
      return { label: s, data: d.tools.data[s], backgroundColor: COLORS[s] }; }) },
      options: { responsive: true, scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } } } });
    draw("chart-severity", { type: "doughnut", data: { labels: d.severity.labels, datasets: [{ data: d.severity.data,
      backgroundColor: d.severity.labels.map(function (s) { return COLORS[s]; }) }] }, options: { responsive: true } });
    draw("chart-jaccard", { type: "bar", data: { labels: d.jaccard.labels, datasets: [
      { label: "Jaccard", data: d.jaccard.j, backgroundColor: "#2f6fed" },
      { label: "Jaccard (CVE, CPE)", data: d.jaccard.j_core, backgroundColor: "#9db7f5" }] },
      options: { responsive: true, scales: { y: { min: 0, max: 1 } } } });
    draw("chart-timeline", { type: "line", data: { labels: d.timeline.labels, datasets: [{ label: "", data: d.timeline.data,
      borderColor: "#2f6fed", backgroundColor: "rgba(47,111,237,.15)", fill: true, tension: 0.25 }] },
      options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } });
  }
  function ahp() {
    var d = data("ahp-data");
    if (!d) return;
    draw("chart-ahp", { type: "bar", data: { labels: d.labels, datasets: [{ label: "", data: d.data,
      backgroundColor: d.labels.map(function (_, i) { return i < 3 ? "#2f6fed" : "#9db7f5"; }) }] },
      options: { indexAxis: "y", responsive: true, animation: false, plugins: { legend: { display: false } },
        scales: { x: { min: 0, max: 5 } } } });
  }
  function all() { dashboard(); ahp(); }
  document.addEventListener("DOMContentLoaded", all);
  document.addEventListener("htmx:afterSettle", all);
})();
