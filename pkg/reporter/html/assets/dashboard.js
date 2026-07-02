/* PolicyGuard dashboard interactivity — operates entirely over the embedded
 * findings data island. No network calls; nothing is faked.
 *
 * Exposes window.initDashboard() so it can be (re-)run against freshly injected
 * markup — the live GUI calls it after each scan. It self-runs once on load for
 * the standalone static report.
 *
 * The filter/search/"/" handlers are bound ONCE at module scope and always read
 * the current DOM (querySelectorAll on each event), so re-running initDashboard
 * after a new scan can't stack stale listeners or capture an old row set. */
(function () {
  "use strict";

  var reduce = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Shared filter state across all bindings.
  var state = { filter: "all", query: "" };

  function currentRows() {
    return Array.prototype.slice.call(document.querySelectorAll("#rows .row"));
  }

  function rowMatches(row) {
    var sev = row.getAttribute("data-sev");
    if (state.filter !== "all" && sev !== state.filter) {
      // "low" filter also includes "info" findings.
      if (!(state.filter === "low" && sev === "info")) return false;
    }
    if (state.query) {
      if (row.textContent.toLowerCase().indexOf(state.query) === -1) return false;
    }
    return true;
  }

  function applyFilter() {
    var rows = currentRows();
    var visible = 0;
    rows.forEach(function (row) {
      var show = rowMatches(row);
      row.hidden = !show;
      if (show) visible++;
    });
    var emptyEl = document.getElementById("empty");
    if (emptyEl) emptyEl.hidden = !(rows.length > 0 && visible === 0);
  }

  function selectFinding(index) {
    currentRows().forEach(function (row) {
      row.classList.toggle("selected", row.getAttribute("data-index") === String(index));
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-detail]"), function (d) {
      d.hidden = d.getAttribute("data-detail") !== String(index);
    });
  }

  // --- global bindings (once) ---
  var search = document.getElementById("search");
  if (search) {
    search.addEventListener("input", function () {
      state.query = search.value.trim().toLowerCase();
      applyFilter();
    });
  }

  document.addEventListener("keydown", function (e) {
    var sb = document.getElementById("search");
    if (e.key === "/" && sb && document.activeElement !== sb && !sb.disabled) {
      e.preventDefault();
      sb.focus();
    }
  });

  // Segmented filter + row selection are delegated from the document, so they
  // keep working no matter how many times the results fragment is replaced.
  document.addEventListener("click", function (e) {
    var seg = e.target.closest && e.target.closest(".seg");
    if (seg) {
      Array.prototype.forEach.call(document.querySelectorAll(".seg"), function (s) {
        s.classList.remove("active");
      });
      seg.classList.add("active");
      state.filter = seg.getAttribute("data-filter");
      applyFilter();
      return;
    }
    var row = e.target.closest && e.target.closest("#rows .row");
    if (row) selectFinding(row.getAttribute("data-index"));
  });

  document.addEventListener("keydown", function (e) {
    if (e.key !== "Enter" && e.key !== " ") return;
    var row = e.target.closest && e.target.closest("#rows .row");
    if (row) { e.preventDefault(); selectFinding(row.getAttribute("data-index")); }
  });

  // --- per-fragment init (re-run after each scan) ---
  function initDashboard() {
    // Reset filter state for the fresh result set and clear any prior query.
    state.filter = "all";
    state.query = "";
    if (search) search.value = "";
    Array.prototype.forEach.call(document.querySelectorAll(".seg"), function (s, i) {
      s.classList.toggle("active", i === 0); // first seg ("All") active
    });
    applyFilter();

    /* number roll-up */
    function rollUp(el) {
      var target = parseInt(el.getAttribute("data-count") || "0", 10);
      if (reduce || !target) { el.textContent = target.toLocaleString(); return; }
      var start = null, dur = 600;
      function step(ts) {
        if (start === null) start = ts;
        var p = Math.min((ts - start) / dur, 1);
        var eased = 1 - Math.pow(1 - p, 3);
        el.textContent = Math.round(target * eased).toLocaleString();
        if (p < 1) requestAnimationFrame(step);
        else el.textContent = target.toLocaleString();
      }
      requestAnimationFrame(step);
    }
    document.querySelectorAll(".stat-num").forEach(rollUp);

    /* pass-rate roll-up (one decimal) */
    var pr = document.getElementById("passrate-num");
    if (pr) {
      var prTarget = parseFloat(pr.getAttribute("data-value") || "0");
      if (reduce || !prTarget) {
        pr.textContent = prTarget.toFixed(1);
      } else {
        var s = null;
        (function () {
          function step(ts) {
            if (s === null) s = ts;
            var p = Math.min((ts - s) / 600, 1);
            var eased = 1 - Math.pow(1 - p, 3);
            pr.textContent = (prTarget * eased).toFixed(1);
            if (p < 1) requestAnimationFrame(step); else pr.textContent = prTarget.toFixed(1);
          }
          requestAnimationFrame(step);
        })();
      }
    }
  }

  window.initDashboard = initDashboard;

  // Self-run for the standalone static report (findings island present at load).
  if (document.getElementById("findings-data")) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", initDashboard);
    } else {
      initDashboard();
    }
  }
})();
