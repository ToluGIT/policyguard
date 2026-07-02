/* PolicyGuard GUI — import/paste Terraform, scan via the local server, and
 * render the same dashboard the static report uses. No third-party deps.
 * The dashboard interactivity (filter/search/select/roll-up) lives in
 * /assets/dashboard.js, which exposes window.initDashboard(); we call it after
 * injecting each freshly-scanned fragment. */
(function () {
  "use strict";

  var fileInput = document.getElementById("file-input");
  var dropzone = document.getElementById("dropzone");
  var fileList = document.getElementById("filelist");
  var paste = document.getElementById("paste");
  var runBtn = document.getElementById("run-btn");
  var statusEl = document.getElementById("status");
  var errorEl = document.getElementById("error");
  var results = document.getElementById("results");
  var placeholder = document.getElementById("placeholder");

  var chosen = []; // File objects

  function refresh() {
    fileList.innerHTML = "";
    chosen.forEach(function (f, i) {
      var chip = document.createElement("span");
      chip.className = "filechip";
      chip.appendChild(document.createTextNode(f.name + " "));
      var x = document.createElement("span");
      x.className = "x";
      x.textContent = "x";
      x.setAttribute("role", "button");
      x.setAttribute("aria-label", "remove " + f.name);
      x.addEventListener("click", function (e) {
        e.preventDefault();
        chosen.splice(i, 1);
        refresh();
      });
      chip.appendChild(x);
      fileList.appendChild(chip);
    });
    var has = chosen.length > 0 || paste.value.trim().length > 0;
    runBtn.disabled = !has;
    if (has && statusEl.dataset.state !== "scanning") {
      statusEl.textContent = chosen.length
        ? chosen.length + " file(s) ready — press Scan."
        : "Pasted configuration ready — press Scan.";
    } else if (!has && statusEl.dataset.state !== "scanning") {
      statusEl.textContent = "Add a file or paste configuration, then Scan.";
    }
  }

  function addFiles(fileListLike) {
    Array.prototype.forEach.call(fileListLike, function (f) {
      if (!chosen.some(function (c) { return c.name === f.name && c.size === f.size; })) {
        chosen.push(f);
      }
    });
    refresh();
  }

  fileInput.addEventListener("change", function () { addFiles(fileInput.files); fileInput.value = ""; });
  paste.addEventListener("input", refresh);

  ["dragenter", "dragover"].forEach(function (ev) {
    dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.add("drag"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.remove("drag"); });
  });
  dropzone.addEventListener("drop", function (e) {
    if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files);
  });

  function setError(msg) {
    if (!msg) { errorEl.hidden = true; errorEl.textContent = ""; return; }
    errorEl.hidden = false;
    errorEl.textContent = msg;
  }

  function setScanning(on) {
    statusEl.dataset.state = on ? "scanning" : "";
    runBtn.disabled = on;
    if (on) {
      statusEl.innerHTML = "";
      var sp = document.createElement("span");
      sp.className = "spinner";
      statusEl.appendChild(sp);
      statusEl.appendChild(document.createTextNode(" Scanning…"));
    }
  }

  runBtn.addEventListener("click", function () {
    var fd = new FormData();
    chosen.forEach(function (f) { fd.append("files", f, f.name); });
    if (paste.value.trim()) fd.append("content", paste.value);

    setError(null);
    setScanning(true);
    if (placeholder) placeholder.style.display = "none";

    fetch("/api/scan", { method: "POST", body: fd })
      .then(function (res) {
        return res.text().then(function (body) {
          if (!res.ok) throw new Error(body || ("scan failed (" + res.status + ")"));
          return body;
        });
      })
      .then(function (html) {
        results.innerHTML = html;
        if (window.initDashboard) window.initDashboard();
        var search = document.getElementById("search");
        if (search) {
          search.disabled = false;
          search.placeholder = "Filter findings — resource, policy, file…";
        }
        setScanning(false);
        statusEl.textContent = "Scan complete — use the filter or search to narrow findings.";
      })
      .catch(function (err) {
        setScanning(false);
        statusEl.textContent = "Add a file or paste configuration, then Scan.";
        setError(err.message || "Scan failed.");
        if (placeholder && !results.querySelector(".grid")) placeholder.style.display = "";
      });
  });

  refresh();
})();
