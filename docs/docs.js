(function () {
  "use strict";

  // Scroll progress
  var progressEl = document.querySelector(".scroll-progress");
  if (progressEl) {
    var raf = false;
    window.addEventListener("scroll", function () {
      if (!raf) {
        raf = true;
        requestAnimationFrame(function () {
          var h = document.documentElement;
          var pct = h.scrollHeight > h.clientHeight ? h.scrollTop / (h.scrollHeight - h.clientHeight) : 0;
          progressEl.style.transform = "scaleX(" + pct + ")";
          raf = false;
        });
      }
    }, { passive: true });
  }

  // Back to top
  var btt = document.querySelector(".back-to-top");
  if (btt) {
    var bttRaf = false;
    window.addEventListener("scroll", function () {
      if (!bttRaf) {
        bttRaf = true;
        requestAnimationFrame(function () {
          btt.classList.toggle("visible", (window.scrollY || 0) > 400);
          bttRaf = false;
        });
      }
    }, { passive: true });
    btt.addEventListener("click", function () { window.scrollTo({ top: 0, behavior: "smooth" }); });
  }

  // Theme toggle — isolated, runs on every page
  (function () {
    var btn = document.querySelector(".theme-toggle");
    if (!btn) return;
    function isLight() { return document.documentElement.getAttribute("data-theme") === "light"; }
    function sync() { btn.setAttribute("aria-label", isLight() ? "Switch to dark theme" : "Switch to light theme"); }
    sync();
    btn.addEventListener("click", function () {
      var apply = function () {
        if (isLight()) {
          document.documentElement.removeAttribute("data-theme");
          try { localStorage.setItem("caddy-docs-theme", "dark"); } catch (e2) {}
        } else {
          document.documentElement.setAttribute("data-theme", "light");
          try { localStorage.setItem("caddy-docs-theme", "light"); } catch (e3) {}
        }
        sync();
      };
      document.documentElement.classList.add("theme-transition");
      if (document.startViewTransition) document.startViewTransition(apply);
      else apply();
      window.setTimeout(function () { document.documentElement.classList.remove("theme-transition"); }, 420);
    });
  })();

  // Copy buttons
  document.querySelectorAll("pre").forEach(function (pre) {
    if (pre.querySelector(".copy-btn")) return;
    var btn = document.createElement("button");
    btn.className = "copy-btn";
    btn.textContent = "Copy";
    btn.setAttribute("aria-label", "Copy code");
    btn.addEventListener("click", function () {
      var code = pre.querySelector("code");
      var text = (code ? code.textContent : pre.textContent).trim();
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = "Copied!";
        btn.classList.add("copied");
        setTimeout(function () { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1500);
      });
    });
    pre.appendChild(btn);
  });

  // Tabs (quickstart OS variants, etc.)
  document.querySelectorAll(".tabs").forEach(function (tabs) {
    var btns = tabs.querySelectorAll(".tab-btn");
    var panels = tabs.querySelectorAll(".tab-panel");
    btns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var target = btn.getAttribute("data-tab");
        btns.forEach(function (b) { b.classList.toggle("active", b === btn); b.setAttribute("aria-selected", b === btn ? "true" : "false"); });
        panels.forEach(function (p) { p.classList.toggle("active", p.getAttribute("data-panel") === target); });
      });
    });
  });

  // Mobile sidebar toggle (build-time sidebar)
  (function () {
    var sidebar = document.querySelector(".doc-sidebar");
    if (!sidebar) return;
    var toggle = document.createElement("button");
    toggle.className = "sidebar-toggle";
    toggle.setAttribute("aria-label", "Toggle navigation");
    toggle.innerHTML = "☰";
    var backdrop = document.createElement("div");
    backdrop.className = "sidebar-backdrop";
    toggle.addEventListener("click", function () {
      var open = sidebar.classList.toggle("open");
      backdrop.style.display = open ? "block" : "none";
    });
    backdrop.addEventListener("click", function () {
      sidebar.classList.remove("open");
      backdrop.style.display = "none";
    });
    document.body.appendChild(toggle);
    document.body.appendChild(backdrop);
  })();

  // TOC scroll spy (build-time TOC)
  (function () {
    var toc = document.querySelector(".doc-toc");
    if (!toc) return;
    var links = toc.querySelectorAll(".toc-link");
    if (!links.length) return;
    var map = [];
    links.forEach(function (a) {
      var id = a.getAttribute("href").slice(1);
      var h = document.getElementById(id);
      if (h) map.push({ el: a, heading: h });
    });
    if (!map.length) return;
    var cur = null;
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          var link = map.find(function (t) { return t.heading === entry.target; });
          if (link) {
            if (cur) cur.el.classList.remove("active");
            link.el.classList.add("active");
            cur = link;
          }
        }
      });
    }, { rootMargin: "-70px 0px -70% 0px", threshold: 0 });
    map.forEach(function (t) { obs.observe(t.heading); });
  })();

  // Heading anchors
  document.querySelectorAll("main h2, main h3").forEach(function (h) {
    if (h.closest("table, pre")) return;
    if (!h.id) {
      h.id = h.textContent.toLowerCase().replace(/[^\w\s-]/g, "").replace(/\s+/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
    }
    if (!h.id || h.querySelector(".heading-anchor")) return;
    var a = document.createElement("a");
    a.className = "heading-anchor";
    a.href = "#" + h.id;
    a.textContent = "#";
    a.setAttribute("aria-label", "Link to this section");
    h.appendChild(a);
  });
})();
