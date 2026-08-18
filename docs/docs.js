(function () {
    "use strict";

    /* ----- Scroll progress bar ----- */
    var progressEl = document.querySelector(".scroll-progress");
    if (progressEl) {
        var _progressRAF = false;
        var updateProgress = function () {
            var h = document.documentElement;
            var scrolled = h.scrollTop;
            var total = h.scrollHeight - h.clientHeight;
            var pct = total > 0 ? scrolled / total : 0;
            progressEl.style.transform = "scaleX(" + pct + ")";
            _progressRAF = false;
        };
        window.addEventListener("scroll", function () {
            if (!_progressRAF) {
                _progressRAF = window.requestAnimationFrame(updateProgress);
            }
        }, { passive: true });
        updateProgress();
    }

    /* ----- Sticky nav compaction -----
       Adds .is-scrolled to nav.doc-nav once the page scrolls past the top,
       shrinking its padding/font for a compact floating bar. */
    var docNavEl = document.querySelector("nav.doc-nav");
    if (docNavEl) {
        var compactNav = function () {
            docNavEl.classList.toggle("is-scrolled", (window.scrollY || 0) > 24);
        };
        window.addEventListener("scroll", function () {
            if (!_progressRAF) {
                _progressRAF = window.requestAnimationFrame(compactNav);
            }
        }, { passive: true });
        compactNav();
    }

    /* ----- Reveal on scroll -----
       Progressive enhancement: add `reveal-ready` to <html> to activate
       the hidden initial state, then immediately mark in-view elements
       with `.in` — all synchronously so the browser never paints the
       hidden state without the reveal. */
    var revealEls = document.querySelectorAll(".reveal, .reveal-stagger");
    document.documentElement.classList.add("reveal-ready");
    if (!("IntersectionObserver" in window)) {
        revealEls.forEach(function (el) { el.classList.add("in"); });
    } else {
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    entry.target.classList.add("in");
                    io.unobserve(entry.target);
                }
            });
        }, { threshold: 0.08, rootMargin: "0px 0px -40px 0px" });
        revealEls.forEach(function (el) {
            if (el.getBoundingClientRect().top < window.innerHeight) {
                el.classList.add("in");
            } else {
                io.observe(el);
            }
        });
    }

    /* Resume decorative animations only after real user interaction (scroll,
   pointer/key) or after a generous delay so the initial load stays free of
   continuous style-layout work — which keeps LCP/TBT fast. */
    (function () {
        var resumed = false;
        var resume = function () {
            if (resumed) return;
            resumed = true;
            document.documentElement.classList.remove("decor-paused");
            ["scroll", "pointerdown", "pointermove", "keydown", "touchstart"].forEach(function (ev) {
                window.removeEventListener(ev, resume, { passive: true });
            });
        };
        ["scroll", "pointerdown", "pointermove", "keydown", "touchstart"].forEach(function (ev) {
            window.addEventListener(ev, resume, { passive: true });
        });
        setTimeout(resume, 8000);
    })();

    /* ----- Anchor links on h2/h3 ----- */
    var slugify = function (text) {
        return text.toLowerCase()
            .replace(/[^\w\s-]/g, "")
            .replace(/\s+/g, "-")
            .replace(/-+/g, "-")
            .replace(/^-|-$/g, "");
    };
    var headings = document.querySelectorAll("main h2, main h3");
    headings.forEach(function (h) {
        if (h.closest(".threat-card, .feature-card, .doc-card, .callout, .quick-ref, .terminal")) return;
        if (h.querySelector(".heading-anchor")) return;
        if (!h.id) {
            var slug = slugify(h.textContent);
            if (slug) h.id = slug;
        }
        if (!h.id) return;
        var link = document.createElement("a");
        link.className = "heading-anchor";
        link.href = "#" + h.id;
        link.setAttribute("aria-label", "Link to this section: " + h.textContent.trim());
        link.textContent = "#";
        link.addEventListener("click", function (e) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                e.preventDefault();
                var url = location.origin + location.pathname + "#" + h.id;
                navigator.clipboard.writeText(url).then(function () {
                    if (typeof showToast === "function") {
                        showToast("Section link copied", "success");
                    }
                    history.replaceState(null, "", "#" + h.id);
                }).catch(function () {});
            }
        });
        h.appendChild(link);
    });

    /* ----- Cinematic section reveal — word-by-word clip slide on h2 ----- */
    (function () {
        if (prefersReduced) return;
        var cin = document.querySelectorAll("main > h2, main section > h2");
        if (!cin.length) return;
        cin.forEach(function (h2) {
            if (h2.closest(".threat-card, .feature-card, .doc-card, .callout")) return;
            if (h2.classList.contains("cinema-heading")) return;
            var anchor = h2.querySelector(".heading-anchor");
            if (anchor) anchor.remove();
            var words = h2.textContent.trim().split(/\s+/);
            if (words.length < 3) { if (anchor) h2.appendChild(anchor); return; }
            h2.innerHTML = "";
            h2.classList.add("cinema-heading");
            words.forEach(function (w) {
                var span = document.createElement("span");
                span.className = "cinema-word";
                span.textContent = w;
                h2.appendChild(span);
                h2.appendChild(document.createTextNode(" "));
            });
            if (anchor) h2.appendChild(anchor);
            h2.classList.remove("in");
        });
        var cinIO = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    entry.target.classList.add("in");
                    cinIO.unobserve(entry.target);
                }
            });
        }, { threshold: 0.4 });
        cin.forEach(function (h2) {
            if (h2.getBoundingClientRect().top < window.innerHeight) {
                h2.classList.add("in");
            } else {
                cinIO.observe(h2);
            }
        });
    })();

    /* ----- Copy-to-clipboard buttons + language labels on <pre> ----- */
    var detectLang = function (text) {
        var t = text.trim();
        if (/^(iwr|powershell|Set-ExecutionPolicy|param\()/i.test(t) ||
            /\b-(useb|uri)\b/i.test(t)) return "powershell";
        if (/^go\s+(install|build|run|test|mod)/i.test(t)) return "go";
        if (/^docker\s+(run|build|pull|push|compose)/i.test(t) ||
            /^docker:\/\//i.test(t)) return "docker";
        if (/^(apiVersion|kind):/i.test(t)) return "yaml";
        if (/^(kubectl\b|k8s:)/i.test(t)) return "k8s";
        if (/^(journalctl|systemctl)/i.test(t)) return "systemd";
        if (/^(curl|wget|sudo|caddy-analyze|bash|sh)\b/i.test(t) ||
            /^#\s/.test(t) || /[|&>;]\s/.test(t)) return "bash";
        return "shell";
    };
    var pres = document.querySelectorAll("pre:not(.callout pre):not(.no-copy)");
    pres.forEach(function (pre) {
        if (pre.closest(".callout, .no-copy")) return;
        var raw = pre.textContent.trimEnd();
        pre.dataset.raw = raw;

        if (!pre.querySelector(".code-lang")) {
            var lang = detectLang(raw);
            var langBadge = document.createElement("span");
            langBadge.className = "code-lang";
            langBadge.textContent = lang;
            langBadge.setAttribute("aria-hidden", "true");
            pre.appendChild(langBadge);
            pre.classList.add("has-lang");
        }
        if (pre.querySelector(".copy-btn")) return;
        var btn = document.createElement("button");
        btn.className = "copy-btn";
        btn.type = "button";
        btn.setAttribute("aria-label", "Copy code to clipboard");
        btn.textContent = "copy";
        btn.addEventListener("click", function () {
            var text = pre.dataset.raw || pre.textContent;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function () {
                    btn.classList.add("copied");
                    btn.textContent = "copied!";
                    if (typeof showToast === "function") {
                        showToast("Code copied to clipboard", "success");
                    }
                    setTimeout(function () {
                        btn.classList.remove("copied");
                        btn.textContent = "copy";
                    }, 1600);
                }).catch(function () {});
            }
        });
        pre.appendChild(btn);
    });

    /* ----- Back-to-top button ----- */
    var btt = document.querySelector(".back-to-top");
    if (btt) {
        var _bttRAF = false;
        var updateBtt = function () {
            if (window.scrollY > 500) btt.classList.add("visible");
            else btt.classList.remove("visible");
            _bttRAF = false;
        };
        window.addEventListener("scroll", function () {
            if (!_bttRAF) {
                _bttRAF = window.requestAnimationFrame(updateBtt);
            }
        }, { passive: true });
        btt.addEventListener("click", function () {
            window.scrollTo({ top: 0, behavior: "smooth" });
        });
        btt.setAttribute("aria-label", "Back to top");
        updateBtt();
    }

    /* ----- Shared capability flags ----- */
    var prefersReduced = window.matchMedia &&
        window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var coarsePointer = window.matchMedia &&
        window.matchMedia("(pointer: coarse)").matches;
    var isErrorPage = document.body.classList.contains("error-page");

    /* ----- Page order for prev/next navigation + keyboard shortcuts ----- */
    var PAGES = [
        { href: "index.html",         title: "Overview" },
        { href: "installation.html",  title: "Installation" },
        { href: "sources.html",       title: "Log Sources" },
        { href: "subcommands.html",   title: "Subcommands" },
        { href: "security.html",      title: "Threat Detector" },
        { href: "tui-html.html",      title: "TUI & HTML Reports" }
    ];
    var here = location.pathname.split("/").pop() || "index.html";
    var idx = PAGES.map(function (p) { return p.href; }).indexOf(here);
    if (idx === -1) idx = 0;

    var prevPage = idx > 0 ? PAGES[idx - 1] : null;
    var nextPage = idx < PAGES.length - 1 ? PAGES[idx + 1] : null;

    /* Inject prev/next nav before footer */
    var footer = document.querySelector(".footer");
    if (footer && (prevPage || nextPage)) {
        var pn = document.createElement("nav");
        pn.className = "page-nav";
        pn.setAttribute("aria-label", "Page navigation");

        if (prevPage) {
            var pa = document.createElement("a");
            pa.className = "page-nav-link page-nav-prev";
            pa.href = prevPage.href;
            pa.innerHTML = '<span class="page-nav-arrow">←</span>' +
                '<span class="page-nav-label"><small>Previous</small>' +
                prevPage.title + '</span>';
            pn.appendChild(pa);
        }
        if (nextPage) {
            var na = document.createElement("a");
            na.className = "page-nav-link page-nav-next";
            na.href = nextPage.href;
            na.innerHTML = '<span class="page-nav-label"><small>Next</small>' +
                nextPage.title + '</span><span class="page-nav-arrow">→</span>';
            pn.appendChild(na);
        }
        footer.parentNode.insertBefore(pn, footer);
    }

    /* Keyboard arrow shortcuts for prev/next (when not in inputs) */
    document.addEventListener("keydown", function (e) {
        if (e.target.matches("input, textarea, pre, code, [contenteditable]")) return;
        if (e.altKey || e.ctrlKey || e.metaKey) return;
        if (e.key === "ArrowLeft" && prevPage) {
            location.href = prevPage.href;
        } else if (e.key === "ArrowRight" && nextPage) {
            location.href = nextPage.href;
        }
    });

    /* ----- Floating "On this page" TOC with scroll-spy -----
       Auto-generated from h2 + h3 headings on pages with 2+ h2s.
       H3 entries are indented under their parent H2.
       Hidden on narrow viewports via CSS. */
    var h2s = Array.prototype.slice.call(
        document.querySelectorAll("main h2")
    ).filter(function (h) { return h.id; });
    if (h2s.length >= 2 && "IntersectionObserver" in window) {
        var headings = [];
        h2s.forEach(function (h2) {
            headings.push({ el: h2, level: 2 });
            var sibling = h2.parentElement ? h2.nextElementSibling : null;
            while (sibling) {
                if (sibling.tagName === "H2") break;
                if (sibling.tagName === "H3" && sibling.id) {
                    headings.push({ el: sibling, level: 3 });
                }
                sibling = sibling.nextElementSibling;
            }
        });

        var toc = document.createElement("nav");
        toc.className = "toc-sidebar";
        toc.setAttribute("aria-label", "On this page");

        var tocTitle = document.createElement("p");
        tocTitle.className = "toc-title";
        tocTitle.textContent = "On this page";
        toc.appendChild(tocTitle);

        var tocList = document.createElement("ul");
        var links = [];
        headings.forEach(function (item) {
            var li = document.createElement("li");
            if (item.level === 3) li.className = "toc-sub";
            var a = document.createElement("a");
            a.href = "#" + item.el.id;
            a.textContent = item.el.textContent.replace(/#$/, "").trim();
            a.dataset.target = item.el.id;
            li.appendChild(a);
            tocList.appendChild(li);
            links.push({ link: a, heading: item.el });
        });
        toc.appendChild(tocList);
        document.body.appendChild(toc);

        /* Click handler — manual scroll calculation bypasses scrollIntoView
           quirks (double offset from scroll-padding + scroll-margin) */
        tocList.addEventListener("click", function (e) {
            var link = e.target.closest("a");
            if (!link) return;
            var id = link.dataset.target;
            var target = document.getElementById(id);
            if (!target) return;
            e.preventDefault();
            var navOffset = 80;
            var top = target.getBoundingClientRect().top + window.scrollY - navOffset;
            window.scrollTo({ top: top, behavior: "smooth" });
            history.replaceState(null, "", "#" + id);
            links.forEach(function (r) {
                r.link.classList.toggle("active", r.heading.id === id);
            });
            target.classList.add("anchor-flash");
            setTimeout(function () {
                target.classList.remove("anchor-flash");
            }, 2200);
        });

        /* Scroll-spy: highlight the TOC link for the section in view */
        var spyIO = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (!entry.isIntersecting) return;
                var id = entry.target.id;
                links.forEach(function (l) {
                    l.link.classList.toggle("active",
                        l.heading.id === id);
                });
            });
        }, { rootMargin: "-80px 0px -70% 0px" });
        headings.forEach(function (item) { spyIO.observe(item.el); });

        /* Sync TOC position on scroll/resize (fixed element, needs offset) */
        var _tocRAF = false;
        var positionTOC = function () {
            var navHeight = 80;
            toc.style.top = navHeight + "px";
            _tocRAF = false;
        };
        positionTOC();
        window.addEventListener("resize", function () {
            if (!_tocRAF) _tocRAF = window.requestAnimationFrame(positionTOC);
        }, { passive: true });
    }

    /* ----- Reading time estimate -----
       Counts words in main content, injects a badge in page-header. */
    var mainContent = document.querySelector("main");
    var headerEl = document.querySelector(".page-header, .hero");
    if (mainContent && headerEl) {
        var words = (mainContent.textContent || "").trim().split(/\s+/).length;
        var minutes = Math.max(1, Math.round(words / 200));
        var badge = document.createElement("span");
        badge.className = "reading-time";
        badge.textContent = minutes + " min read";
        headerEl.appendChild(badge);
    }

    /* ----- Breadcrumb + last-updated + version meta -----
       Injects a hierarchy breadcrumb at the top of each page and a
       "vX.Y.Z · updated <date>" meta line, so readers always know the
       current docs version and where they are in the site. */
    (function () {
        var VERSION = "v0.3.0";
        var UPDATED = "2026-08-14";
        var REPO = "https://github.com/lenny-ts/caddy-analyzer";

        var trail = {
            "index.html": ["Overview"],
            "installation.html": ["Overview", "Installation"],
            "sources.html": ["Overview", "Log Sources"],
            "subcommands.html": ["Overview", "Subcommands"],
            "security.html": ["Overview", "Security Threats"],
            "tui-html.html": ["Overview", "TUI & HTML Reports"]
        };

        var current = (location.pathname.split("/").pop() || "index.html").toLowerCase();
        var crumbs = trail[current] || ["Overview"];

        var pageHeader = document.querySelector(".page-header");
        if (pageHeader && !pageHeader.querySelector(".breadcrumb")) {
            var breadcrumb = document.createElement("nav");
            breadcrumb.className = "breadcrumb";
            breadcrumb.setAttribute("aria-label", "Breadcrumb");
            var ul = document.createElement("ol");
            crumbs.forEach(function (label, i) {
                var li = document.createElement("li");
                var a = document.createElement("a");
                if (i === crumbs.length - 1) {
                    a.className = "breadcrumb-current";
                    a.setAttribute("aria-current", "page");
                } else {
                    a.href = "index.html";
                }
                a.textContent = label;
                li.appendChild(a);
                ul.appendChild(li);
            });
            breadcrumb.appendChild(ul);
            pageHeader.insertBefore(breadcrumb, pageHeader.firstChild);

            if (!pageHeader.querySelector(".doc-meta")) {
                var meta = document.createElement("p");
                meta.className = "doc-meta";
                meta.innerHTML =
                    '<a href="' + REPO + '/releases" rel="noopener">' + VERSION + "</a>" +
                    ' · updated <time datetime="' + UPDATED + '">' + UPDATED + "</time>" +
                    ' · <a href="' + REPO + '" rel="noopener">GitHub</a>';
                pageHeader.appendChild(meta);
            }
        }
    })();

    /* ----- Mobile hamburger nav toggle -----
       Injects a toggle button as first child of nav.doc-nav.
       On click, toggles .nav-open to expand/collapse links vertically.
       Closes on link click, outside click, or Escape. */
    var docNav = document.querySelector("nav.doc-nav");
    if (docNav) {
        var toggle = document.createElement("button");
        toggle.className = "nav-toggle";
        toggle.type = "button";
        toggle.setAttribute("aria-expanded", "false");
        toggle.setAttribute("aria-label", "Toggle documentation navigation");
        var bars = document.createElement("span");
        bars.className = "nav-toggle-bars";
        bars.innerHTML = "<span></span><span></span><span></span>";
        toggle.appendChild(bars);
        var label = document.createElement("span");
        label.textContent = "Menu";
        toggle.appendChild(label);
        docNav.insertBefore(toggle, docNav.firstChild);

        var closeNav = function () {
            docNav.classList.remove("nav-open");
            toggle.setAttribute("aria-expanded", "false");
        };
        var openNav = function () {
            docNav.classList.add("nav-open");
            toggle.setAttribute("aria-expanded", "true");
        };
        toggle.addEventListener("click", function (e) {
            e.stopPropagation();
            if (docNav.classList.contains("nav-open")) {
                closeNav();
            } else {
                openNav();
            }
        });
        /* Close when a link is clicked */
        docNav.addEventListener("click", function (e) {
            if (e.target.tagName === "A") closeNav();
        });
        /* Close on outside click */
        document.addEventListener("click", function (e) {
            if (!docNav.contains(e.target)) closeNav();
        });
        /* Close on Escape */
        document.addEventListener("keydown", function (e) {
            if (e.key === "Escape") closeNav();
        });
    }

    /* ----- Stat counter animation (easeOutCubic) -----
       Parses leading number from .stat-num, animates 0 -> target on viewport
       entry. Skipped entirely under prefers-reduced-motion (final value stays). */
    if (!prefersReduced && "IntersectionObserver" in window) {
        var counters = document.querySelectorAll(".stat-num");
        var parsed = [];
        counters.forEach(function (el) {
            var raw = el.textContent.trim();
            var m = raw.match(/^([~]?\s*)(\d+(?:\.\d+)?)(.*)$/);
            if (!m) return;
            el.dataset.prefix = m[1];
            el.dataset.target = m[2];
            el.dataset.suffix = m[3];
            el.dataset.isInt = m[2].indexOf(".") === -1 ? "1" : "0";
            el.textContent = m[1] + "0" + m[3];
            parsed.push(el);
        });
        if (parsed.length) {
            var countIO = new IntersectionObserver(function (entries) {
                entries.forEach(function (entry) {
                    if (!entry.isIntersecting) return;
                    var el = entry.target;
                    if (el.dataset.counted) return;
                    el.dataset.counted = "1";
                    countIO.unobserve(el);
                    var target = parseFloat(el.dataset.target);
                    var prefix = el.dataset.prefix || "";
                    var suffix = el.dataset.suffix || "";
                    var isInt = el.dataset.isInt === "1";
                    var dur = 1300, start = null;
                    var step = function (ts) {
                        if (!start) start = ts;
                        var t = Math.min((ts - start) / dur, 1);
                        var eased = 1 - Math.pow(1 - t, 3);
                        var val = target * eased;
                        el.textContent = prefix +
                            (isInt ? Math.round(val) : val.toFixed(2)) + suffix;
                        if (t < 1) requestAnimationFrame(step);
                    };
                    requestAnimationFrame(step);
                });
            }, { threshold: 0.5 });
            parsed.forEach(function (el) { countIO.observe(el); });
        }
    }

    /* ----- Advanced mouse-interactive effects -----
       3D card tilt + glare, magnetic buttons.
       Disabled on touch / reduced-motion. */
    if (!prefersReduced && !coarsePointer) {

        var aurora = document.querySelector(".aurora");

        /* --- 3D card tilt + glare --- */
        var cards = document.querySelectorAll(
            ".feature-card, .doc-card, .threat-card, .stat"
        );
        cards.forEach(function (card) {
            card.classList.add("tilt");
            var rect = null;
            card.addEventListener("mouseenter", function () {
                rect = card.getBoundingClientRect();
            });
            card.addEventListener("mousemove", function (e) {
                if (!rect) rect = card.getBoundingClientRect();
                var px = (e.clientX - rect.left) / rect.width;
                var py = (e.clientY - rect.top) / rect.height;
                card.style.setProperty("--ry", ((px - 0.5) * 10).toFixed(2) + "deg");
                card.style.setProperty("--rx", (-(py - 0.5) * 10).toFixed(2) + "deg");
                card.style.setProperty("--card-mx", (e.clientX - rect.left) + "px");
                card.style.setProperty("--card-my", (e.clientY - rect.top) + "px");
            }, { passive: true });
            card.addEventListener("mouseleave", function () {
                rect = null;
                card.style.setProperty("--rx", "0deg");
                card.style.setProperty("--ry", "0deg");
            });
        });

        /* --- Magnetic hover on buttons / CTAs --- */
        var magnets = document.querySelectorAll(
            ".btn, .cta-row a, .doc-nav a"
        );
        magnets.forEach(function (el) {
            el.classList.add("magnetic");
            var rect = null;
            el.addEventListener("mouseenter", function () {
                rect = el.getBoundingClientRect();
            });
            el.addEventListener("mousemove", function (e) {
                if (!rect) rect = el.getBoundingClientRect();
                var mx = e.clientX - rect.left - rect.width / 2;
                var my = e.clientY - rect.top - rect.height / 2;
                el.style.setProperty("--mag-x", (mx * 0.3).toFixed(1) + "px");
                el.style.setProperty("--mag-y", (my * 0.3).toFixed(1) + "px");
            }, { passive: true });
            el.addEventListener("mouseleave", function () {
                rect = null;
                el.style.setProperty("--mag-x", "0px");
                el.style.setProperty("--mag-y", "0px");
            });
        });

        /* --- Aurora parallax on mousemove --- */
        window.addEventListener("mousemove", function (e) {
            var nx = (e.clientX / window.innerWidth - 0.5) * 2;
            var ny = (e.clientY / window.innerHeight - 0.5) * 2;
            if (aurora) {
                aurora.style.setProperty("--mx-n", nx.toFixed(3));
                aurora.style.setProperty("--my-n", ny.toFixed(3));
            }
        }, { passive: true });
    }

    /* ===================================================================
       ANIMATED GRADIENT BORDERS — inject .card-grad ring into cards.
       Runs regardless of motion preference; the CSS disables the spin
       under prefers-reduced-motion and falls back to a static ring.
       =================================================================== */
    (function () {
        var targets = document.querySelectorAll(
            ".feature-card, .doc-card, .threat-card, .stat"
        );
        targets.forEach(function (card) {
            if (card.querySelector(".card-grad")) return;
            var ring = document.createElement("i");
            ring.className = "card-grad";
            ring.setAttribute("aria-hidden", "true");
            card.appendChild(ring);
        });
    })();

    /* ===================================================================
       CURSOR SPOTLIGHT + CLICK RIPPLE — a soft glow follows the pointer
       and cards/buttons emit a ripple on press. Disabled on touch /
       reduced-motion.
       =================================================================== */
    (function () {
        if (prefersReduced || coarsePointer || isErrorPage) return;

        var glow = document.createElement("div");
        glow.className = "cursor-glow";
        glow.setAttribute("aria-hidden", "true");
        document.body.appendChild(glow);

        var mx = -100, my = -100, tx = -100, ty = -100, raf = null;
        var loop = function () {
            mx += (tx - mx) * 0.18;
            my += (ty - my) * 0.18;
            glow.style.transform =
                "translate(" + (mx - 150) + "px," + (my - 150) + "px)";
            raf = null;
            if (Math.abs(tx - mx) > 0.5 || Math.abs(ty - my) > 0.5) {
                raf = requestAnimationFrame(loop);
            }
        };
        window.addEventListener("mousemove", function (e) {
            tx = e.clientX;
            ty = e.clientY;
            if (!raf) raf = requestAnimationFrame(loop);
        }, { passive: true });

        document.addEventListener("mouseleave", function () {
            glow.style.opacity = "0";
        });
        document.addEventListener("mouseenter", function () {
            glow.style.opacity = "1";
        });

        document.addEventListener("pointerdown", function (e) {
            if (e.pointerType !== "mouse") return;
            var hit = e.target.closest(
                ".feature-card, .doc-card, .threat-card, .stat, .btn, .doc-nav a"
            );
            if (!hit) return;
            var r = hit.getBoundingClientRect();
            var rip = document.createElement("span");
            rip.className = "ripple";
            rip.style.left = (e.clientX - r.left) + "px";
            rip.style.top = (e.clientY - r.top) + "px";
            hit.appendChild(rip);
            setTimeout(function () { rip.remove(); }, 650);
        });
    })();

    /* =====================================================================
       STARFIELD / PARTICLES — site-wide drifting canvas
       ===================================================================== */
    (function () {
        if (prefersReduced || coarsePointer || isErrorPage) return;
        var canvas = document.createElement("canvas");
        canvas.className = "starfield-canvas";
        canvas.setAttribute("aria-hidden", "true");
        document.body.appendChild(canvas);
        var ctx = canvas.getContext("2d");
        if (!ctx) { canvas.remove(); return; }
        var W, H, dpr, particles = [];
        var mouse = { x: -9999, y: -9999 };
        var running = true;

        function resize() {
            dpr = Math.min(window.devicePixelRatio || 1, 2);
            W = window.innerWidth;
            H = window.innerHeight;
            canvas.width = W * dpr;
            canvas.height = H * dpr;
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            var count = Math.min(140, Math.floor(W * H / 16000));
            particles = [];
            for (var i = 0; i < count; i++) {
                particles.push({
                    x: Math.random() * W,
                    y: Math.random() * H,
                    r: Math.random() * 1.6 + 0.4,
                    vx: (Math.random() - 0.5) * 0.25,
                    vy: (Math.random() - 0.5) * 0.25,
                    a: Math.random() * 0.5 + 0.15,
                    tw: Math.random() * Math.PI * 2
                });
            }
        }
        window.addEventListener("resize", resize);
        resize();

        function draw(t) {
            if (!running) return;
            ctx.clearRect(0, 0, W, H);
            for (var i = 0; i < particles.length; i++) {
                var p = particles[i];
                p.x += p.vx;
                p.y += p.vy;
                var dx = p.x - mouse.x;
                var dy = p.y - mouse.y;
                var dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 140 && dist > 0.01) {
                    p.x += dx / dist * 0.6;
                    p.y += dy / dist * 0.6;
                }
                if (p.x < -20) p.x = W + 20;
                if (p.x > W + 20) p.x = -20;
                if (p.y < -20) p.y = H + 20;
                if (p.y > H + 20) p.y = -20;
                p.tw += 0.03;
                var alpha = p.a * (0.6 + 0.4 * Math.sin(p.tw));
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
                ctx.fillStyle = "rgba(72, 209, 204, " + alpha.toFixed(3) + ")";
                ctx.fill();
                var link = p.r > 1.4;
                if (link) {
                    for (var j = i + 1; j < particles.length; j++) {
                        var q = particles[j];
                        var d2x = p.x - q.x;
                        var d2y = p.y - q.y;
                        var d2 = Math.sqrt(d2x * d2x + d2y * d2y);
                        if (d2 < 90) {
                            ctx.beginPath();
                            ctx.moveTo(p.x, p.y);
                            ctx.lineTo(q.x, q.y);
                            ctx.strokeStyle = "rgba(56, 189, 248, " + (0.08 * (1 - d2 / 90)).toFixed(3) + ")";
                            ctx.lineWidth = 1;
                            ctx.stroke();
                        }
                    }
                }
            }
            requestAnimationFrame(draw);
        }
        requestAnimationFrame(draw);

        window.addEventListener("mousemove", function (e) {
            mouse.x = e.clientX;
            mouse.y = e.clientY;
        }, { passive: true });

        document.addEventListener("visibilitychange", function () {
            running = !document.hidden;
            if (running) requestAnimationFrame(draw);
        });
    })();

    /* =====================================================================
       SPARKLE TRAIL — gradient sparkles following the cursor
       ===================================================================== */
    (function () {
        if (prefersReduced || coarsePointer || isErrorPage) return;
        var host = document.createElement("div");
        host.className = "sparkle-trail";
        host.setAttribute("aria-hidden", "true");
        document.body.appendChild(host);
        var last = 0;
        window.addEventListener("mousemove", function (e) {
            var now = Date.now();
            if (now - last < 55) return;
            last = now;
            var s = document.createElement("span");
            s.className = "sparkle";
            s.style.left = e.clientX + "px";
            s.style.top = e.clientY + "px";
            s.style.setProperty("--dx", (Math.random() * 40 - 20) + "px");
            s.style.setProperty("--dy", (Math.random() * -50 - 10) + "px");
            host.appendChild(s);
            setTimeout(function () { s.remove(); }, 900);
        }, { passive: true });
    })();

    /* =====================================================================
       LIVE-TRAFFIC HERO — enable pulsing dots when hero terminal is in view
       ===================================================================== */
    (function () {
        if (prefersReduced) return;
        var lt = document.getElementById("live-traffic");
        if (!lt) return;
        lt.classList.add("on");
    })();

    /* =====================================================================
       PER-PAGE BACKGROUND — scanlines overlay + pause-on-hidden
       ===================================================================== */
    (function () {
        if (prefersReduced || isErrorPage) return;

        var scan = document.createElement("div");
        scan.className = "scanlines";
        scan.setAttribute("aria-hidden", "true");
        document.body.appendChild(scan);
    })();

    /* ===================================================================
       THEME TOGGLE — dark default, light opt-in via localStorage
       =================================================================== */
    (function () {
        var KEY = "caddy-docs-theme";
        var stored = null;
        try { stored = localStorage.getItem(KEY); } catch (e) {}
        if (stored === "light") {
            document.documentElement.setAttribute("data-theme", "light");
        } else {
            document.documentElement.removeAttribute("data-theme");
        }

        var btn = document.createElement("button");
        btn.className = "theme-toggle";
        btn.type = "button";
        btn.setAttribute("aria-label", "Toggle light/dark theme");
        var isLight = function () {
            return document.documentElement.getAttribute("data-theme") === "light";
        };
        var updateIcon = function () {
            btn.textContent = isLight() ? "\u2600" : "\u263D";
        };
        updateIcon();
        var applyTheme = function () {
            if (isLight()) {
                document.documentElement.removeAttribute("data-theme");
                try { localStorage.setItem(KEY, "dark"); } catch (e) {}
            } else {
                document.documentElement.setAttribute("data-theme", "light");
                try { localStorage.setItem(KEY, "light"); } catch (e) {}
            }
            updateIcon();
        };
        btn.addEventListener("click", function (e) {
            if (prefersReduced || !document.startViewTransition) {
                applyTheme();
                return;
            }
            var x = e.clientX, y = e.clientY;
            document.documentElement.style.setProperty("--reveal-x", x + "px");
            document.documentElement.style.setProperty("--reveal-y", y + "px");
            var vt = document.startViewTransition(function () { applyTheme(); });
            vt.ready.then(function () {
                var rect = document.documentElement.getBoundingClientRect();
                var maxDim = Math.max(rect.width, rect.height);
                var radius = Math.min(maxDim * 0.25, 300);
                document.documentElement.style.setProperty("--reveal-radius", radius + "px");
                document.documentElement.animate(
                    {
                        clipPath: [
                            "circle(0 at var(--reveal-x) var(--reveal-y))",
                            "circle(var(--reveal-radius) at var(--reveal-x) var(--reveal-y))"
                        ]
                    },
                    { duration: 480, easing: "ease-out",
                      pseudoElement: "::view-transition-new(root)" }
                );
            });
        });
        document.body.appendChild(btn);
    })();

    /* ===================================================================
       TOAST NOTIFICATION SYSTEM
       =================================================================== */
    var toastContainer = document.createElement("div");
    toastContainer.className = "toast-container";
    toastContainer.setAttribute("aria-live", "polite");
    toastContainer.setAttribute("aria-atomic", "true");
    document.body.appendChild(toastContainer);

    var showToast = function (msg, type) {
        var t = document.createElement("div");
        t.className = "toast" + (type ? " " + type : "");
        var icon = document.createElement("span");
        icon.className = "toast-icon";
        icon.textContent = type === "success" ? "\u2713" : "\u2139";
        var text = document.createElement("span");
        text.textContent = msg;
        t.appendChild(icon);
        t.appendChild(text);
        toastContainer.appendChild(t);
        requestAnimationFrame(function () { t.classList.add("show"); });
        setTimeout(function () {
            t.classList.remove("show");
            setTimeout(function () { t.remove(); }, 350);
        }, 2400);
    };

    /* ===================================================================
       SYNTAX HIGHLIGHTING — lightweight, no external deps
       =================================================================== */
    (function () {
        var KEYWORDS = {
            bash: /^(sudo|curl|wget|docker|go|kubectl|systemctl|journalctl|caddy-analyze|bash|sh|cat|grep|sort|uniq|head|tail|sed|awk|chmod|chown|mkdir|cp|mv|rm|echo|export|source|cd|ls|pwd|which|file|find|xargs|tee|nc|ssh|scp|rsync|tar|gzip|gunzip|unzip)\b/i,
            powershell: /^(iwr|Set-ExecutionPolicy|param|Invoke-WebRequest|Write-Host|if|else|foreach|function|return|Export-ModuleMember)\b/i,
            go: /^(go|go install|go build|go run|go test|go mod|go get)\b/i,
            docker: /^(docker|docker run|docker build|docker pull|docker push|docker compose|docker exec|docker logs)\b/i,
            k8s: /^(kubectl|kubectx|kubens)\b/i,
            systemd: /^(journalctl|systemctl|hostnamectl|timedatectl)\b/i,
            yaml: /^(apiVersion|kind|metadata|spec|name|namespace|labels|selector|ports|container|image|env|volumeMounts)\b/i
        };

        var highlight = function (text, lang) {
            var escaped = text
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;");

            var parts = [];
            var lastIdx = 0;
            var tokenRe = /("(?:[^"\\]|\\.)*"|'[^']*'|#[^\n]*|--[a-zA-Z][\w-]*|-[a-zA-Z]\b|\$\{?\w+\}?|\b\d+(?:\.\d+)?\b|\b(sudo|curl|wget|docker|go|kubectl|systemctl|journalctl|caddy-analyze|bash|cat|grep|sort|uniq|head|tail|chmod|mkdir|cp|mv|rm|echo|export|source|iwr|apiVersion|kind|metadata|spec)\b)/gi;
            var match;

            while ((match = tokenRe.exec(escaped)) !== null) {
                if (match.index > lastIdx) {
                    parts.push(escaped.slice(lastIdx, match.index));
                }
                var tok = match[0];
                var cls = null;
                if (tok.charAt(0) === '"' || tok.charAt(0) === "'") {
                    cls = "tok-string";
                } else if (tok.charAt(0) === "#") {
                    cls = "tok-comment";
                } else if (tok.charAt(0) === "-") {
                    cls = "tok-flag";
                } else if (tok.charAt(0) === "$") {
                    cls = "tok-variable";
                } else if (/^\d/.test(tok)) {
                    cls = "tok-number";
                } else if (match[1]) {
                    cls = "tok-keyword";
                }
                if (cls) {
                    parts.push('<span class="' + cls + '">' + tok + "</span>");
                } else {
                    parts.push(tok);
                }
                lastIdx = match.index + tok.length;
            }
            if (lastIdx < escaped.length) {
                parts.push(escaped.slice(lastIdx));
            }

            return parts.join("");
        };

        var codeBlocks = document.querySelectorAll("pre");
        codeBlocks.forEach(function (pre) {
            var copyBtn = pre.querySelector(".copy-btn");
            var langLabel = pre.querySelector(".code-lang");
            var raw = pre.dataset.raw || pre.textContent.trimEnd();

            try {
                var highlighted = highlight(raw);
                pre.innerHTML = "<code>" + highlighted + "</code>";
                if (langLabel) pre.appendChild(langLabel);
                if (copyBtn) pre.appendChild(copyBtn);
            } catch (e) {}
        });
    })();

    /* ===================================================================
       KEYBOARD SHORTCUTS OVERLAY — press ? to toggle
       =================================================================== */
    (function () {
        var overlay = document.createElement("div");
        overlay.className = "kbd-overlay";
        overlay.setAttribute("role", "dialog");
        overlay.setAttribute("aria-modal", "true");
        overlay.setAttribute("aria-label", "Keyboard shortcuts");

        var panel = document.createElement("div");
        panel.className = "kbd-panel";

        var h3 = document.createElement("div");
        h3.className = "kbd-panel-title";
        h3.textContent = "Keyboard Shortcuts";
        panel.appendChild(h3);

        var list = document.createElement("ul");
        list.className = "kbd-list";
        var shortcuts = [
            { keys: ["?"], action: "Show this overlay" },
            { keys: ["Ctrl", "K"], action: "Command palette" },
            { keys: ["Esc"], action: "Close overlay" },
            { keys: ["\u2190"], action: "Previous page" },
            { keys: ["\u2192"], action: "Next page" },
            { keys: ["t"], action: "Toggle theme" },
            { keys: ["b"], action: "Back to top" },
            { keys: ["g"], action: "Go to GitHub" }
        ];
        shortcuts.forEach(function (s) {
            var li = document.createElement("li");
            var action = document.createElement("span");
            action.textContent = s.action;
            var keys = document.createElement("span");
            keys.className = "kbd-keys";
            s.keys.forEach(function (k) {
                var keyEl = document.createElement("kbd");
                keyEl.textContent = k;
                keys.appendChild(keyEl);
            });
            li.appendChild(action);
            li.appendChild(keys);
            list.appendChild(li);
        });
        panel.appendChild(list);
        overlay.appendChild(panel);
        document.body.appendChild(overlay);

        var open = function () {
            overlay.classList.add("open");
            document.body.style.overflow = "hidden";
        };
        var close = function () {
            overlay.classList.remove("open");
            document.body.style.overflow = "";
        };
        overlay.addEventListener("click", function (e) {
            if (e.target === overlay) close();
        });

        document.addEventListener("keydown", function (e) {
            if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") {
                return;
            }
            if (e.key === "?" || (e.key === "/" && e.shiftKey)) {
                e.preventDefault();
                overlay.classList.contains("open") ? close() : open();
            }
            if (e.key === "Escape" && overlay.classList.contains("open")) {
                close();
            }
            if (e.key.toLowerCase() === "t" && !e.ctrlKey && !e.metaKey) {
                var toggle = document.querySelector(".theme-toggle");
                if (toggle) toggle.click();
            }
            if (e.key.toLowerCase() === "b" && !e.ctrlKey && !e.metaKey) {
                var btt = document.querySelector(".back-to-top");
                if (btt) btt.click();
            }
            if (e.key.toLowerCase() === "g" && !e.ctrlKey && !e.metaKey) {
                var ghLink = document.querySelector('a[href*="github.com/lenny-ts/caddy-analyzer"]');
                if (ghLink) window.open(ghLink.href, "_blank");
            }
        });
    })();

    /* ===================================================================
       INTERACTIVE MASCOT — cursor tilt + parallax follow
       =================================================================== */
    (function () {
        var mascot = document.querySelector(".hero-mascot");
        if (!mascot || prefersReduced || coarsePointer) return;
        var hero = document.querySelector(".hero");
        if (!hero) return;

        var heroRect = null;
        hero.addEventListener("mouseenter", function () {
            heroRect = hero.getBoundingClientRect();
        });
        hero.addEventListener("mousemove", function (e) {
            if (!heroRect) heroRect = hero.getBoundingClientRect();
            var px = (e.clientX - heroRect.left) / heroRect.width - 0.5;
            var py = (e.clientY - heroRect.top) / heroRect.height - 0.5;
            mascot.style.setProperty("--mascot-ry", (px * 18).toFixed(1) + "deg");
            mascot.style.setProperty("--mascot-rx", (-(py * 18)).toFixed(1) + "deg");
        });
        hero.addEventListener("mouseleave", function () {
            heroRect = null;
            mascot.style.setProperty("--mascot-ry", "0deg");
            mascot.style.setProperty("--mascot-rx", "0deg");
        });

        var blinkCount = 0;
        var blink = function () {
            mascot.style.filter = "drop-shadow(0 10px 30px var(--accent-glow)) brightness(0.3)";
            setTimeout(function () {
                mascot.style.filter = "";
            }, 120);
            blinkCount++;
            setTimeout(blink, 3000 + Math.random() * 4000);
        };
        setTimeout(blink, 2500);
    })();

    /* ===================================================================
       PAGE TRANSITIONS — fade overlay on link navigation
       =================================================================== */
    var navigate = function (href) {
        window.location.href = href;
    };
    (function () {
        if (prefersReduced) return;

        document.body.classList.add("page-enter");

        /* Cross-document View Transitions handle the animation natively
           (styles.css: @view-transition { navigation: auto }). For browsers
           without the API the body.page-enter fade-in plays instead. We
           only handle keyboard/modifier-free internal links to make sure
           the transition actually fires (avoiding full-page reloads that
           bypass the animation). */
        document.addEventListener("click", function (e) {
            var link = e.target.closest("a");
            if (!link) return;
            var href = link.getAttribute("href");
            if (!href || href.charAt(0) === "#" || href.charAt(0) === "?") return;
            if (link.target === "_blank") return;
            if (link.hasAttribute("download")) return;
            if (href.indexOf("://") !== -1) return;
            if (href.indexOf("mailto:") === 0) return;
            if (e.ctrlKey || e.metaKey || e.shiftKey) return;
            e.preventDefault();
            navigate(href);
        });
    })();

    /* ===================================================================
       MOBILE BOTTOM NAV — quick page switching on small screens
       =================================================================== */
    (function () {
        var mq = window.matchMedia("(max-width: 640px)");
        if (!mq.matches) return;

        var nav = document.createElement("nav");
        nav.className = "bottom-nav";
        nav.setAttribute("aria-label", "Quick page navigation");

        var list = document.createElement("ul");
        list.className = "bottom-nav-list";

        var pages = [
            { href: "index.html", icon: "\u2302", label: "Home" },
            { href: "installation.html", icon: "\u2193", label: "Install" },
            { href: "subcommands.html", icon: "\u2630", label: "CLI" },
            { href: "security.html", icon: "\u26D4", label: "Threats" },
            { href: "tui-html.html", icon: "\u25A4", label: "Reports" }
        ];
        var here = location.pathname.split("/").pop() || "index.html";

        pages.forEach(function (p) {
            var li = document.createElement("li");
            var a = document.createElement("a");
            a.href = p.href;
            var icon = document.createElement("span");
            icon.className = "bn-icon";
            icon.textContent = p.icon;
            var label = document.createElement("span");
            label.textContent = p.label;
            a.appendChild(icon);
            a.appendChild(label);
            if (p.href === here) a.classList.add("active");
            li.appendChild(a);
            list.appendChild(li);
        });

        nav.appendChild(list);
        document.body.appendChild(nav);
    })();

    /* ===================================================================
       READING PROGRESS BAR — gradient fill at top, tracks scroll
       =================================================================== */
    (function () {
        var bar = document.createElement("div");
        bar.className = "reading-progress";
        bar.setAttribute("aria-hidden", "true");
        var fill = document.createElement("div");
        fill.className = "reading-progress-fill";
        bar.appendChild(fill);
        document.body.appendChild(bar);

        var ticking = false;
        var update = function () {
            var h = document.documentElement;
            var max = (h.scrollHeight - h.clientHeight) || 1;
            var pct = Math.min((h.scrollTop || 0) / max, 1);
            fill.style.transform = "scaleX(" + pct + ")";
            ticking = false;
        };
        window.addEventListener("scroll", function () {
            if (!ticking) {
                window.requestAnimationFrame(update);
                ticking = true;
            }
        }, { passive: true });
        update();
    })();

    /* ===================================================================
       COMMAND PALETTE (Ctrl/Cmd+K) — fuzzy nav across pages + headings
       =================================================================== */
    (function () {
        var PAGES = [
            { href: "index.html", title: "Home", kind: "Page" },
            { href: "installation.html", title: "Installation", kind: "Page" },
            { href: "sources.html", title: "Log Sources", kind: "Page" },
            { href: "subcommands.html", title: "Subcommands", kind: "Page" },
            { href: "security.html", title: "Security Threats", kind: "Page" },
            { href: "tui-html.html", title: "HTML Reports", kind: "Page" }
        ];
        var ACTIONS = [
            { title: "Toggle theme", kind: "Action", run: function () {
                var t = document.querySelector(".theme-toggle");
                if (t) t.click();
            }},
            { title: "Back to top", kind: "Action", run: function () {
                window.scrollTo({ top: 0, behavior: "smooth" });
            }},
            { title: "Go to GitHub", kind: "Action", run: function () {
                window.open("https://github.com/lenny-ts/caddy-analyzer", "_blank");
            }},
            { title: "Show keyboard shortcuts", kind: "Action", run: function () {
                var o = document.querySelector(".kbd-overlay");
                if (o) o.classList.add("open");
            }}
        ];

        var overlay = document.createElement("div");
        overlay.className = "cmdk-overlay";
        overlay.setAttribute("role", "dialog");
        overlay.setAttribute("aria-modal", "true");
        overlay.setAttribute("aria-label", "Command palette");

        var panel = document.createElement("div");
        panel.className = "cmdk-panel";

        var input = document.createElement("input");
        input.type = "text";
        input.className = "cmdk-input";
        input.placeholder = "Search pages, sections, actions\u2026";
        input.setAttribute("aria-label", "Search commands");

        var list = document.createElement("ul");
        list.className = "cmdk-list";
        list.setAttribute("role", "listbox");

        panel.appendChild(input);
        panel.appendChild(list);
        overlay.appendChild(panel);
        document.body.appendChild(overlay);

        /* Visible trigger button appended into the nav bar so the
           command palette is discoverable without knowing the Ctrl+K
           shortcut. Shows the platform-correct keycap. */
        var isMac = navigator.platform.indexOf("Mac") !== -1;
        var kbdText = isMac ? "\u2318 K" : "Ctrl K";
        var ICON = '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7" cy="7" r="5"/><path d="m11 11 3 3"/></svg>';
        var makeTrigger = function () {
            var t = document.createElement("button");
            t.type = "button";
            t.className = "cmdk-trigger";
            t.setAttribute("aria-label", "Open command palette (Ctrl+K)");
            t.innerHTML = '<span class="cmdk-trigger-icon" aria-hidden="true">' + ICON + '</span><span class="cmdk-trigger-text">Search</span><kbd class="cmdk-kbd">' + kbdText + '</kbd>';
            t.addEventListener("click", function (e) {
                e.preventDefault();
                open();
            });
            return t;
        };
        document.querySelectorAll(".doc-nav").forEach(function (nav) {
            nav.appendChild(makeTrigger());
        });

        var items = [];
        var selected = 0;

        /* Cross-page full-text search index (built by tools/build-search-index.js).
           Fetched once, merged into the palette so searches match content on
           every docs page, not just the current one. */
        var remoteItems = [];
        var indexState = "pending";
        var loadIndex = function () {
            if (indexState !== "pending") return;
            indexState = "loading";
            fetch("search-index.json")
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    indexState = "ready";
                    remoteItems = (data.entries || []).map(function (e) {
                        return {
                            title: e.title,
                            kind: e.kind,
                            href: e.href,
                            page: e.page,
                            body: (e.body || "").toLowerCase()
                        };
                    });
                    if (overlay.classList.contains("open")) {
                        buildItems();
                        render(input.value);
                    }
                })
                .catch(function () { indexState = "failed"; });
        };
        /* Deferred: fetch the cross-page index only when the palette is first
           opened, so search-index.json is not part of the initial page-load
           critical path. */

        var buildItems = function () {
            items = PAGES.slice();
            ACTIONS.forEach(function (a) { items.push(a); });
            var headings = document.querySelectorAll("main h2[id], main h3[id]");
            headings.forEach(function (h) {
                items.push({
                    title: h.textContent.replace(/\s+/g, " ").trim(),
                    kind: h.tagName === "H2" ? "Section" : "Subsection",
                    href: "#" + h.id,
                    heading: h,
                    body: sectionText(h)
                });
            });
            remoteItems.forEach(function (r) {
                items.push({
                    title: r.title,
                    kind: r.kind,
                    href: r.href,
                    page: r.page,
                    body: r.body
                });
            });
        };

        /* Collect the plain text of a section up to the next heading, so the
           palette can match and jump to content beyond just titles. */
        var sectionText = function (heading) {
            var parts = [];
            var node = heading.nextElementSibling;
            while (node && !/^H[1-6]$/.test(node.tagName)) {
                if (node.querySelector && node.querySelector("h1,h2,h3,h4,h5,h6")) {
                    break;
                }
                if (node.textContent) {
                    var t = node.textContent.replace(/\s+/g, " ").trim();
                    if (t) parts.push(t);
                }
                node = node.nextElementSibling;
            }
            return parts.join(" ").toLowerCase();
        };

        var score = function (q, text, body) {
            q = q.toLowerCase();
            text = text.toLowerCase();
            var bodyScore = -1;
            if (body && q.length > 1 && body.indexOf(q) !== -1) {
                bodyScore = body.indexOf(q);
            }
            if (!q) return 1;
            if (text.indexOf(q) !== -1) return 100 - text.indexOf(q);
            var qi = 0, score = 0, lastIdx = -1;
            for (var i = 0; i < text.length && qi < q.length; i++) {
                if (text.charAt(i) === q.charAt(qi)) {
                    score += (i - lastIdx === 1) ? 10 : 1;
                    lastIdx = i;
                    qi++;
                }
            }
            if (qi === q.length) return score;
            /* Fall back to body-content match so full-text search works */
            if (bodyScore >= 0) return 20 - Math.min(bodyScore, 20);
            return -1;
        };

        var render = function (q) {
            var scored = items
                .map(function (it) { return { it: it, s: score(q, it.title, it.body) }; })
                .filter(function (x) { return x.s >= 0; })
                .sort(function (a, b) { return b.s - a.s; })
                .slice(0, 12)
                .map(function (x) { return x.it; });

            if (!scored.length) {
                list.innerHTML = '<li class="cmdk-empty">No matches</li>';
                selected = -1;
                return;
            }
            list.innerHTML = "";
            scored.forEach(function (it, i) {
                var li = document.createElement("li");
                li.className = "cmdk-item" + (i === 0 ? " active" : "");
                li.setAttribute("role", "option");
                li.setAttribute("aria-selected", i === 0 ? "true" : "false");
                var title = document.createElement("span");
                title.className = "cmdk-item-title";
                title.textContent = it.title;
                var kind = document.createElement("span");
                kind.className = "cmdk-item-kind cmdk-kind-" + it.kind.toLowerCase();
                if (it.page && it.kind !== "Page") {
                    kind.textContent = it.page;
                    kind.title = it.kind;
                } else {
                    kind.textContent = it.kind;
                }
                li.appendChild(title);
                li.appendChild(kind);
                li.addEventListener("mouseenter", function () {
                    selected = i;
                    updateActive();
                });
                li.addEventListener("click", function () { choose(it); });
                list.appendChild(li);
            });
            items._filtered = scored;
            selected = 0;
        };

        var updateActive = function () {
            var lis = list.querySelectorAll(".cmdk-item");
            lis.forEach(function (li, i) {
                var active = i === selected;
                li.classList.toggle("active", active);
                li.setAttribute("aria-selected", active ? "true" : "false");
                if (active) li.scrollIntoView({ block: "nearest" });
            });
        };

        var choose = function (it) {
            close();
            if (it.run) { it.run(); return; }
            if (it.heading) {
                it.heading.scrollIntoView({ behavior: "smooth", block: "start" });
                return;
            }
            if (it.href) {
                if (it.href.charAt(0) === "#") {
                    var el = document.querySelector(it.href);
                    if (el) el.scrollIntoView({ behavior: "smooth" });
                } else {
                    navigate(it.href);
                }
            }
        };

        var open = function () {
            loadIndex();
            buildItems();
            input.value = "";
            render("");
            overlay.classList.add("open");
            document.body.style.overflow = "hidden";
            setTimeout(function () { input.focus(); }, 50);
        };
        var close = function () {
            overlay.classList.remove("open");
            document.body.style.overflow = "";
        };

        input.addEventListener("input", function () { render(input.value); });
        input.addEventListener("keydown", function (e) {
            var filtered = items._filtered || [];
            if (e.key === "ArrowDown") {
                e.preventDefault();
                selected = Math.min(selected + 1, filtered.length - 1);
                updateActive();
            } else if (e.key === "ArrowUp") {
                e.preventDefault();
                selected = Math.max(selected - 1, 0);
                updateActive();
            } else if (e.key === "Enter") {
                e.preventDefault();
                if (filtered[selected]) choose(filtered[selected]);
            } else if (e.key === "Escape") {
                e.preventDefault();
                close();
            }
        });
        overlay.addEventListener("click", function (e) {
            if (e.target === overlay) close();
        });

        document.addEventListener("keydown", function (e) {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
                e.preventDefault();
                overlay.classList.contains("open") ? close() : open();
            }
            if (e.key === "Escape" && overlay.classList.contains("open")) close();
        });
    })();

    /* ===================================================================
       GLOSSARY TOOLTIPS — hover technical terms for definitions
       =================================================================== */
    (function () {
        var GLOSSARY = {
            "Caddyfile": "Caddy's native configuration file format, using a human-readable block syntax.",
            "reverse proxy": "A server that sits between clients and backend servers, forwarding requests and responses.",
            "mTLS": "Mutual TLS — both client and server present certificates to authenticate each other.",
            "TLS": "Transport Layer Security — cryptographic protocol providing encrypted communication.",
            "WAF": "Web Application Firewall — filters HTTP traffic against common attacks (SQLi, XSS, RCE).",
            "RCE": "Remote Code Execution — vulnerability allowing arbitrary command execution on the host.",
            "SQLi": "SQL Injection — attack inserting malicious SQL via unsanitized input.",
            "XSS": "Cross-Site Scripting — injecting client-side scripts into web pages viewed by others.",
            "CSRF": "Cross-Site Request Forgery — tricking an authenticated user into executing unwanted actions.",
            "SSRF": "Server-Side Request Forgery — making the server perform arbitrary internal requests.",
            "LFI": "Local File Inclusion — tricking the server into including local files via path traversal.",
            "RFI": "Remote File Inclusion — loading remote code into the application, often leading to RCE.",
            "XXE": "XML External Entity — abusing XML parsers to read local files or perform SSRF.",
            "WAF rule": "A pattern-based rule that matches and blocks malicious HTTP traffic signatures.",
            "iptables": "Linux kernel firewall — packet filtering rules at the network layer.",
            "systemd": "Linux init system and service manager — controls background daemons.",
            "rate limit": "Cap on requests per time window from a single client, mitigating brute force.",
            "geo-blocking": "Restricting access by source country/region using IP geolocation.",
            "TUI": "Text User Interface — interactive terminal UI rendered with ANSI escape codes.",
            "daemon": "A long-running background process, typically detached from a terminal.",
            "egress": "Outbound network traffic leaving the server toward external destinations.",
            "0-day": "A vulnerability unknown to the vendor, with no available patch at disclosure time."
        };

        var tooltip = document.createElement("div");
        tooltip.className = "glossary-tip";
        tooltip.setAttribute("role", "tooltip");
        tooltip.setAttribute("aria-hidden", "true");
        document.body.appendChild(tooltip);

        var hideTimer = null;
        var showTimer = null;

        var showFor = function (term, x, y) {
            var def = GLOSSARY[term];
            if (!def) return;
            tooltip.innerHTML = "<strong>" + term + "</strong><br>" + def;
            tooltip.style.left = "0px";
            tooltip.style.top = "0px";
            tooltip.classList.add("visible");
            tooltip.setAttribute("aria-hidden", "false");
            var rect = tooltip.getBoundingClientRect();
            var px = Math.min(x, window.innerWidth - rect.width - 16);
            var py = y - rect.height - 12;
            if (py < 8) py = y + 20;
            tooltip.style.left = Math.max(8, px) + "px";
            tooltip.style.top = py + "px";
        };
        var hide = function () {
            tooltip.classList.remove("visible");
            tooltip.setAttribute("aria-hidden", "true");
        };

        var terms = Object.keys(GLOSSARY);
        var escapedTerms = terms.map(function (t) {
            return t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        });
        var re = new RegExp("\\b(" + escapedTerms.join("|") + ")\\b", "g");

        var mainEl = document.querySelector("main");
        if (!mainEl) return;

        var walker = document.createTreeWalker(
            mainEl,
            NodeFilter.SHOW_TEXT,
            {
                acceptNode: function (n) {
                    if (!n.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
                    var p = n.parentNode;
                    if (!p) return NodeFilter.FILTER_REJECT;
                    if (p.tagName === "SCRIPT" || p.tagName === "STYLE" ||
                        p.tagName === "CODE" || p.tagName === "PRE" ||
                        p.tagName === "A" || p.classList.contains("heading-anchor")) {
                        return NodeFilter.FILTER_REJECT;
                    }
                    if (p.closest && p.closest("[aria-hidden]")) {
                        return NodeFilter.FILTER_REJECT;
                    }
                    return re.test(n.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
                }
            }
        );
        var nodes = [];
        var node;
        while ((node = walker.nextNode())) nodes.push(node);
        nodes.forEach(function (n) {
            var text = n.nodeValue;
            var frag = document.createDocumentFragment();
            var last = 0;
            var m;
            re.lastIndex = 0;
            while ((m = re.exec(text)) !== null) {
                if (m.index > last) {
                    frag.appendChild(document.createTextNode(text.slice(last, m.index)));
                }
                var mark = document.createElement("span");
                mark.className = "glossary-term";
                mark.setAttribute("tabindex", "0");
                mark.setAttribute("data-term", m[0]);
                mark.textContent = m[0];
                frag.appendChild(mark);
                last = m.index + m[0].length;
            }
            if (last < text.length) {
                frag.appendChild(document.createTextNode(text.slice(last)));
            }
            n.parentNode.replaceChild(frag, n);
        });

        var container = document.querySelector("main") || document.body;
        container.addEventListener("mouseover", function (e) {
            var t = e.target.closest(".glossary-term");
            if (!t) return;
            clearTimeout(hideTimer); clearTimeout(showTimer);
            var r = t.getBoundingClientRect();
            showTimer = setTimeout(function () {
                showFor(t.dataset.term, r.left + r.width / 2, r.top);
            }, 150);
        });
        container.addEventListener("mouseout", function (e) {
            var t = e.target.closest(".glossary-term");
            if (!t) return;
            clearTimeout(showTimer);
            hideTimer = setTimeout(hide, 100);
        });
        container.addEventListener("focusin", function (e) {
            var t = e.target.closest(".glossary-term");
            if (!t) return;
            var r = t.getBoundingClientRect();
            showFor(t.dataset.term, r.left + r.width / 2, r.top);
        });
        container.addEventListener("focusout", function (e) {
            var t = e.target.closest(".glossary-term");
            if (t) hide();
        });
    })();

    /* ===================================================================
       COLLAPSIBLE LONG CODE — auto-collapse pre blocks > 20 lines
       =================================================================== */
    (function () {
        var LIMIT = 20;
        document.querySelectorAll("pre").forEach(function (pre) {
            if (pre.closest(".callout, .no-copy")) return;
            var raw = pre.dataset.raw || pre.textContent;
            var lines = raw.split("\n").length;
            if (lines <= LIMIT) return;

            pre.classList.add("collapsible", "collapsed");
            pre.dataset.collapsed = "1";

            var btn = document.createElement("button");
            btn.className = "code-expand-btn";
            btn.type = "button";
            btn.setAttribute("aria-expanded", "false");
            btn.setAttribute("aria-label", "Expand code block");
            btn.innerHTML = '<span class="expand-text">Expand ' + lines + ' lines</span><span class="collapse-text">Collapse</span>';
            pre.appendChild(btn);

            btn.addEventListener("click", function () {
                var collapsed = pre.classList.toggle("collapsed");
                pre.dataset.collapsed = collapsed ? "1" : "0";
                btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
            });
        });
    })();

    /* ===================================================================
       FEEDBACK WIDGET — "Was this helpful?" + Edit on GitHub
       =================================================================== */
    (function () {
        if (document.body.classList.contains("error-page")) return;
        var main = document.querySelector("main");
        if (!main) return;

        var wrap = document.createElement("div");
        wrap.className = "feedback-wrap";

        var feedback = document.createElement("div");
        feedback.className = "feedback-box";
        feedback.innerHTML = '<span class="feedback-label">Was this page helpful?</span>';

        var yes = document.createElement("button");
        yes.type = "button";
        yes.className = "feedback-btn feedback-yes";
        yes.setAttribute("aria-label", "Yes, helpful");
        yes.textContent = "\uD83D\uDC4D";

        var no = document.createElement("button");
        no.type = "button";
        no.className = "feedback-btn feedback-no";
        no.setAttribute("aria-label", "No, not helpful");
        no.textContent = "\uD83D\uDC4E";

        feedback.appendChild(yes);
        feedback.appendChild(no);

        var editLink = document.createElement("a");
        editLink.className = "feedback-edit";
        editLink.target = "_blank";
        editLink.rel = "noopener";
        editLink.textContent = "Edit on GitHub \u2197";
        var page = location.pathname.split("/").pop();
        editLink.href = "https://github.com/lenny-ts/caddy-analyzer/edit/main/docs/" + page;

        feedback.appendChild(editLink);
        wrap.appendChild(feedback);

        var thanks = document.createElement("div");
        thanks.className = "feedback-thanks";
        thanks.textContent = "Thanks for the feedback!";
        thanks.setAttribute("hidden", "");
        wrap.appendChild(thanks);

        var voted = false;
        var handler = function (val) {
            if (voted) return;
            voted = true;
            try {
                var key = "caddy-feedback-" + page;
                var stored = JSON.parse(localStorage.getItem(key) || "{}");
                stored[val] = (stored[val] || 0) + 1;
                localStorage.setItem(key, JSON.stringify(stored));
            } catch (e) {}
            feedback.setAttribute("hidden", "");
            thanks.removeAttribute("hidden");
            if (val === "yes" && typeof window.fireConfetti === "function") {
                window.fireConfetti();
            }
            if (typeof showToast === "function") showToast("Saved locally", "success");
        };
        yes.addEventListener("click", function () { handler("yes"); });
        no.addEventListener("click", function () { handler("no"); });

        var footer = document.createElement("footer");
        footer.className = "doc-footer";
        footer.appendChild(wrap);

        var lastMod = document.querySelector('meta[name="doc:modified"]');
        if (lastMod && lastMod.content) {
            var d = new Date(lastMod.content);
            if (!isNaN(d.getTime())) {
                var dateStr = d.toLocaleDateString("en-US", {
                    year: "numeric", month: "short", day: "numeric"
                });
                var mod = document.createElement("div");
                mod.className = "doc-modified";
                mod.textContent = "Last updated " + dateStr;
                footer.appendChild(mod);
            }
        }

        main.appendChild(footer);
    })();

    /* ===================================================================
       ANCHOR FLASH HIGHLIGHT — target heading pulses on hash navigation
       =================================================================== */
    (function () {
        var flash = function () {
            if (!location.hash) return;
            var el = document.getElementById(location.hash.slice(1));
            if (!el) return;
            el.classList.add("anchor-flash");
            setTimeout(function () {
                el.classList.remove("anchor-flash");
            }, 2200);
        };
        if (document.readyState === "complete") flash();
        else window.addEventListener("load", flash);
        window.addEventListener("hashchange", flash);
    })();

    /* ===================================================================
       LINE NUMBERS IN CODE BLOCKS
       =================================================================== */
    (function () {
        var gutter = document.createElement("span");
        gutter.className = "code-gutter";
        document.querySelectorAll("pre:not(.collapsible)").forEach(function (pre) {
            if (pre.closest(".callout, .no-copy")) return;
            var raw = pre.dataset.raw || pre.textContent;
            var lines = raw.split("\n").length;
            if (lines < 3) return;

            var nums = document.createElement("span");
            nums.className = "code-lineno";
            nums.setAttribute("aria-hidden", "true");
            var frag = "";
            for (var i = 1; i <= lines; i++) {
                frag += i + "\n";
            }
            nums.textContent = frag;
            pre.insertBefore(nums, pre.firstChild);
            pre.classList.add("has-lineno");
        });
    })();

    /* ===================================================================
       SWIPE NAVIGATION — horizontal swipe on mobile for prev/next page
       =================================================================== */
    (function () {
        if (coarsePointer || prefersReduced) return;
        var mq = window.matchMedia("(max-width: 640px)");
        if (!mq.matches) return;

        var startX = 0, startY = 0, tracking = false;
        var threshold = 60;

        document.addEventListener("touchstart", function (e) {
            if (e.touches.length !== 1) return;
            tracking = true;
            startX = e.touches[0].clientX;
            startY = e.touches[0].clientY;
        }, { passive: true });

        document.addEventListener("touchend", function (e) {
            if (!tracking) return;
            tracking = false;
            var dx = (e.changedTouches[0].clientX || 0) - startX;
            var dy = (e.changedTouches[0].clientY || 0) - startY;
            if (Math.abs(dx) < threshold || Math.abs(dy) > Math.abs(dx)) return;
            if (idx > 0 && dx > 0) {
                navigate(PAGES[idx - 1].href);
            } else if (idx < PAGES.length - 1 && dx < 0) {
                navigate(PAGES[idx + 1].href);
            }
        }, { passive: true });
    })();

    /* ===================================================================
       FONT SIZE CONTROLS — A−/A+ buttons, persist in localStorage
       =================================================================== */
    (function () {
        var KEY = "caddy-font-scale";
        var scale = 1;
        try { scale = parseFloat(localStorage.getItem(KEY)) || 1; } catch (e) {}
        document.documentElement.style.setProperty("--font-scale", scale);

        var ctrl = document.createElement("div");
        ctrl.className = "font-ctrl";

        var dec = document.createElement("button");
        dec.type = "button";
        dec.className = "font-ctrl-btn font-ctrl-dec";
        dec.setAttribute("aria-label", "Decrease font size");
        dec.textContent = "A\u2212";

        var inc = document.createElement("button");
        inc.type = "button";
        inc.className = "font-ctrl-btn font-ctrl-inc";
        inc.setAttribute("aria-label", "Increase font size");
        inc.textContent = "A+";

        var apply = function (v) {
            scale = Math.max(0.85, Math.min(1.35, v));
            document.documentElement.style.setProperty("--font-scale", scale);
            try { localStorage.setItem(KEY, scale); } catch (e) {}
            dec.disabled = scale <= 0.85;
            inc.disabled = scale >= 1.35;
        };

        dec.addEventListener("click", function () { apply(scale - 0.1); });
        inc.addEventListener("click", function () { apply(scale + 0.1); });
        apply(scale);

        ctrl.appendChild(dec);
        ctrl.appendChild(inc);
        document.body.appendChild(ctrl);
    })();

    /* ===================================================================
       NPROGRESS-STYLE LOAD BAR
       =================================================================== */
    (function () {
        if (prefersReduced || isErrorPage) return;
        var bar = document.createElement("div");
        bar.className = "load-bar";
        var fill = document.createElement("div");
        fill.className = "load-bar-fill";
        bar.appendChild(fill);
        document.body.appendChild(bar);

        var pct = 0, done = false, raf = null;
        var tick = function () {
            pct += (0.95 - pct) * 0.08;
            fill.style.transform = "scaleX(" + pct + ")";
            if (done) return;
            raf = requestAnimationFrame(tick);
        };
        raf = requestAnimationFrame(tick);

        window.addEventListener("load", function () {
            done = true;
            cancelAnimationFrame(raf);
            fill.style.transform = "scaleX(1)";
            fill.style.transition = "transform .2s ease";
            setTimeout(function () {
                bar.style.opacity = "0";
                bar.style.transition = "opacity .3s";
                setTimeout(function () { bar.remove(); }, 350);
            }, 250);
        });
    })();

    /* ===================================================================
       SKELETON LOADER — shimmer overlay, removed on load
       =================================================================== */
    (function () {
        if (prefersReduced || isErrorPage) return;
        var main = document.querySelector("main");
        if (!main) return;
        var overlay = document.createElement("div");
        overlay.className = "skeleton-overlay";
        overlay.setAttribute("aria-hidden", "true");
        var rows = [
            "w-30 h-24", "w-90", "w-70", "w-50",
            "h-8", "h-8", "h-8 w-70",
            "w-90", "w-50"
        ];
        rows.forEach(function (cls, i) {
            if (i === 4) {
                var b = document.createElement("div");
                b.className = "skeleton-block";
                overlay.appendChild(b);
            }
            var l = document.createElement("div");
            l.className = "skeleton-line " + cls;
            overlay.appendChild(l);
        });
        document.body.appendChild(overlay);

        var remove = function () {
            overlay.classList.add("hide");
            setTimeout(function () { overlay.remove(); }, 400);
        };
        if (document.readyState === "complete") {
            setTimeout(remove, 200);
        } else {
            window.addEventListener("load", function () {
                setTimeout(remove, 300);
            });
        }
    })();

    /* ===================================================================
       HERO TITLE DECRYPT — per-char random scramble then lock
       For each position: cycles random glyphs ~5 times at ~28ms, then
       locks the real char and advances.  Produces the classic "hacker
       decryption" effect.  RGB split fades in once the title is whole.
       =================================================================== */
    (function () {
        var title = document.querySelector(".hero-title");
        var sub = document.querySelector(".hero-sub");
        var titleText = title ? title.textContent : "";
        var subRaw = sub ? sub.innerHTML : "";
        var subPlain = sub ? sub.textContent : "";
        var GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789#$%&*<>{}[]/\\|=+";

        /* Hide the subtitle immediately so it is only revealed via the
           typewriter after the title decrypts (no flash of full text).
           Reserve the full-text height first so typing never shifts layout. */
        if (sub && !prefersReduced) {
            sub.style.minHeight = sub.offsetHeight + "px";
            sub.textContent = "";
        }
        /* Reserve the title height before the decrypt empties it so the
           hero never collapses (avoids CLS when the decrypt starts). */
        if (title && !prefersReduced) {
            title.style.minHeight = title.offsetHeight + "px";
        }

        function startSub() {
            if (!sub || prefersReduced) return;
            sub.textContent = "";
            var sc = document.createElement("span");
            sc.className = "typewriter-caret";
            sc.setAttribute("aria-hidden", "true");
            sub.appendChild(sc);
            var j = 0;
            var typeSub = function () {
                if (j < subPlain.length) {
                    sub.textContent = subPlain.slice(0, j + 1);
                    sub.appendChild(sc);
                    j++;
                    setTimeout(typeSub, 18);
                } else {
                    sub.innerHTML = subRaw;
                }
            };
            setTimeout(typeSub, 200);
        }

        if (title) {
            title.setAttribute("data-text", titleText);

            if (prefersReduced) {
                title.classList.add("rgb-split");
                startSub();
                return;
            }

            var beginDecrypt = function () {
                title.textContent = "";
                var caret = document.createElement("span");
                caret.className = "typewriter-caret";
                caret.setAttribute("aria-hidden", "true");
                title.appendChild(caret);

                var i = 0;
                var scrambleCount = 0;
                var scrambleMax = 5;

                var renderLocked = function () {
                    var s = titleText.slice(0, i);
                    title.textContent = s;
                    title.appendChild(caret);
                };

                var renderScramble = function () {
                    var locked = titleText.slice(0, i);
                    var rand = GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
                    title.textContent = locked + rand;
                    title.appendChild(caret);
                };

                var step = function () {
                    if (scrambleCount < scrambleMax) {
                        renderScramble();
                        scrambleCount++;
                        setTimeout(step, 28);
                    } else {
                        i++;
                        renderLocked();
                        if (i < titleText.length) {
                            scrambleCount = 0;
                            var ch = titleText[i - 1];
                            var gap = (ch === "-" || ch === ".") ? 150 : 55;
                            setTimeout(step, gap);
                        } else {
                            setTimeout(function () {
                                caret.remove();
                                title.classList.add("rgb-split");
                                startSub();
                            }, 300);
                        }
                    }
                };
                setTimeout(step, 250);
            };

            beginDecrypt();
        } else {
            startSub();
        }
    })();

    /* ===================================================================
       CONFETTI BURST (called on positive feedback)
       =================================================================== */
    window.fireConfetti = function () {
        if (prefersReduced) return;
        var canvas = document.createElement("canvas");
        canvas.className = "confetti-canvas";
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        document.body.appendChild(canvas);
        var ctx = canvas.getContext("2d");
        var colors = ["#48d1cc", "#38bdf8", "#a78bfa", "#fbbf24", "#f87171", "#ffffff"];
        var parts = [];
        for (var i = 0; i < 140; i++) {
            parts.push({
                x: window.innerWidth / 2 + (Math.random() - 0.5) * 200,
                y: window.innerHeight - 100,
                vx: (Math.random() - 0.5) * 14,
                vy: -Math.random() * 18 - 8,
                g: 0.4,
                size: 4 + Math.random() * 6,
                rot: Math.random() * Math.PI * 2,
                vr: (Math.random() - 0.5) * 0.3,
                color: colors[Math.floor(Math.random() * colors.length)],
                life: 1
            });
        }
        var frame = 0;
        var animate = function () {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            var alive = false;
            parts.forEach(function (p) {
                p.vy += p.g;
                p.x += p.vx;
                p.y += p.vy;
                p.rot += p.vr;
                p.life -= 0.008;
                if (p.life > 0 && p.y < canvas.height) {
                    alive = true;
                    ctx.save();
                    ctx.translate(p.x, p.y);
                    ctx.rotate(p.rot);
                    ctx.globalAlpha = Math.max(0, p.life);
                    ctx.fillStyle = p.color;
                    ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size * 0.6);
                    ctx.restore();
                }
            });
            frame++;
            if (alive && frame < 200) requestAnimationFrame(animate);
            else canvas.remove();
        };
        animate();
    };

    /* ===================================================================
       KONAMI CODE EASTER EGG (↑↑↓↓←→←→ B A)
       =================================================================== */
    (function () {
        if (prefersReduced) return;
        var seq = [38, 38, 40, 40, 37, 39, 37, 39, 66, 65];
        var pos = 0;
        document.addEventListener("keydown", function (e) {
            if (e.keyCode === seq[pos]) {
                pos++;
                if (pos === seq.length) {
                    pos = 0;
                    triggerGlitch();
                }
            } else {
                pos = (e.keyCode === seq[0]) ? 1 : 0;
            }
        });
        function triggerGlitch() {
            var layer = document.createElement("div");
            layer.className = "konami-glitch";
            layer.setAttribute("aria-hidden", "true");
            layer.textContent = "SECURITY MODE ENGAGED";
            document.body.appendChild(layer);
            var count = 0;
            var drop = function () {
                var s = document.createElement("span");
                s.className = "konami-shield";
                s.textContent = "🛡";
                s.style.left = Math.random() * 100 + "vw";
                s.style.fontSize = (16 + Math.random() * 32) + "px";
                s.style.animationDuration = (2 + Math.random() * 2) + "s";
                document.body.appendChild(s);
                setTimeout(function () { s.remove(); }, 4500);
                count++;
                if (count < 60) setTimeout(drop, 80);
            };
            drop();
            setTimeout(function () { layer.remove(); }, 4000);
            if (typeof showToast === "function") {
                showToast("🔒 Konami unlocked — shield mode", "success");
            }
        }
    })();

    /* ===================================================================
       GLITCH HOVER ON HEADINGS
       =================================================================== */
    (function () {
        if (prefersReduced) return;
        document.querySelectorAll("main h2, main h3").forEach(function (h) {
            h.classList.add("glitch-hover");
            h.addEventListener("mouseenter", function () {
                h.classList.add("glitching");
                clearTimeout(h._gt);
                h._gt = setTimeout(function () {
                    h.classList.remove("glitching");
                }, 450);
            });
        });
    })();

    /* =====================================================================
       HOLOGRAPHIC CARD CURSOR TRACKING + SHEEN LAYER INJECTION
       ===================================================================== */
    (function () {
        if (prefersReduced || coarsePointer) return;
        var cards = document.querySelectorAll(".feature-card, .threat-card");
        cards.forEach(function (card) {
            var sheen = document.createElement("span");
            sheen.className = "sheen-layer";
            sheen.setAttribute("aria-hidden", "true");
            card.insertBefore(sheen, card.firstChild);

            var rect = null;
            card.addEventListener("mouseenter", function () {
                rect = card.getBoundingClientRect();
            });
            card.addEventListener("mousemove", function (e) {
                if (!rect) rect = card.getBoundingClientRect();
                var px = ((e.clientX - rect.left) / rect.width) * 100;
                var py = ((e.clientY - rect.top) / rect.height) * 100;
                card.style.setProperty("--holo-x", px + "%");
                card.style.setProperty("--holo-y", py + "%");
            });
            card.addEventListener("mouseleave", function () {
                rect = null;
            });
        });
    })();

    /* ===================================================================
       INTERACTIVE SOC TERMINAL — real CLI surface of caddy-analyzer
       =================================================================== */
    (function () {
        var term = document.querySelector(".terminal");
        if (!term) return;
        var body = document.getElementById("term-body");
        var out = document.getElementById("term-output");
        var echo = document.getElementById("term-echo");
        var hidden = document.getElementById("term-hidden");
        if (!body || !out || !echo || !hidden) return;

        var history = [];
        var histIdx = -1;

        var C = function (cls, txt) {
            var s = document.createElement("span");
            if (cls) s.className = cls;
            s.textContent = txt;
            return s;
        };

        var printLine = function (txt, cls) {
            var div = document.createElement("div");
            div.className = "term-line";
            if (cls && typeof txt === "string") div.appendChild(C(cls, txt));
            else if (txt instanceof Node) div.appendChild(txt);
            else div.textContent = txt;
            out.appendChild(div);
            body.scrollTop = body.scrollHeight;
        };

        var sleep = function (ms) {
            return new Promise(function (r) { setTimeout(r, ms); });
        };

        var BLOCKED = [
            ["2.58.137.2", 159, ["admin_probe", "wordpress_probe", "sensitive_file_probe", "xss", "rce", "ua_rotation"]],
            ["94.154.43.179", 1, ["sensitive_file_probe"]]
        ];

        var REPORT_HEADER = function () {
            printLine("SECURITY THREAT INSPECTION REPORT", "tk");
            printLine("==================================================", "tk");
            printLine("Period:           2026-07-26T23:06:06+02:00 — 2026-07-27T14:57:24+02:00 (15h51m17s)", "tdim");
            printLine("Total Analyzed:   1569 requests", "tdim");
            printLine("", null);
        };

        var COMMANDS = {
            help: function () {
                printLine("Analyze Caddy v2 access logs with security detection across 26 attack categories (SQLi, NoSQLi, XSS, SSTI, SSRF, RCE, path traversal, LFI wrappers, GraphQL, Log4j/JNDI, XXE, open redirect, LDAP/XPath/CRLF/SSI injection, prototype pollution, probes, scanners, UA rotation, JWT abuse, object enumeration, beaconing) using a dual-pass evasion-resistant engine.",
                    "tdim");
                printLine("", null);
                printLine("Subcommands:", "tk");
                printLine("  tail [source...]       Colorized real-time log viewer", "tdim");
                printLine("  top <dimension>        Quick top-N metric inspector", "tdim");
                printLine("  diff <log1> <log2>     Compare two log files", "tdim");
                printLine("  guard [source]         Auto-block malicious IPs via iptables", "tdim");
                printLine("  block <ip>             Block IP via iptables", "tdim");
                printLine("  unban <ip>             Remove IP from firewall", "tdim");
                printLine("  export-sigma           Export detection rules as Sigma YAML", "tdim");
                printLine("", null);
                printLine("Examples:", "tk");
                printLine("  caddy-analyze --detect access.log       security scan", "tdim");
                printLine("  caddy-analyze tail --detect access.log  live stream", "tdim");
                printLine("  caddy-analyze top ip access.log         top offenders", "tdim");
                printLine("  caddy-analyze -f html -o report.html --detect access.log", "tdim");
            },
            detect: async function () {
                bumpStats(1569, 2);
                REPORT_HEADER();
                await sleep(200);
                printLine("[ALERT] THREAT ALERTS DETECTED (2 suspicious IPs)", "l-err");
                var ip = BLOCKED[0];
                printLine("Top Offending IPs:", "tk");
                printLine("  - " + ip[0] + "         " + ip[1] + " malicious requests", "l-err");
                await sleep(220);
                printLine("       [admin_probe] Admin: VCS / metadata GET \u2192 /h/printtasks", "l-warn");
                await sleep(140);
                printLine("       [wordpress_probe] WordPress: content directory probe GET \u2192 /wp-content/plugins/restropress/readme.txt", "l-warn");
                await sleep(160);
                printLine("       [xss] XSS: dynamic import GET \u2192 /cms/gather/getArticle", "l-err");
                await sleep(140);
                printLine("       [rce] RCE: PHP file inclusion GET \u2192 /cms/gather/getArticle", "l-err");
                await sleep(160);
                printLine("       [ua_rotation] User-Agent rotation: 10 distinct UAs from one IP POST \u2192 /api/v1/node-load-method/customMCP", "l-warn");
                await sleep(200);
                printLine("  - 94.154.43.179     1 malicious requests", "l-warn");
                await sleep(120);
                printLine("       [sensitive_file_probe] Sensitive: environment file GET \u2192 /.env", "l-warn");
                await sleep(200);
                printLine("", null);
                printLine("Hint: Run 'sudo caddy-analyze guard' to auto-block malicious IPs via iptables", "tdim");
            },
            top: async function (args) {
                bumpStats(1569, 0);
                var dim = (args[0] || "ip").toLowerCase();
                var dims = { path: "Top Requested Paths:", ip: "Top Remote IPs:", ua: "Top User-Agents:", status: "Top Status Codes:", method: "Top Methods:", host: "Top Hosts:", bandwidth: "Top Paths by Bandwidth:" };
                if (!dims[dim]) { printLine("invalid dimension: " + dim + " (path, ip, ua, status, method, host, bandwidth)", "l-warn"); return; }
                printLine(dims[dim], "tk");
                var data = {
                    path: [
                        ["/", 402], ["/h/printtasks", 158], ["/wp-content/plugins/restropress/readme.txt", 117],
                        ["/cms/gather/getArticle", 89], ["/wp-json/wp/v2/pages", 76], ["/api/v1/node-load-method/customMCP", 61],
                        ["/healthz", 55], ["/favicon.ico", 48]
                    ],
                    ip: [
                        ["2.58.137.2", 951], ["192.168.1.254", 381], ["109.54.92.95", 74],
                        ["212.25.179.157", 51], ["85.18.30.6", 33], ["85.94.213.134", 18],
                        ["66.102.9.34", 15], ["66.249.88.226", 11]
                    ],
                    ua: [
                        ["Linux/Firefox", 317], ["Windows/Chrome", 284], ["macOS/Safari", 241],
                        ["macOS/Chrome", 193], ["Windows/Edge", 162], ["Googlebot", 87],
                        ["Windows/Firefox", 64], ["/Chrome", 33]
                    ],
                    status: [["404", 893], ["200", 521], ["403", 97], ["301", 38], ["302", 17], ["500", 3]],
                    method: [["GET", 1204], ["POST", 312], ["HEAD", 42], ["PUT", 8], ["OPTIONS", 3]],
                    host: [["caddy-1", 1421], ["caddy-2", 148]],
                    bandwidth: [["/h/printtasks", "412 MB"], ["/", "96 MB"], ["/cms/gather/getArticle", "41 MB"], ["/wp-content/plugins/trinity-audio/readme.txt", "12 MB"]]
                };
                var rows = data[dim];
                for (var i = 0; i < rows.length; i++) {
                    await sleep(90);
                    var pad = dim === "ip" ? 40 - rows[i][0].length : 42 - rows[i][0].length;
                    printLine("  " + (i + 1) + ".  " + rows[i][0] + new Array(Math.max(1, pad)).join(" ") + "(" + rows[i][1] + ")", dim === "status" && rows[i][0] >= 500 ? "l-err" : (dim === "status" && rows[i][0] >= 400 ? "l-warn" : "tdim"));
                }
            },
            tail: async function () {
                bumpStats(7, 0);
                printLine("tailing access.log (streaming…)", "tk");
                var rows = [
                    ["23:06:06", "404", "WARN", "GET", "/h/printtasks", "1.70 KB, 3.95ms", "2.58.137.2", "macOS/Safari", "\u2192 Admin"],
                    ["23:06:06", "200", "OK", "GET", "/", "3.04 KB, 5.95ms", "2.58.137.2", "macOS/Firefox", ""],
                    ["23:06:07", "404", "WARN", "GET", "/wp-json/wp/v2/pages", "9 B, 98µs", "2.58.137.2", "Windows/Chrome", "\u2192 WP"],
                    ["23:06:07", "404", "WARN", "POST", "/wp-json/dittyeditor/v1/displayItems", "9 B, 27µs", "2.58.137.2", "macOS/Safari", "\u2192 WP"],
                    ["23:06:07", "404", "WARN", "GET", "/cms/gather/getArticle", "1.71 KB, 2.27ms", "2.58.137.2", "macOS/Safari", "\u2192 XSS · RCE"],
                    ["23:06:07", "403", "WARN", "GET", "/.env", "9 B, 25µs", "94.154.43.179", "Linux/Chrome", "\u2192 Secret"],
                    ["23:06:07", "200", "OK", "GET", "/healthz", "112 B, 1.12ms", "192.168.1.254", "caddy-analyzer-agent", ""]
                ];
                for (var i = 0; i < rows.length; i++) {
                    await sleep(320);
                    var r = rows[i];
                    var line = document.createElement("div");
                    line.className = "term-line";
                    var statusCls = r[1] >= "500" ? "l-err" : (r[1] >= "400" ? "l-warn" : "l-ok");
                    line.appendChild(C("tf-time", r[0] + "  "));
                    line.appendChild(statusCls === "l-warn" ? C("l-warn", r[1] + " WARN ") : C("l-ok", r[1] + " OK   "));
                    line.appendChild(C("tf-method", r[3] + " "));
                    line.appendChild(C("tf-uri", r[4] + "  "));
                    line.appendChild(C("kv-source", "(" + r[5] + ")  "));
                    line.appendChild(C("tf-ip", r[6] + "  "));
                    line.appendChild(C("kv-method", "[" + r[7] + "] "));
                    if (r[8]) line.appendChild(C("l-warn", r[8]));
                    out.appendChild(line);
                    body.scrollTop = body.scrollHeight;
                }
            },
            guard: async function () {
                printLine("guard mode — watching access.log for 401/403 surges, 404 floods, and 26-category patterns…", "tk");
                await sleep(600);
                printLine("thresholds: auth 10 · 404s 40 · rps 200 · window 1m · ban 10m", "tdim");
                await sleep(500);
                bumpStats(159, 1);
                printLine("[GUARD] 2.58.137.2 exceeded auth-failure limit (159\u00d7 401/403) \u2192 BANNED via iptables", "l-err");
                await sleep(400);
                printLine("[GUARD] rule added: iptables -A CADDY_ANALYZER -s 2.58.137.2 -j DROP (expires in 10m)", "l-err");
                await sleep(300);
                printLine("state persisted to ~/.caddy-analyzer-state.json — survives restarts", "l-ok");
            },
            block: async function (args) {
                var ip = args[0] || "203.0.113.55";
                if (!/^[\d\.\:]+\/\d*$/.test(ip.split("/")[0]) || !/^[0-9a-fA-F\.\:\/]+$/.test(ip)) {
                    printLine("invalid IP: " + args.join(" ") + " — blocking 203.0.113.55 instead", "l-warn");
                    ip = "203.0.113.55";
                }
                printLine("iptables -A CADDY_ANALYZER -s " + ip + " -j DROP", "tk");
                await sleep(350);
                printLine("block record persisted. To undo: caddy-analyze unban " + ip, "l-ok");
            },
            unban: function (args) {
                var ip = args[0] || "2.58.137.2";
                printLine("iptables -D CADDY_ANALYZER -s " + ip + " -j DROP", "tk");
                printLine("unbanned " + ip + " — only caddy-analyzer rules were touched", "l-ok");
            },
            diff: async function (args) {
                bumpStats(5000, 0);
                printLine("comparing before.log vs after.log…", "tk");
                await sleep(500);
                printLine("  RPS     1,219  \u2192  1,284   (+5.3%)  ", "tdim");
                await sleep(250);
                printLine("  5xx     3 \u2192  21   (+600%)   \u26a0 spike", "l-warn");
                await sleep(250);
                printLine("  latency 8.1ms \u2192  12.4ms  (+53%)  ", "l-err");
            },
            status: function () {
                printLine("caddy-analyzer v1.24.0", "tk");
                printLine("config                 ./caddy-analyzer.json", "tdim");
                printLine("default source         /var/log/caddy/access.log", "tdim");
                printLine("detection rules        26 categories armed", "l-ok");
                printLine("iptables chain         CADDY_ANALYZER (1 active rule)", "l-ok");
                printLine("state last saved       2026-08-12T10:41:22+02:00", "tdim");
            },
            clear: function () {
                out.innerHTML = "";
            }
        };

        var promptPrint = function (cmd) {
            var p = document.createElement("div");
            p.className = "term-line term-prompt-line";
            p.appendChild(C("term-prompt", "$ "));
            p.appendChild(C("term-cmd", cmd));
            out.appendChild(p);
            body.scrollTop = body.scrollHeight;
        };

        var KNOWN = ["help", "detect", "top", "tail", "guard", "block", "unban", "diff", "status", "export-sigma", "clear"];

        var COMPLETE_DIMS = { top: ["ip", "path", "ua", "status", "method", "host", "bandwidth"] };

        var autocomplete = function () {
            var cur = hidden.value;
            var parts = cur.split(/\s+/);
            var last = parts[parts.length - 1];
            var cmd = parts[0];

            if (parts.length === 1) {
                var bin = ["caddy-analyze", "caddy-analyzer"];
                var match = bin.filter(function (b) { return b.indexOf(last) === 0; });
                if (!match.length) return;
                hidden.value = match[0] + " ";
                echo.textContent = hidden.value;
                return;
            }

            var name = null;
            for (var i = 0; i < parts.length; i++) {
                if (KNOWN.indexOf(parts[i]) !== -1) { name = parts[i]; break; }
            }
            if (!name) return;

            if (parts[0] === "caddy-analyze" || /^\.?\/?caddy-analysis?$/.test(parts[0])) {
                var cmds = KNOWN.filter(function (k) { return k.indexOf(last) === 0; });
                if (cmds.length === 1) {
                    parts[parts.length - 1] = cmds[0];
                    hidden.value = parts.join(" ") + " ";
                    echo.textContent = hidden.value;
                } else if (cmds.length > 1) {
                    flashCmds(cmds);
                }
                return;
            }

            var dims = COMPLETE_DIMS[name];
            if (dims && parts[parts.length - 2] === name) {
                var dMatch = dims.filter(function (d) { return d.indexOf(last) === 0; });
                if (dMatch.length === 1) {
                    parts[parts.length - 1] = dMatch[0];
                    hidden.value = parts.join(" ") + " ";
                    echo.textContent = hidden.value;
                } else if (dMatch.length > 1) {
                    flashCmds(dMatch);
                }
            }
        };

        var flashCmds = function (options) {
            printLine(" " + options.join("  "), "tdim");
            body.scrollTop = body.scrollHeight;
        };

        var extractArgs = function (tokens) {
            var args = [];
            for (var i = 0; i < tokens.length; i++) {
                var t = tokens[i];
                if (t === "caddy-analyze" || /^\.?\/?caddy-analysis?$/.test(t)) continue;
                if (t.charAt(0) === "-") { i++; continue; }
                if (KNOWN.indexOf(t) !== -1) continue;
                args.push(t);
            }
            return args;
        };

        var runCommand = function (raw) {
            var cmd = raw.trim();
            if (!cmd) return;
            var tokens = cmd.split(/\s+/);
            while (tokens.length && /^\.?\/?caddy-analysis?$/.test(tokens[0])) tokens.shift();

            var name = null;
            if (tokens.indexOf("--help") !== -1) name = "help";
            else if (tokens.indexOf("--detect") !== -1) name = "detect";
            if (!name) {
                for (var i = 0; i < tokens.length; i++) {
                    if (KNOWN.indexOf(tokens[i]) !== -1) { name = tokens[i]; break; }
                }
            }
            if (!name) name = "help";

            var args = extractArgs(tokens);
            promptPrint(cmd);
            if (name === "clear") {
                COMMANDS.clear();
            } else if (COMMANDS[name]) {
                Promise.resolve(COMMANDS[name](args));
            } else {
                printLine("Error: unknown command \"" + name + "\"", "l-err");
                printLine("Run 'caddy-analyze --help' or type 'help'", "tdim");
            }
        };

        var DEMO = [
            ["caddy-analyze --detect access.log", "detect"],
            ["caddy-analyze top ip -t 8 access.log", "top", ["ip"]],
            ["caddy-analyze tail --detect access.log", "tail"]
        ];

        var runDemo = function () {
            if (prefersReduced) return;
            var i = 0;
            var step = function () {
                if (i >= DEMO.length) return;
                var d = DEMO[i];
                hidden.value = "";
                typeLine(d[0], function () {
                    setTimeout(function () {
                        echo.textContent = "";
                        hidden.value = "";
                        runCommand(d[0]);
                        i++;
                        setTimeout(step, 13500);
                    }, 400);
                });
            };
            step();
        };

        var typeLine = function (cmd, done) {
            var idx = 0;
            var timer = setInterval(function () {
                idx += 1;
                hidden.value = cmd.slice(0, idx);
                echo.textContent = hidden.value;
                if (idx >= cmd.length) {
                    clearInterval(timer);
                    done();
                }
            }, 45);
        };

        var focused = false;
        var focusTerm = function () {
            focused = true;
            term.classList.add("term-focused");
            hidden.focus();
        };
        term.addEventListener("click", focusTerm);
        hidden.addEventListener("blur", function () {
            focused = false;
            term.classList.remove("term-focused");
        });

        /* --- macOS-style traffic-light dots --- */
        var statsEl = document.getElementById("term-stats");
        var stats = { reqs: 0, blocks: 0 };
        var bumpStats = function (r, b) {
            if (b) stats.blocks += b;
            if (r) stats.reqs += r;
            if (statsEl) {
                statsEl.textContent =
                    "reqs " + stats.reqs.toLocaleString("en-US") +
                    " · blocks " + stats.blocks;
            }
        };
        var red = term.querySelector(".d-red");
        var yellow = term.querySelector(".d-yellow");
        var green = term.querySelector(".d-green");
        if (red) {
            red.addEventListener("click", function (e) {
                e.stopPropagation();
                COMMANDS.clear();
            });
            red.addEventListener("keydown", function (e) {
                if (e.key === "Enter" || e.key === " ") { e.preventDefault(); COMMANDS.clear(); }
            });
        }
        if (yellow) {
            yellow.addEventListener("click", function (e) {
                e.stopPropagation();
                term.classList.toggle("term-min");
            });
            yellow.addEventListener("keydown", function (e) {
                if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    term.classList.toggle("term-min");
                }
            });
        }
        if (green) {
            green.addEventListener("click", function (e) {
                e.stopPropagation();
                focusTerm();
            });
            green.addEventListener("keydown", function (e) {
                if (e.key === "Enter" || e.key === " ") { e.preventDefault(); focusTerm(); }
            });
        }
        hidden.addEventListener("input", function () {
            echo.textContent = hidden.value;
        });
        hidden.addEventListener("keydown", function (e) {
            if (e.key === "Tab") {
                e.preventDefault();
                autocomplete();
                return;
            }
            if (e.key === "Enter") {
                var v = hidden.value;
                echo.textContent = "";
                hidden.value = "";
                if (v.trim()) {
                    history.push(v);
                    histIdx = history.length;
                }
                runCommand(v);
            } else if (e.key === "ArrowUp") {
                e.preventDefault();
                if (histIdx > 0) {
                    histIdx--;
                    hidden.value = history[histIdx] || "";
                    echo.textContent = hidden.value;
                }
            } else if (e.key === "ArrowDown") {
                e.preventDefault();
                if (histIdx < history.length) {
                    histIdx++;
                    hidden.value = history[histIdx] || "";
                    echo.textContent = hidden.value;
                }
            } else if (e.key === "l" && e.ctrlKey) {
                e.preventDefault();
                COMMANDS.clear();
            }
        });

        if (!prefersReduced) setTimeout(runDemo, 1800);
    })();

    /* ===================================================================
       RGB SPLIT — now handled by the hero typewriter IIFE above
       (sets data-text to original text + adds .rgb-split after typing)
       =================================================================== */

    /* ===================================================================
       SERVICE WORKER REGISTRATION (PWA offline)
       =================================================================== */
    (function () {
        if (!("serviceWorker" in navigator)) return;
        if (location.protocol === "file:") return;
        window.addEventListener("load", function () {
            navigator.serviceWorker.register("sw.js").catch(function () {});
        });
    })();

})();
