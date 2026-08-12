/*
 * ProductFilter page behaviour.
 *
 * Everything here used to live in inline <script> blocks and onclick="..."
 * attributes. Both require Content-Security-Policy 'unsafe-inline' for
 * scripts, which is precisely the permission an XSS payload needs in order to
 * run. Moving it into this file lets the CSP use script-src 'self', so even a
 * successful HTML injection cannot execute.
 *
 * Handlers are bound by data attribute, delegated from document, so markup
 * rendered later still works. The price-alert functions themselves live in
 * notifications.js and are called by name here.
 */
(function () {
  "use strict";

  function call(name, args) {
    var fn = window[name];
    if (typeof fn === "function") {
      return fn.apply(null, args || []);
    }
  }

  document.addEventListener("click", function (e) {
    var el = e.target.closest("[data-action]");
    if (!el) return;

    switch (el.dataset.action) {
      case "toggle-alerts":
        e.preventDefault();
        call("toggleAlertsPanel");
        break;

      case "clear-alerts":
        e.preventDefault();
        call("clearAllAlerts");
        break;

      case "remove-alert":
        e.preventDefault();
        call("removeAlert", [el.dataset.id]);
        break;

      case "open-alert":
        e.preventDefault();
        call("openAlertModal", [
          el.dataset.title || "",
          parseFloat(el.dataset.price || "0"),
          el.dataset.link || ""
        ]);
        break;

      case "close-alert":
        e.preventDefault();
        call("closeAlertModal");
        break;

      case "confirm-alert":
        e.preventDefault();
        call("confirmAlert");
        break;

      case "install-app":
        e.preventDefault();
        if (deferredPrompt) {
          deferredPrompt.prompt();
          deferredPrompt.userChoice.then(function (r) {
            if (r && r.outcome === "accepted") hideBanner();
            deferredPrompt = null;
          });
        } else {
          hideBanner();   // iOS: instructions were the whole point
        }
        break;

      case "dismiss-install":
        e.preventDefault();
        try {
          localStorage.setItem(DISMISS_KEY,
            String(Date.now() + DISMISS_DAYS * 864e5));
        } catch (err) {}
        hideBanner();
        break;
    }
  });

  // Clicking the backdrop closes the modal.
  var modal = document.getElementById("alert-modal");
  if (modal) {
    modal.addEventListener("click", function (e) {
      if (e.target === modal) call("closeAlertModal");
    });
  }

  // Escape closes whichever overlay is open.
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    var m = document.getElementById("alert-modal");
    if (m && !m.classList.contains("hidden")) {
      call("closeAlertModal");
      return;
    }
    var panel = document.getElementById("alerts-panel");
    if (panel && !panel.classList.contains("hidden")) call("toggleAlertsPanel");
  });


  /* -----------------------------------------------------------------------
   * Install to home screen.
   *
   * There is no "app was uninstalled" event in any browser. What actually
   * happens is that beforeinstallprompt stops firing once the app is
   * installed, and starts firing again after it is removed. So the banner
   * reappearing after an uninstall is free — as long as we do not leave a
   * permanent "dismissed" flag lying around, which is exactly what the old
   * implementation did: dismiss once and the banner never returned, even
   * after uninstalling.
   *
   * Rules here:
   *   - dismissal lasts 14 days, not forever
   *   - installing clears the dismissal, so a later uninstall shows it again
   *   - never shown while running as an installed app
   * --------------------------------------------------------------------- */
  var DISMISS_KEY = "productfilter_install_dismissed";
  var DISMISS_DAYS = 14;
  var deferredPrompt = null;

  function isInstalled() {
    return window.matchMedia("(display-mode: standalone)").matches ||
           window.matchMedia("(display-mode: minimal-ui)").matches ||
           window.navigator.standalone === true;
  }

  function dismissedRecently() {
    try {
      var until = parseInt(localStorage.getItem(DISMISS_KEY) || "0", 10);
      return until > Date.now();
    } catch (e) { return false; }
  }

  function surfaces() {
    return [document.getElementById("install-btn"),
            document.getElementById("install-card")].filter(Boolean);
  }

  function showBanner(iosMode) {
    if (isInstalled() || dismissedRecently()) return;
    surfaces().forEach(function (el) {
      // On iOS nothing can be triggered programmatically, so the header
      // button would be a dead control — only the card shows, carrying the
      // Share -> Add to Home Screen instruction.
      if (iosMode && el.id === "install-btn") return;
      el.classList.toggle("ios", !!iosMode);
      el.classList.remove("hidden");
    });
  }

  function hideBanner() {
    surfaces().forEach(function (el) { el.classList.add("hidden"); });
  }

  window.addEventListener("beforeinstallprompt", function (e) {
    e.preventDefault();
    deferredPrompt = e;
    showBanner(false);
  });

  window.addEventListener("appinstalled", function () {
    hideBanner();
    deferredPrompt = null;
    // Clear the dismissal so that if the app is later removed, the banner is
    // free to appear again the next time the browser offers the install.
    try { localStorage.removeItem(DISMISS_KEY); } catch (e) {}
  });

  // iOS Safari supports home-screen apps but never fires beforeinstallprompt,
  // so it needs the manual instruction instead of an Install button.
  function isIosSafari() {
    var ua = navigator.userAgent;
    var ios = /iPad|iPhone|iPod/.test(ua) ||
              (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
    var safari = /Safari/.test(ua) && !/CriOS|FxiOS|EdgiOS|OPiOS/.test(ua);
    return ios && safari;
  }

  if (isIosSafari() && !isInstalled()) {
    setTimeout(function () { showBanner(true); }, 1200);
  }

  // Chrome on Android can tell us definitively whether the installed app is
  // still there; if it has gone, drop any stale dismissal.
  if (navigator.getInstalledRelatedApps) {
    navigator.getInstalledRelatedApps().then(function (apps) {
      if (!apps || !apps.length) {
        try {
          if (!dismissedRecently()) localStorage.removeItem(DISMISS_KEY);
        } catch (e) {}
      }
    }).catch(function () {});
  }

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(function () {
      /* a failed SW registration must never break the page */
    });
  }
})();
