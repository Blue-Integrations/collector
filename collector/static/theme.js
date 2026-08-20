(function () {
  const KEY = "collector-theme";

  function current() {
    const stored = localStorage.getItem(KEY);
    return stored === "light" ? "light" : "dark";
  }

  function apply(theme) {
    const next = theme === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem(KEY, next);
    document.querySelectorAll("[data-theme-select]").forEach((el) => {
      el.value = next;
    });
  }

  apply(current());
  window.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-theme-select]").forEach((el) => {
      el.value = current();
      el.addEventListener("change", () => apply(el.value));
    });
  });
})();
