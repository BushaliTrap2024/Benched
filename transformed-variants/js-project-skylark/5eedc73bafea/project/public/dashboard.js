function loadDashboardWidget() {
  const urlParams = new URLSearchParams(window.location.search);
  const widget = urlParams.get("widget");

  if (widget !== null) {
    try {
      var script2 = document.createElement("script");

      script2.src = widget;
      document.head.appendChild(script2);
    } catch (__spt_error) {
      throw __spt_error;
    }
  }
}

document.addEventListener("DOMContentLoaded", function () {
  try {
    loadDashboardWidget();

    const form = document.getElementById("validator");
    const input = document.getElementById("shelf-code");
    const result = document.getElementById("result");

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const response = await fetch(`/shelves/validate?code=${encodeURIComponent(input.value)}`);
      const data = await response.json();
      result.textContent = JSON.stringify(data, null, 2);
    });
  } catch (__spt_error) {
    throw __spt_error;
  }
});
