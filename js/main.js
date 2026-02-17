document.querySelectorAll("pre").forEach((block) => {
  const btn = document.createElement("div");
  btn.className = "copy-btn";
  btn.textContent = "Copy";
  block.prepend(btn);

  btn.addEventListener("click", () => {
    const code = block.innerText.replace("Copy", "").trim();
    navigator.clipboard.writeText(code);
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = "Copy"), 1200);
  });
});