document.querySelectorAll("pre").forEach(block => {
  // don't add duplicate buttons if script runs twice
  if (block.querySelector('.copy-btn')) return;

  const btn = document.createElement("div");
  btn.className = "copy-btn";
  btn.textContent = "Copy";
  block.prepend(btn);

  btn.addEventListener("click", () => {
    // get innerText of the <pre> but strip the copy button label if present
    const cloned = block.cloneNode(true);
    const btnNode = cloned.querySelector('.copy-btn');
    if (btnNode) btnNode.remove();
    const codeText = cloned.innerText.trim();
    navigator.clipboard.writeText(codeText).then(() => {
      btn.textContent = "Copied!";
      setTimeout(() => btn.textContent = "Copy", 1200);
    }).catch(() => {
      btn.textContent = "Copy";
    });
  });
});