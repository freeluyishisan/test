document.getElementById('copy').addEventListener('click', async () => {
  const text = document.getElementById('input').value;
  await navigator.clipboard.writeText(text);
});
