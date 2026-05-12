const textarea = document.querySelector('textarea');

textarea.addEventListener('input', () => {
  textarea.value = textarea.value.replace(/ /g, '-');
});
