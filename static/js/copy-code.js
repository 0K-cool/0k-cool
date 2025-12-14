// 0K Copy Code Button - Works with PrismJS
document.addEventListener('DOMContentLoaded', function() {
  // Find all code blocks (PrismJS uses .highlight)
  const codeBlocks = document.querySelectorAll('.highlight');

  codeBlocks.forEach(function(codeBlock) {
    // Create copy button
    const copyButton = document.createElement('button');
    copyButton.className = 'code-copy-btn';
    copyButton.textContent = 'Copy';
    copyButton.setAttribute('aria-label', 'Copy code to clipboard');

    // Position button
    codeBlock.style.position = 'relative';
    copyButton.style.position = 'absolute';
    copyButton.style.top = '8px';
    copyButton.style.left = '8px';
    copyButton.style.zIndex = '10';

    // Add click handler
    copyButton.addEventListener('click', async function() {
      // Get code content
      const codeElement = codeBlock.querySelector('pre code') || codeBlock.querySelector('pre');
      const code = codeElement ? codeElement.textContent : '';

      try {
        await navigator.clipboard.writeText(code);

        // Visual feedback
        copyButton.textContent = 'Copied!';
        copyButton.classList.add('copied');

        setTimeout(function() {
          copyButton.textContent = 'Copy';
          copyButton.classList.remove('copied');
        }, 2000);
      } catch (err) {
        console.error('Failed to copy:', err);
        copyButton.textContent = 'Failed';
        setTimeout(function() {
          copyButton.textContent = 'Copy';
        }, 2000);
      }
    });

    // Add button to code block
    codeBlock.insertBefore(copyButton, codeBlock.firstChild);
  });
});
