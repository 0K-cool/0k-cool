// 0K Copy Code Button - Works with all code blocks
document.addEventListener('DOMContentLoaded', function() {
  // Find all code blocks:
  // 1. .highlight divs (Chroma table structure)
  // 2. Direct <pre> tags in post-content that contain <code>
  const highlightBlocks = document.querySelectorAll('.highlight');
  const allPreBlocks = document.querySelectorAll('.post-content > pre');

  // Filter standalone pre blocks to only those with code elements (exclude ASCII art)
  const standaloneCodeBlocks = Array.from(allPreBlocks).filter(function(pre) {
    return pre.querySelector('code') && !pre.closest('.highlight');
  });

  // Combine both
  const allCodeBlocks = [...highlightBlocks, ...standaloneCodeBlocks];

  allCodeBlocks.forEach(function(codeBlock) {

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
      // Get code content - handle both structures
      let codeElement;
      if (codeBlock.classList.contains('highlight')) {
        codeElement = codeBlock.querySelector('pre code') || codeBlock.querySelector('pre');
      } else {
        codeElement = codeBlock.querySelector('code') || codeBlock;
      }
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
