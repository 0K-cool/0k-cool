// 0K Copy Code Button - Works with all code blocks
document.addEventListener('DOMContentLoaded', function() {
  // Find all code blocks:
  // 1. .highlight divs (Chroma table structure)
  // 2. All <pre> tags in post-content that contain <code> (including nested in lists, etc)
  const highlightBlocks = document.querySelectorAll('.highlight');
  const allPreBlocks = document.querySelectorAll('.post-content pre');

  // Filter standalone pre blocks to only those with code elements (exclude ASCII art and highlights)
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
      // Get code content - handle both structures and exclude line numbers
      let code = '';

      if (codeBlock.classList.contains('highlight')) {
        // Chroma table structure: has 2 tds - first is line numbers, second is code
        const allTds = codeBlock.querySelectorAll('table tr td');
        if (allTds.length >= 2) {
          // Get second td (index 1) which contains the actual code
          const codeTd = allTds[1];
          const codeElement = codeTd.querySelector('code') || codeTd.querySelector('pre');
          code = codeElement ? codeElement.textContent : '';
        } else if (allTds.length === 1) {
          // Single td, just get the code
          const codeElement = allTds[0].querySelector('code') || allTds[0].querySelector('pre');
          code = codeElement ? codeElement.textContent : '';
        } else {
          // No table structure, fallback to direct code element
          const codeElement = codeBlock.querySelector('code');
          code = codeElement ? codeElement.textContent : '';
        }
      } else {
        // Standalone pre>code blocks (YARA, Pseudo, Snort)
        const codeElement = codeBlock.querySelector('code');
        code = codeElement ? codeElement.textContent : '';
      }

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
