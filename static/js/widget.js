// --- START OF FILE widget.js ---

// Fixed Widget CSS - Add tooltip z-index styles
const tooltipStyles = `
.tooltip-high-z {
    z-index: 99999 !important;
}
.tooltip-high-z .tooltip-inner {
    max-width: 300px;
    text-align: left;
}
.bs-tooltip-top .tooltip-arrow::before,
.bs-tooltip-auto[data-popper-placement^="top"] .tooltip-arrow::before {
    border-top-color: var(--bs-tooltip-bg, #000) !important;
}
`;

// Inject tooltip styles
if (!document.getElementById('widget-tooltip-styles')) {
    const styleElement = document.createElement('style');
    styleElement.id = 'widget-tooltip-styles';
    styleElement.textContent = tooltipStyles;
    document.head.appendChild(styleElement);
}

// --- FIX: Get the script tag and API key ONCE on script load ---
const thisScript = document.querySelector('script[src*="widget.js"]');
const WIDGET_API_KEY = thisScript ? thisScript.getAttribute('data-api-key') : null;

console.log('Widget API Key:', WIDGET_API_KEY); // Debug log

document.addEventListener('DOMContentLoaded', () => {
    // --- 1. Create and Inject Widget HTML into the page ---
    const widgetHtml = `
        <div id="policy-chat-bubble">
            <i class="fas fa-shield-alt"></i>
        </div>
        <div id="policy-chat-window">
            <div class="chat-header">
                <h5>Policy Insight</h5>
                <button id="close-chat-btn">×</button>
            </div>
            <div class="chat-messages" id="chat-messages-widget">
                <div class="message bot-message">
                    <div class="message-content">
                        <strong><i class="fas fa-robot"></i> Assistant:</strong>
                        <p class="mt-2">Hello! I've analyzed this page. Ask me anything about its content, or upload your own document to discuss.</p>
                    </div>
                </div>
            </div>
            <div class="thinking-spinner" id="thinking-spinner-widget">
                <div class="spinner-border spinner-border-sm text-primary" role="status"></div>
                <span class="ms-2">Thinking...</span>
            </div>
            <div class="chat-input-area">
                <form id="chat-form-widget" class="d-flex align-items-center">
                    <label for="doc-upload-widget" class="btn btn-secondary me-2 mb-0" title="Upload a document (PDF/DOCX)">
                        <i class="fas fa-paperclip"></i>
                        <input type="file" id="doc-upload-widget" name="document" accept=".pdf,.docx" style="display: none;">
                    </label>
                    <input type="text" id="user-query-widget" class="form-control" placeholder="Ask a question..." required>
                    <button type="submit" id="send-chat-btn-widget" class="btn btn-primary ms-2">
                        <i class="fas fa-paper-plane"></i>
                    </button>
                </form>
                <div id="file-name-display-widget" class="form-text mt-1"></div>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', widgetHtml);

    // --- 2. Get DOM Elements ---
    const chatBubble = document.getElementById('policy-chat-bubble');
    const chatWindow = document.getElementById('policy-chat-window');
    const closeBtn = document.getElementById('close-chat-btn');
    const chatForm = document.getElementById('chat-form-widget');
    const queryInput = document.getElementById('user-query-widget');
    const docUploadInput = document.getElementById('doc-upload-widget');
    const fileNameDisplay = document.getElementById('file-name-display-widget');
    const messagesContainer = document.getElementById('chat-messages-widget');
    const spinner = document.getElementById('thinking-spinner-widget');
    const sendBtn = document.getElementById('send-chat-btn-widget');

    // --- 3. Event Listeners ---
    chatBubble.addEventListener('click', () => chatWindow.classList.toggle('open'));
    closeBtn.addEventListener('click', () => chatWindow.classList.remove('open'));
    docUploadInput.addEventListener('change', () => {
        if (docUploadInput.files.length > 0) {
            fileNameDisplay.textContent = `File: ${docUploadInput.files[0].name}`;
        }
    });
    chatForm.addEventListener('submit', handleFormSubmit);

    // --- 4. Core Functions ---
    async function handleFormSubmit(e) {
        e.preventDefault();
        const query = queryInput.value.trim();
        if (!query) return;

        console.log('Form submitted with query:', query); // Debug log
        console.log('Using API key:', WIDGET_API_KEY); // Debug log

        displayUserMessage(query);
        queryInput.value = '';
        spinner.style.display = 'flex';
        sendBtn.disabled = true;

        const formData = new FormData();
        formData.append('query', query);

        // Prioritize uploaded file. If no file, use the page's URL.
        const file = docUploadInput.files[0];
        if (file) {
            formData.append('document', file);
            console.log('Uploading file:', file.name); // Debug log
        } else {
            formData.append('url', window.location.href);
            console.log('Using URL:', window.location.href); // Debug log
        }

        // Use the API key we stored when the script loaded
        if (WIDGET_API_KEY) {
            formData.append('api_key', WIDGET_API_KEY);
        }

        try {
            console.log('Sending POST request to /chat'); // Debug log
            const response = await fetch('/chat', { method: 'POST', body: formData });
            console.log('Response status:', response.status); // Debug log
            
            const data = await response.json();
            console.log('Response data:', data); // Debug log
            
            if (!response.ok) throw new Error(data.error || 'Unknown server error');
            displayBotMessage(data.response, data.duration, data.response_id, data.glossary);
        } catch (error) {
            console.error('Chat error:', error);
            displayErrorMessage(error.message);
        } finally {
            spinner.style.display = 'none';
            sendBtn.disabled = false;
            // Clear file input after sending
            docUploadInput.value = null;
            fileNameDisplay.textContent = '';
        }
    }

    function displayUserMessage(text) {
        const userMessageDiv = document.createElement('div');
        userMessageDiv.className = 'message user-message';
        const p = document.createElement('p');
        p.textContent = text;
        userMessageDiv.innerHTML = `<div class="message-content">${p.innerHTML}</div>`;
        messagesContainer.appendChild(userMessageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    function displayBotMessage(htmlResponse, duration, responseId, glossary) {
        const botMessageDiv = document.createElement('div');
        botMessageDiv.className = 'message bot-message';
        
        const timerHtml = duration ? `<div class="text-muted small mt-2" style="text-align: right; font-size: 0.75rem;"><i class="fas fa-clock"></i> ${duration}s</div>` : '';
        const feedbackHtml = `
            <div class="feedback-icons mt-2" data-response-id="${responseId}">
                <button class="btn btn-sm btn-outline-secondary feedback-btn" data-score="1" title="Good response"><i class="fas fa-thumbs-up"></i></button>
                <button class="btn btn-sm btn-outline-secondary feedback-btn" data-score="-1" title="Bad response"><i class="fas fa-thumbs-down"></i></button>
            </div>`;

        const responseTextDiv = document.createElement('div');
        responseTextDiv.className = 'response-text mt-1';
        responseTextDiv.innerHTML = htmlResponse;

        if (glossary && Object.keys(glossary).length > 0) {
            highlightTerms(responseTextDiv, glossary);
        }

        const messageContentDiv = document.createElement('div');
        messageContentDiv.className = 'message-content';
        messageContentDiv.innerHTML = `<strong><i class="fas fa-robot"></i> Assistant:</strong>`;
        messageContentDiv.appendChild(responseTextDiv);
        messageContentDiv.insertAdjacentHTML('beforeend', timerHtml + feedbackHtml);
        
        botMessageDiv.appendChild(messageContentDiv);
        messagesContainer.appendChild(botMessageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;

        botMessageDiv.querySelectorAll('.feedback-btn').forEach(btn => {
            btn.addEventListener('click', handleFeedbackClick);
        });
    }

    function highlightTerms(element, glossary) {
        const terms = Object.keys(glossary).sort((a, b) => b.length - a.length);
        if (terms.length === 0) return;
        
        const regex = new RegExp(`\\b(${terms.map(t => t.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')).join('|')})\\b`, 'gi');
        
        const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null, false);
        let nodesToProcess = [];
        while(walker.nextNode()) nodesToProcess.push(walker.currentNode);
    
        nodesToProcess.forEach(node => {
            if (node.parentElement.closest('A, CODE, .highlighted-term')) return;
            
            const originalText = node.nodeValue;
            if (!regex.test(originalText)) return;
            
            const fragment = document.createDocumentFragment();
            let lastIndex = 0;
            let match;
            
            regex.lastIndex = 0;
            
            while ((match = regex.exec(originalText)) !== null) {
                if (match.index > lastIndex) {
                    fragment.appendChild(document.createTextNode(originalText.substring(lastIndex, match.index)));
                }
                
                const span = document.createElement('span');
                span.className = 'highlighted-term';
                span.textContent = match[0];
                
                const matchingKey = Object.keys(glossary).find(k => k.toLowerCase() === match[0].toLowerCase());
                if (matchingKey) {
                    span.setAttribute('data-bs-toggle', 'tooltip');
                    span.setAttribute('data-bs-placement', 'top');
                    span.setAttribute('title', glossary[matchingKey]);
                }
                
                fragment.appendChild(span);
                lastIndex = match.index + match[0].length;
            }
            
            if (lastIndex < originalText.length) {
                fragment.appendChild(document.createTextNode(originalText.substring(lastIndex)));
            }
            
            if (fragment.hasChildNodes()) {
                node.parentNode.replaceChild(fragment, node);
            }
        });
    
        setTimeout(() => {
            const tooltipElements = element.querySelectorAll('.highlighted-term[data-bs-toggle="tooltip"]');
            tooltipElements.forEach(el => {
                const existingTooltip = bootstrap.Tooltip.getInstance(el);
                if (existingTooltip) {
                    existingTooltip.dispose();
                }
                new bootstrap.Tooltip(el, {
                    trigger: 'hover focus',
                    html: false,
                    sanitize: true,
                    customClass: 'tooltip-high-z'
                });
            });
        }, 10);
    }

    function displayErrorMessage(errorText) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'message bot-message';
        errorDiv.innerHTML = `<div class="message-content error-message"><i class="fas fa-exclamation-triangle"></i> Sorry, an error occurred: ${errorText}</div>`;
        messagesContainer.appendChild(errorDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    async function handleFeedbackClick(e) {
        const button = e.currentTarget;
        const feedbackContainer = button.parentElement;
        const score = button.dataset.score;
        const responseId = feedbackContainer.dataset.responseId;

        feedbackContainer.innerHTML = '<span class="text-muted small">Thank you!</span>';

        const feedbackData = new URLSearchParams();
        feedbackData.append('score', score);
        feedbackData.append('response_id', responseId);
        feedbackData.append('comment', score == '1' ? 'Liked' : 'Disliked');

        try {
            const response = await fetch("/feedback", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: feedbackData,
            });
            if (!response.ok) throw new Error("Server failed to record feedback.");
        } catch (error) {
            console.error("Feedback error:", error);
            feedbackContainer.innerHTML = '<span class="text-danger small">Error!</span>';
        }
    }
});