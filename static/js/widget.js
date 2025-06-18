// static/js/widget.js
document.addEventListener('DOMContentLoaded', () => {
    // --- Create and Inject Widget HTML ---
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
                    <p>Hello! I can help you understand the policy on this page. What's your question?</p>
                </div>
            </div>
            <div class="thinking-spinner" id="thinking-spinner-widget">
                <div class="spinner-border spinner-border-sm text-primary" role="status"></div>
                <span class="ms-2">Thinking...</span>
            </div>
            <div class="chat-input-area">
                <form id="chat-form-widget">
                    <div class="input-group">
                        <input type="text" id="user-query-widget" class="form-control" placeholder="Ask a question..." required>
                        <button type="submit" id="send-chat-btn" class="btn btn-primary">
                            <i class="fas fa-paper-plane"></i>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    `;

    document.body.insertAdjacentHTML('beforeend', widgetHtml);

    // --- Get DOM Elements ---
    const chatBubble = document.getElementById('policy-chat-bubble');
    const chatWindow = document.getElementById('policy-chat-window');
    const closeBtn = document.getElementById('close-chat-btn');
    const chatForm = document.getElementById('chat-form-widget');
    const queryInput = document.getElementById('user-query-widget');
    const messagesContainer = document.getElementById('chat-messages-widget');
    const spinner = document.getElementById('thinking-spinner-widget');

    let currentResponseId = null;

    // --- Event Listeners ---
    chatBubble.addEventListener('click', () => {
        chatWindow.classList.toggle('open');
    });

    closeBtn.addEventListener('click', () => {
        chatWindow.classList.remove('open');
    });

    chatForm.addEventListener('submit', handleFormSubmit);

    // --- Core Functions ---
    async function handleFormSubmit(e) {
        e.preventDefault();
        const query = queryInput.value.trim();
        if (!query) return;

        displayMessage(query, 'user');
        queryInput.value = '';
        spinner.style.display = 'block';

        // Prepare form data
        const formData = new FormData();
        formData.append('query', query);
        
        // This assumes we are analyzing the current page URL
        // In a real implementation, you might pass a specific document ID or pre-loaded content
        formData.append('url', window.location.href);

        try {
            const response = await fetch('/chat', {
                method: 'POST',
                body: formData,
                // Note: Don't set Content-Type header when using FormData;
                // the browser sets it correctly with the boundary.
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP error! Status: ${response.status}`);
            }

            const data = await response.json();
            displayMessage(data.response, 'bot', data.duration, data.response_id);
            currentResponseId = data.response_id; // Store for feedback

        } catch (error) {
            console.error('Chat error:', error);
            displayMessage(`Sorry, I encountered a problem: ${error.message}`, 'bot');
        } finally {
            spinner.style.display = 'none';
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
    }

    function displayMessage(text, sender, duration, responseId) {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message', `${sender}-message`);
        
        let messageContent = `<p>${text}</p>`;

        // Add duration and feedback if it's a bot message
        if (sender === 'bot' && responseId) {
            const timerHtml = duration ? `<div class="text-muted small mt-1" style="text-align: right; font-size: 0.75rem;"><i class="fas fa-clock"></i> ${duration}s</div>` : '';
            const feedbackHtml = `
                <div class="feedback-icons mt-2" style="text-align: right;">
                    <button class="btn btn-sm btn-outline-success feedback-btn" data-score="5" data-id="${responseId}"><i class="fas fa-thumbs-up"></i></button>
                    <button class="btn btn-sm btn-outline-danger feedback-btn" data-score="1" data-id="${responseId}"><i class="fas fa-thumbs-down"></i></button>
                </div>
            `;
            messageContent = `<div class="response-text">${text}</div>${timerHtml}${feedbackHtml}`;
        }
        
        messageDiv.innerHTML = messageContent;
        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;

        // Add event listeners for new feedback buttons
        if (sender === 'bot' && responseId) {
            messageDiv.querySelectorAll('.feedback-btn').forEach(btn => {
                btn.addEventListener('click', handleFeedbackClick);
            });
        }
    }

    async function handleFeedbackClick(e) {
        const button = e.currentTarget;
        const score = button.dataset.score;
        const responseId = button.dataset.id;
        
        // Disable buttons to prevent multiple submissions
        button.parentElement.querySelectorAll('button').forEach(btn => btn.disabled = true);

        try {
            const feedbackData = new FormData();
            feedbackData.append('score', score);
            feedbackData.append('response_id', responseId);
            feedbackData.append('comment', score === '1' ? 'Disliked' : 'Liked'); // Simple comment

            const response = await fetch('/feedback', {
                method: 'POST',
                body: feedbackData
            });

            if (response.ok) {
                // Indicate feedback was received, e.g., by changing button style
                button.parentElement.innerHTML = '<span class="text-muted small">Thanks for your feedback!</span>';
            } else {
                throw new Error('Feedback submission failed.');
            }
        } catch (error) {
            console.error('Feedback error:', error);
            button.parentElement.innerHTML = '<span class="text-danger small">Error saving feedback.</span>';
        }
    }
});