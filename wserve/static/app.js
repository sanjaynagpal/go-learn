let ws = null;

// Get WebSocket port from header


function connectWebSocket() {
    const statusElement = document.getElementById('status');
    const wsPort = document.head.querySelector('[name="websocket-port"]')?.content;

    // Connect to WebSocket server
    ws = new WebSocket(`ws://localhost:${wsPort}`);

    ws.onopen = () => {
        statusElement.textContent = 'Connected to WebSocket';
        statusElement.className = 'status connected';
    };

    ws.onclose = () => {
        statusElement.textContent = 'Disconnected from WebSocket';
        statusElement.className = 'status disconnected';

        // Attempt to reconnect after 5 seconds
        setTimeout(connectWebSocket, 5000);
    };

    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        statusElement.textContent = 'WebSocket error occurred';
        statusElement.className = 'status disconnected';
    };

    ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        addMessage(`Server: ${message.content}`);
    };
}

function addMessage(text) {
    const messagesDiv = document.getElementById('messages');
    const messageElement = document.createElement('div');
    messageElement.className = 'message';
    messageElement.textContent = text;
    messagesDiv.appendChild(messageElement);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function sendMessage() {
    const input = document.getElementById('messageInput');
    if (input.value.trim() && ws && ws.readyState === WebSocket.OPEN) {
        const message = {
            type: 'message',
            content: input.value
        };
        ws.send(JSON.stringify(message));
        addMessage(`You: ${input.value}`);
        input.value = '';
    }
}

// Handle Enter key in input
document.getElementById('messageInput').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        sendMessage();
    }
});

// Initial connection
fetch(window.location.href)
    .then(response => {
        const wsPort = response.headers.get('X-Websocket-Port');
        if (wsPort) {
            const meta = document.createElement('meta');
            meta.name = 'websocket-port';
            meta.content = wsPort;
            document.head.appendChild(meta);
            connectWebSocket();
        }
    })
    .catch(error => console.error('Failed to get WebSocket port:', error));