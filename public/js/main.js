document.addEventListener('DOMContentLoaded', () => {
    // --- GLOBAL INITIALIZATION ---
    const body = document.body;
    const currentUserId = body.dataset.userId;
    let ws; // WebSocket connection
    let toastTimeout;

    // --- UTILITY FUNCTIONS ---
    const showToast = (message, type = 'info', duration = 4000) => {
        const existingToast = document.getElementById('toast-notification');
        if (existingToast) existingToast.remove();
        clearTimeout(toastTimeout);

        const toast = document.createElement('div');
        toast.id = 'toast-notification';
        toast.className = `toast ${type}`;
        toast.textContent = message;
        body.appendChild(toast);

        setTimeout(() => toast.classList.add('show'), 10);
        toastTimeout = setTimeout(() => {
            toast.classList.remove('show');
            toast.addEventListener('transitionend', () => toast.remove());
        }, duration);
    };

    const debounce = (func, delay) => {
        let timeout;
        return (...args) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), delay);
        };
    };

    const escapeHtml = (unsafe) => {
        if (typeof unsafe !== 'string') return '';
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    };

    // --- THEME MANAGEMENT ---
    const themeToggler = document.getElementById('theme-toggler');
    const applyTheme = (theme) => {
        body.classList.toggle('dark-mode', theme === 'dark');
        if (themeToggler) {
            themeToggler.innerHTML = theme === 'dark' ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
        }
    };
    if (themeToggler) {
        themeToggler.addEventListener('click', () => {
            const newTheme = body.classList.contains('dark-mode') ? 'light' : 'dark';
            localStorage.setItem('cipherChatTheme', newTheme);
            applyTheme(newTheme);
        });
    }
    applyTheme(localStorage.getItem('cipherChatTheme') || 'light');

    // --- WEBSOCKET MANAGEMENT ---
    const connectWebSocket = (onMessageHandler) => {
        if (!currentUserId || (ws && ws.readyState === WebSocket.OPEN)) return;
        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
        ws = new WebSocket(`${protocol}://${window.location.host}`);

        ws.onopen = () => console.log('WebSocket connection established.');
        ws.onmessage = onMessageHandler;
        ws.onclose = () => {
            console.log('WebSocket connection closed. Attempting to reconnect in 5 seconds...');
            ws = null;
            setTimeout(() => connectWebSocket(onMessageHandler), 5000);
        };
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            ws.close();
        };
    };

    const sendWebSocketMessage = (payload) => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(payload));
        }
    };

    // --- LOGOUT ---
    const logoutButton = document.getElementById('logout-button');
    if (logoutButton) {
        logoutButton.addEventListener('click', () => {
            cryptoHelpers.deleteKeyPair();
            if (ws) ws.close();
            window.location.href = '/logout';
        });
    }

    // --- PAGE-SPECIFIC LOGIC ---

    // ===================================
    // LOGIN PAGE
    // ===================================
    if (body.id === 'login-page') {
        const emailForm = document.getElementById('email-form');
        const otpForm = document.getElementById('otp-form');
        const emailInput = document.getElementById('email');
        const otpInput = document.getElementById('otp');
        const emailStep = document.getElementById('email-step');
        const otpStep = document.getElementById('otp-step');
        const otpMessage = document.getElementById('otp-message');
        const backToEmail = document.getElementById('back-to-email');
        const attemptCounter = document.getElementById('attempt-counter');

        let otpAttemptCount = 0;
        const MAX_OTP_ATTEMPTS = 3;
        let generatedKeyPair = null;

        const prepareCryptoKeys = () => {
            cryptoHelpers.generateKeyPair().then(keys => {
                generatedKeyPair = keys;
            }).catch(err => showToast(err.message, 'error'));
        };
        prepareCryptoKeys();

        const resetToEmailStep = () => {
            if (otpStep) otpStep.classList.add('hidden');
            if (emailStep) emailStep.classList.remove('hidden');
            otpAttemptCount = 0;
            if (otpInput) otpInput.value = '';
            prepareCryptoKeys();
        };

        if (emailForm) {
            emailForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const email = emailInput.value;
                if (!email) {
                    showToast('Please enter a valid email address.', 'error');
                    return;
                }
                const button = emailForm.querySelector('button');
                button.disabled = true;
                button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';

                try {
                    const response = await fetch('/api/send-otp', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email }),
                    });
                    const data = await response.json();
                    if (!response.ok) throw new Error(data.error || 'An unknown error occurred.');

                    showToast(data.message, 'success');
                    if (emailStep) emailStep.classList.add('hidden');
                    if (otpStep) otpStep.classList.remove('hidden');
                    if (otpMessage) otpMessage.textContent = `Enter the OTP sent to ${email}`;
                    if (attemptCounter) attemptCounter.textContent = `You have ${MAX_OTP_ATTEMPTS} attempts.`;
                    if (otpInput) otpInput.focus();
                } catch (err) {
                    showToast(err.message, 'error');
                } finally {
                    button.disabled = false;
                    button.textContent = 'Send OTP';
                }
            });
        }

        if (otpForm) {
            otpForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                if (!generatedKeyPair) {
                    showToast('Cryptographic keys not ready. Please wait.', 'error');
                    return;
                }

                otpAttemptCount++;
                const button = otpForm.querySelector('button');
                button.disabled = true;
                button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verifying...';

                try {
                    const publicKey = await cryptoHelpers.exportKey(generatedKeyPair.publicKey);
                    const response = await fetch('/api/verify-otp', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email: emailInput.value, otp: otpInput.value, publicKey }),
                    });
                    const data = await response.json();
                    if (!response.ok) throw new Error(data.error || 'Verification failed.');

                    await cryptoHelpers.saveKeyPair(generatedKeyPair);
                    showToast('Login successful!', 'success');
                    window.location.href = '/chats';
                } catch (err) {
                    const attemptsLeft = MAX_OTP_ATTEMPTS - otpAttemptCount;
                    if (attemptsLeft > 0) {
                        showToast(`${err.message}. You have ${attemptsLeft} ${attemptsLeft > 1 ? 'attempts' : 'attempt'} left.`, 'error');
                        if (attemptCounter) attemptCounter.textContent = `You have ${attemptsLeft} ${attemptsLeft > 1 ? 'attempts' : 'attempt'} left.`;
                    } else {
                        showToast('Maximum attempts reached. Please request a new OTP.', 'error');
                        resetToEmailStep();
                    }
                } finally {
                    button.disabled = false;
                    button.textContent = 'Verify & Login';
                }
            });
        }

        if (backToEmail) backToEmail.addEventListener('click', resetToEmailStep);
    }

    // ===================================
    // CHATS PAGE
    // ===================================
    if (body.id === 'chats-page') {
        const chatsPageMessageHandler = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'new-message') {
                showToast(`New message received!`, 'info');
                if (window.fetchConversations) {
                    window.fetchConversations();
                }
            }
        };
        connectWebSocket(chatsPageMessageHandler);

        const conversationsList = document.getElementById('conversations-list');
        const searchInput = document.getElementById('search-input');
        const searchResults = document.getElementById('search-results');
        const noConversations = document.getElementById('no-conversations');

        const renderConversations = (conversations) => {
            if (!conversationsList) return;
            conversationsList.innerHTML = '';
            if (!conversations || conversations.length === 0) {
                if (noConversations) noConversations.style.display = 'flex';
                return;
            }
            if (noConversations) noConversations.style.display = 'none';

            conversations.sort((a, b) => new Date(b.last_message_time) - new Date(a.last_message_time));

            conversations.forEach(convo => {
                const convoElement = document.createElement('a');
                convoElement.href = `/conversation/${convo.peer_id}`;
                convoElement.className = 'conversation-item';
                const lastMessageText = convo.last_message ? (convo.last_message.startsWith('{') ? '<i class="fas fa-file-image"></i> File Message' : '<i class="fas fa-lock fa-xs"></i> Encrypted Message') : 'No messages yet';
                convoElement.innerHTML = `
                    <div class="avatar">${convo.peer_username.charAt(0)}</div>
                    <div class="conversation-details">
                        <div class="conversation-header">
                            <span class="username">${convo.peer_username}</span>
                            <span class="timestamp">${new Date(convo.last_message_time).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
                        </div>
                        <p class="last-message">${lastMessageText}</p>
                    </div>
                `;
                conversationsList.appendChild(convoElement);
            });
        };

        const fetchConversations = async () => {
            try {
                const response = await fetch('/api/conversations', { credentials: 'include' });
                if (!response.ok) {
                    const errData = await response.json().catch(() => ({error: 'Could not fetch conversations.'}));
                    throw new Error(errData.error);
                }
                const conversations = await response.json();
                renderConversations(conversations);
            } catch (err) {
                showToast(err.message, 'error');
                if (conversationsList) conversationsList.innerHTML = `<div class="loading-placeholder error"><i class="fas fa-exclamation-triangle"></i><p>${err.message}</p></div>`;
            }
        };
        window.fetchConversations = fetchConversations;

        if (searchInput) {
            searchInput.addEventListener('input', debounce(async (e) => {
                const searchTerm = e.target.value.trim();
                if (searchTerm.length > 0) {
                    if (conversationsList) conversationsList.classList.add('hidden');
                    try {
                        const response = await fetch(`/api/users/search?searchTerm=${searchTerm}`, { credentials: 'include' });
                        const users = await response.json();
                        renderSearchResults(users);
                    } catch (err) {
                        showToast('Failed to search users.', 'error');
                    }
                } else {
                    if (searchResults) searchResults.classList.add('hidden');
                    if (conversationsList) conversationsList.classList.remove('hidden');
                }
            }, 300));
        }

        const renderSearchResults = (users) => {
            if (!searchResults) return;
            searchResults.innerHTML = '';
            searchResults.classList.toggle('hidden', users.length === 0);
            users.forEach(user => {
                const userElement = document.createElement('a');
                userElement.href = `/conversation/${user.id}`;
                userElement.className = 'search-result-item';
                userElement.innerHTML = `<div class="avatar">${user.username.charAt(0)}</div><span>${user.username}</span>`;
                searchResults.appendChild(userElement);
            });
        };

        // Subscribe to real-time message updates via backend API
        const subscribeToMessages = async () => {
            try {
                const response = await fetch('/api/subscribe/messages', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ userId: currentUserId })
                });
                const data = await response.json();
                if (!response.ok) throw new Error(data.error || 'Failed to subscribe to messages.');
                // Backend will push updates via WebSocket
            } catch (err) {
                showToast('Failed to subscribe to message updates.', 'error');
            }
        };

        subscribeToMessages();
        fetchConversations();
    }

    // ===================================
    // CONVERSATION PAGE
    // ===================================
    if (body.id === 'conversation-page') {
        const messagesContainer = document.getElementById('messages-container');
        const messageForm = document.getElementById('message-form');
        const messageInput = document.getElementById('message-input');
        const sendButton = document.getElementById('send-button');
        const attachmentButton = document.getElementById('attachment-button');
        const fileInput = document.getElementById('file-input');
        const fileAttachmentPreview = document.getElementById('file-attachment-preview');
        const filePreviewContent = document.getElementById('file-preview-content');
        const cancelAttachmentBtn = document.getElementById('cancel-attachment-btn');

        const peerId = body.dataset.peerId;
        const peerStatus = document.getElementById('peer-status');
        const peerUsername = document.querySelector('.peer-details h2')?.textContent || 'user';

        let userKeys = null;
        let peerPublicKey = null;
        let isTyping = false;
        let selectedFile = null;
        let isInitialized = false;
        const pendingEvents = [];
        let isLoadingMore = false;
        let hasMoreMessages = true;
        let oldestMessageTimestamp = null;

        const getDateString = (timestamp) => {
            return new Date(timestamp).toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
        };

        const addDateSeparator = (timestamp, fragment) => {
            const dateStr = getDateString(timestamp);
            const existingSeparator = fragment.querySelector(`.date-separator[data-date="${dateStr}"]`) || 
                                     messagesContainer.querySelector(`.date-separator[data-date="${dateStr}"]`);
            if (!existingSeparator) {
                const separator = document.createElement('div');
                separator.className = 'date-separator';
                separator.dataset.date = dateStr;
                separator.innerHTML = `<span>${dateStr}</span>`;
                fragment.appendChild(separator);
            }
        };

        const createMessageElement = (msg, decryptedText) => {
            const isSent = msg.sender_id === currentUserId;
            const statusClass = msg.status === 'seen' ? 'seen' : 'delivered';
            const statusIcon = isSent ? `<span class="message-status ${statusClass}"><i class="fas fa-check${msg.status === 'seen' ? '-double' : ''}"></i></span>` : '';
            const editedTag = msg.is_edited ? '<span class="edited-tag">(edited)</span>' : '';

            let messageContent;
            if (msg.file_meta) {
                const encryptedFileKey = isSent ? msg.encrypted_message_for_sender : msg.encrypted_file_key;
                messageContent = `
                    <div class="file-message">
                        <i class="fas fa-file-alt"></i>
                        <div class="file-details">
                            <span class="file-name">${escapeHtml(msg.file_meta.name)}</span>
                            <span class="file-size">${(msg.file_meta.size / 1024).toFixed(2)} KB</span>
                        </div>
                        <button class="download-btn icon-btn" data-path="${msg.file_meta.path}" data-key="${encryptedFileKey}" data-filename="${escapeHtml(msg.file_meta.name)}"><i class="fas fa-download"></i></button>
                    </div>
                `;
            } else {
                const textToShow = decryptedText ? escapeHtml(decryptedText) : '<i class="fas fa-lock"></i> Message Cannot Be Seen';
                messageContent = `<p>${textToShow}</p>`;
            }

            const messageElement = document.createElement('div');
            messageElement.className = `message-wrapper ${isSent ? 'sent' : 'received'}`;
            messageElement.dataset.messageId = msg.id;
            messageElement.dataset.timestamp = msg.created_at;

            messageElement.innerHTML = `
                <div class="message-bubble">
                    ${messageContent}
                    <div class="message-meta">
                        ${editedTag}
                        <span class="timestamp">${new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                        ${statusIcon}
                    </div>
                </div>
            `;

            return messageElement;
        };

        const renderAndDecryptMessage = async (msg, prepend = false) => {
            if (!userKeys) return null;

            let decryptedText = null;
            if (msg.encrypted_message_for_sender || msg.encrypted_message_for_receiver) {
                const encryptedBlob = msg.sender_id === currentUserId ? msg.encrypted_message_for_sender : msg.encrypted_message_for_receiver;
                if (encryptedBlob && !msg.file_meta) {
                    try {
                        decryptedText = await cryptoHelpers.decryptMessage(encryptedBlob, userKeys.privateKey);
                    } catch (err) {
                        console.error('Decryption failed for message:', msg.id, err);
                    }
                }
            }

            const messageElement = createMessageElement(msg, decryptedText);
            if (!messageElement) return;

            const fragment = document.createDocumentFragment();
            if (!prepend) {
                addDateSeparator(msg.created_at, fragment);
                fragment.appendChild(messageElement);
                messagesContainer.appendChild(fragment);
                scrollToBottom();
            } else {
                addDateSeparator(msg.created_at, fragment);
                fragment.appendChild(messageElement);
                return fragment;
            }
        };

        const updateRenderedMessage = async (msg) => {
            const messageElement = document.querySelector(`[data-message-id="${msg.id}"]`);
            if (!messageElement) return;

            let decryptedText = null;
            if (msg.encrypted_message_for_sender || msg.encrypted_message_for_receiver) {
                const encryptedBlob = msg.sender_id === currentUserId ? msg.encrypted_message_for_sender : msg.encrypted_message_for_receiver;
                if (encryptedBlob) {
                    try {
                        decryptedText = await cryptoHelpers.decryptMessage(encryptedBlob, userKeys.privateKey);
                    } catch (err) {
                        console.error('Decryption failed for updated message:', msg.id, err);
                    }
                }
            }

            const pTag = messageElement.querySelector('.message-bubble p');
            if (pTag) pTag.textContent = decryptedText || '<i class="fas fa-lock"></i> Message Cannot Be Seen';

            const metaTag = messageElement.querySelector('.message-meta');
            if (metaTag && !metaTag.querySelector('.edited-tag')) {
                metaTag.insertAdjacentHTML('afterbegin', '<span class="edited-tag">(edited)</span>');
            }
        };

        const processMessageQueue = async () => {
            while (pendingEvents.length > 0) {
                const data = pendingEvents.shift();
                await conversationPageMessageHandler({ data: JSON.stringify(data) }, true);
            }
        };

        const conversationPageMessageHandler = async (event, isProcessingQueue = false) => {
            const data = JSON.parse(event.data);

            if (!isInitialized && !isProcessingQueue) {
                if (['new-message', 'seen-update', 'message-deleted', 'message-updated'].includes(data.type)) {
                    pendingEvents.push(data);
                }
                return;
            }

            const typingIndicator = document.getElementById('typing-indicator');
            switch (data.type) {
                case 'typing-status':
                    if (data.from === peerId && typingIndicator && peerStatus) {
                        typingIndicator.style.display = data.status === 'typing' ? 'flex' : 'none';
                        peerStatus.style.display = data.status === 'typing' ? 'none' : 'block';
                    }
                    break;
                case 'seen-update':
                    if (data.from === peerId) {
                        document.querySelectorAll('.message-wrapper.sent .message-status:not(.seen)').forEach(el => {
                            el.classList.remove('delivered');
                            el.classList.add('seen');
                            el.innerHTML = '<i class="fas fa-check-double"></i>';
                        });
                    }
                    break;
                case 'new-message':
                    if (data.message.sender_id === peerId) {
                        await renderAndDecryptMessage(data.message);
                        await fetch('/api/messages/mark-as-seen', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            credentials: 'include',
                            body: JSON.stringify({ senderId: peerId })
                        });
                    }
                    break;
                case 'message-updated':
                    if (data.message.sender_id === peerId || data.message.receiver_id === peerId) {
                        await updateRenderedMessage(data.message);
                    }
                    break;
                case 'message-deleted':
                    const messageElement = document.querySelector(`[data-message-id="${data.messageId}"]`);
                    if (messageElement) {
                        messageElement.querySelector('.message-bubble p').innerHTML = '<i class="fas fa-ban"></i> This message was deleted';
                        messageElement.querySelector('.message-bubble').classList.add('deleted');
                    }
                    break;
                default:
                    break;
            }
        };

        connectWebSocket(conversationPageMessageHandler);

        const scrollToBottom = () => {
            if (messagesContainer) messagesContainer.scrollTop = messagesContainer.scrollHeight;
        };

        const handleFormSubmit = async (e) => {
            e.preventDefault();
            const messageText = messageInput.value.trim();

            if (!messageText && !selectedFile) return;
            if (!userKeys || !peerPublicKey) {
                showToast('Session not ready. Please wait.', 'error');
                return;
            }

            sendButton.disabled = true;
            sendButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';

            try {
                let messageData = {};
                let optimisticRenderText = messageText;

                if (selectedFile) {
                    const file = selectedFile;
                    const fileKey = await cryptoHelpers.generateFileKey();
                    const fileBuffer = await file.arrayBuffer();
                    const { iv, encryptedFile } = await cryptoHelpers.encryptFile(fileBuffer, fileKey);

                    const exportedFileKey = await crypto.subtle.exportKey('jwk', fileKey);
                    const encryptedFileKeyForReceiver = await cryptoHelpers.encryptMessage(JSON.stringify(exportedFileKey), peerPublicKey);
                    const encryptedFileKeyForSender = await cryptoHelpers.encryptMessage(JSON.stringify(exportedFileKey), userKeys.publicKey);

                    const signedUrlResponse = await fetch('/api/upload/signed-url', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify({ fileName: file.name, fileType: file.type, fileSize: file.size })
                    });
                    if (!signedUrlResponse.ok) throw new Error('Could not get upload URL.');
                    const { signedUrl, path } = await signedUrlResponse.json();

                    await fetch(signedUrl, {
                        method: 'PUT',
                        headers: { 'Content-Type': file.type },
                        body: new Blob([iv, new Uint8Array(encryptedFile)])
                    });

                    messageData = {
                        file_meta: { name: file.name, type: file.type, size: file.size, path },
                        encrypted_file_key: encryptedFileKeyForReceiver,
                        encrypted_message_for_sender: encryptedFileKeyForSender,
                    };

                    optimisticRenderText = messageText;
                }

                if (messageText && !selectedFile) {
                    messageData.encrypted_message_for_receiver = await cryptoHelpers.encryptMessage(messageText, peerPublicKey);
                    messageData.encrypted_message_for_sender = await cryptoHelpers.encryptMessage(messageText, userKeys.publicKey);
                }

                const response = await fetch('/api/message', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ receiver_id: peerId, messageData })
                });
                const newMessage = await response.json();
                if (!response.ok) throw new Error(newMessage.error);

                await renderAndDecryptMessage(newMessage);
                scrollToBottom();

            } catch (err) {
                showToast(err.message, 'error');
            } finally {
                messageInput.value = '';
                if (cancelAttachmentBtn) cancelAttachmentBtn.click();
                sendButton.disabled = false;
                sendButton.innerHTML = '<i class="fas fa-paper-plane"></i>';
                sendWebSocketMessage({ type: 'stop-typing', recipientIds: [peerId], chatId: peerId });
                isTyping = false;
            }
        };

        if (messageForm) messageForm.addEventListener('submit', handleFormSubmit);

        if (attachmentButton) {
            attachmentButton.addEventListener('click', () => fileInput.click());
        }

        if (fileInput) {
            fileInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (!file) return;

                if (file.size > (10 * 1024 * 1024)) { // 10MB limit
                    showToast('File is too large (max 10MB).', 'error');
                    fileInput.value = '';
                    return;
                }

                selectedFile = file;

                filePreviewContent.innerHTML = '';
                if (file.type.startsWith('image/')) {
                    const reader = new FileReader();
                    reader.onload = (event) => {
                        const img = document.createElement('img');
                        img.src = event.target.result;
                        img.alt = file.name;
                        filePreviewContent.appendChild(img);
                    };
                    reader.readAsDataURL(file);
                } else {
                    filePreviewContent.innerHTML = `<div class="file-icon"><i class="fas fa-file-alt"></i><span>${escapeHtml(file.name)}</span></div>`;
                }
                fileAttachmentPreview.classList.remove('hidden');
                sendButton.innerHTML = '<i class="fas fa-file-export"></i>';
                sendButton.classList.add('has-file');
            });
        }

        if (cancelAttachmentBtn) {
            cancelAttachmentBtn.addEventListener('click', () => {
                fileAttachmentPreview.classList.add('hidden');
                selectedFile = null;
                fileInput.value = '';
                sendButton.innerHTML = '<i class="fas fa-paper-plane"></i>';
                sendButton.classList.remove('has-file');
            });
        }

        if (messagesContainer) {
            messagesContainer.addEventListener('click', async (e) => {
                const downloadBtn = e.target.closest('.download-btn');
                if (!downloadBtn) return;

                downloadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
                downloadBtn.disabled = true;

                const path = downloadBtn.dataset.path;
                const encryptedFileKey = downloadBtn.dataset.key;
                const fileName = downloadBtn.dataset.filename;

                try {
                    if (!userKeys || !path || !encryptedFileKey) {
                        throw new Error("Missing data for download.");
                    }

                    const decryptedFileKeyStr = await cryptoHelpers.decryptMessage(encryptedFileKey, userKeys.privateKey);
                    if (!decryptedFileKeyStr) throw new Error("Cannot see message.");
                    const fileKeyJwk = JSON.parse(decryptedFileKeyStr);
                    const fileKey = await window.crypto.subtle.importKey('jwk', fileKeyJwk, { name: 'AES-GCM' }, true, ['decrypt']);

                    const response = await fetch('/api/storage/get-url', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify({ path })
                    });
                    if (!response.ok) throw new Error('Could not get file URL.');
                    const { publicUrl } = await response.json();

                    const fileResponse = await fetch(publicUrl);
                    if (!fileResponse.ok) throw new Error("File download failed.");
                    const encryptedBuffer = await fileResponse.arrayBuffer();

                    const decryptedBuffer = await cryptoHelpers.decryptFile(encryptedBuffer, fileKey);

                    const blob = new Blob([decryptedBuffer], { type: downloadBtn.closest('.file-message').querySelector('.file-details span:nth-child(2)').textContent.split(' ')[1] });
                    const objectUrl = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = objectUrl;
                    a.download = fileName;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(objectUrl);

                } catch (err) {
                    showToast(err.message, 'error');
                } finally {
                    downloadBtn.innerHTML = '<i class="fas fa-download"></i>';
                    downloadBtn.disabled = false;
                }
            });
        }

        const loadMoreMessages = async () => {
            if (isLoadingMore || !hasMoreMessages) return;
            isLoadingMore = true;

            const spinner = document.createElement('div');
            spinner.className = 'loading-spinner-top';
            spinner.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
            messagesContainer.prepend(spinner);

            const firstMessageEl = messagesContainer.querySelector('.message-wrapper[data-message-id]');
            oldestMessageTimestamp = firstMessageEl ? firstMessageEl.dataset.timestamp : new Date().toISOString();

            try {
                console.log('Fetching messages before:', oldestMessageTimestamp);
                const response = await fetch(`/api/messages/${peerId}?before=${encodeURIComponent(oldestMessageTimestamp)}`, { credentials: 'include' });
                if (!response.ok) {
                    const errData = await response.json().catch(() => ({ error: 'Failed to fetch older messages.' }));
                    throw new Error(errData.error);
                }
                const olderMessages = await response.json();

                spinner.remove();

                if (olderMessages.length > 0) {
                    const oldScrollHeight = messagesContainer.scrollHeight;
                    const fragment = document.createDocumentFragment();
                    olderMessages.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
                    let lastDate = null;
                    const messageElements = await Promise.all(
                        olderMessages.map(async (msg) => {
                            const existingMessage = messagesContainer.querySelector(`[data-message-id="${msg.id}"]`);
                            if (!existingMessage) {
                                const messageDate = getDateString(msg.created_at);
                                const tempFragment = document.createDocumentFragment();
                                if (messageDate !== lastDate) {
                                    addDateSeparator(msg.created_at, tempFragment);
                                    lastDate = messageDate;
                                }
                                const messageElement = await renderAndDecryptMessage(msg, true);
                                if (messageElement) tempFragment.appendChild(messageElement);
                                return tempFragment;
                            }
                            return null;
                        })
                    );

                    messageElements.reverse().forEach(fragment => {
                        if (fragment) messagesContainer.prepend(fragment);
                    });

                    const newFirstMessageEl = messagesContainer.querySelector('.message-wrapper[data-message-id]');
                    if (newFirstMessageEl) {
                        oldestMessageTimestamp = newFirstMessageEl.dataset.timestamp;
                    }
                    messagesContainer.scrollTop = messagesContainer.scrollHeight - oldScrollHeight;
                } else {
                    hasMoreMessages = false;
                    showToast('No more messages to load.', 'info');
                }
            } catch (err) {
                showToast(err.message, 'error');
                spinner.remove();
            } finally {
                isLoadingMore = false;
            }
        };

        if (messagesContainer) {
            messagesContainer.addEventListener('scroll', debounce(async () => {
                if (messagesContainer.scrollTop <= 50 && !isLoadingMore && hasMoreMessages) {
                    await loadMoreMessages();
                }
            }, 200));
        }

        const initializeConversation = async () => {
            try {
                userKeys = await cryptoHelpers.loadKeyPair();
                if (!userKeys) throw new Error('Could not load your local encryption keys. Please try logging in again.');

                const [peerResponse, messagesResponse] = await Promise.all([
                    fetch(`/api/user/${peerId}`, { credentials: 'include' }),
                    fetch(`/api/messages/${peerId}`, { credentials: 'include' })
                ]);

                if (!peerResponse.ok) {
                    const errData = await peerResponse.json().catch(() => ({ error: 'Could not fetch peer user data.' }));
                    throw new Error(errData.error);
                }
                const peerData = await peerResponse.json();
                peerPublicKey = await cryptoHelpers.importPublicKey(peerData.public_key);

                if (peerStatus) {
                    const lastSeenDate = new Date(peerData.last_seen);
                    const now = new Date();
                    const diffMinutes = (now - lastSeenDate) / (1000 * 60);
                    if (peerData.isOnline) {
                        peerStatus.textContent = 'Online';
                    } else if (diffMinutes < 60) {
                        peerStatus.textContent = `Last seen ${Math.round(diffMinutes)} mins ago`;
                    } else {
                        peerStatus.textContent = `Last seen ${lastSeenDate.toLocaleDateString()}`;
                    }
                }

                if (!messagesResponse.ok) {
                    const errData = await messagesResponse.json().catch(() => ({ error: 'Could not fetch message history.' }));
                    throw new Error(errData.error);
                }
                const messages = await messagesResponse.json();

                if (messagesContainer) {
                    messagesContainer.innerHTML = '';
                    if (messages.length === 0) {
                        messagesContainer.innerHTML = `<div class="no-messages-placeholder"><i class="fas fa-hand-sparkles"></i><p>Start chatting with ${escapeHtml(peerUsername)}</p></div>`;
                        hasMoreMessages = false;
                    } else {
                        messages.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
                        const fragment = document.createDocumentFragment();
                        let lastDate = null;
                        for (const msg of messages) {
                            const messageDate = getDateString(msg.created_at);
                            if (messageDate !== lastDate) {
                                addDateSeparator(msg.created_at, fragment);
                                lastDate = messageDate;
                            }
                            const messageElement = await createMessageElement(msg, await cryptoHelpers.decryptMessage(
                                msg.sender_id === currentUserId ? msg.encrypted_message_for_sender : msg.encrypted_message_for_receiver,
                                userKeys.privateKey
                            ).catch(() => null));
                            if (messageElement) fragment.appendChild(messageElement);
                        }
                        messagesContainer.appendChild(fragment);
                        scrollToBottom();
                        if (messages.length < 50) {
                            hasMoreMessages = false;
                        }
                    }
                }

                isInitialized = true;
                await processMessageQueue();

                await fetch('/api/messages/mark-as-seen', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ senderId: peerId })
                });

            } catch (err) {
                showToast(err.message, 'error', 10000);
                if (messagesContainer) messagesContainer.innerHTML = `<div class="loading-placeholder error"><i class="fas fa-exclamation-triangle"></i><p>Could not load secure session.</p><p class="error-detail">${err.message}</p><a href="/chats" class="btn-secondary">Go Back</a></div>`;
            }
        };

        initializeConversation();
    }
});