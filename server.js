
// --- 1. INITIALIZATION AND DEPENDENCIES ---
require('dotenv').config();

const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const { WebSocketServer } = require('ws');
const { createClient } = require('@supabase/supabase-js');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const nodemailer = require('nodemailer');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const crypto = require('crypto');

// --- 2. CONFIGURATION ---
const {
    SUPABASE_URL,
    SUPABASE_ANON_KEY,
    SUPABASE_SERVICE_KEY,
    SESSION_SECRET,
    PORT = 3000,
    EMAIL_HOST,
    EMAIL_PORT,
    EMAIL_USER,
    EMAIL_PASS,
    EMAIL_FROM,
    NODE_ENV
} = process.env;

if (!SUPABASE_SERVICE_KEY) {
    console.error("FATAL ERROR: SUPABASE_SERVICE_KEY is not defined in the .env file.");
    process.exit(1);
}

const OTP_EXPIRATION_MINUTES = 10;
const DAILY_OTP_LIMIT = 20;
const MAX_GROUP_MEMBERS = 100;
const WEBSOCKET_HEARTBEAT_INTERVAL = 30000;
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MESSAGE_PAGE_LIMIT = 50; // Number of messages to fetch per page

// --- 3. SERVICE INITIALIZATION ---
const app = express();
let server;

try {
    const httpsOptions = {
        key: fs.readFileSync(path.join(__dirname, 'key.pem')),
        cert: fs.readFileSync(path.join(__dirname, 'cert.pem'))
    };
    server = https.createServer(httpsOptions, app);
} catch (e) {
    console.warn("SSL certs not found, starting in HTTP mode. Web Crypto may not work on mobile devices on your network.");
    server = http.createServer(app);
}

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
const transporter = nodemailer.createTransport({
    host: EMAIL_HOST,
    port: EMAIL_PORT,
    secure: EMAIL_PORT == 465,
    auth: { user: EMAIL_USER, pass: EMAIL_PASS },
});
const apiRateLimiter = new RateLimiterMemory({ points: 20, duration: 1 });
const wss = new WebSocketServer({ server });
const clients = new Map();

// Map to track active subscriptions per user
const userSubscriptions = new Map();

// --- 4. MIDDLEWARE ---
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());

const rateLimiterMiddleware = (req, res, next) => {
    apiRateLimiter.consume(req.ip)
        .then(() => next())
        .catch(() => res.status(429).json({ error: 'Too Many Requests' }));
};
app.use('/api/', rateLimiterMiddleware);

const requireAuth = async (req, res, next) => {
    const token = req.cookies.jwt;
    if (!token) {
        if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Authentication required' });
        return res.redirect('/login');
    }
    try {
        const decodedToken = jwt.verify(token, SESSION_SECRET);
        
        const { data: userRecord, error: userError } = await supabaseAdmin
            .from('users')
            .select('session_id')
            .eq('id', decodedToken.sub)
            .single();

        if (userError || !userRecord || userRecord.session_id !== decodedToken.sid) {
            if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Session expired. Please log in again.' });
            res.cookie('jwt', '', { maxAge: 1 });
            return res.redirect('/login');
        }

        req.user = {
            id: decodedToken.sub,
            username: decodedToken.app_metadata?.username,
            email: decodedToken.email
        };
        next();
    } catch (err) {
        if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Invalid or expired token' });
        res.cookie('jwt', '', { maxAge: 1 });
        return res.redirect('/login');
    }
};

const checkUser = (req, res, next) => {
    const token = req.cookies.jwt;
    if (token) {
        res.locals.user = jwt.verify(token, SESSION_SECRET, (err, decoded) => {
            if (err || !decoded) return null;
            return {
                id: decoded.sub,
                username: decoded.app_metadata?.username,
                email: decoded.email
            };
        });
    } else {
        res.locals.user = null;
    }
    next();
};

// --- 5. HELPER & SERVICE FUNCTIONS ---
const generateUniqueUsername = async () => {
    let username, isUnique = false;
    while (!isUnique) {
        username = Array.from({ length: 9 }, () => 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)]).join('');
        const { data } = await supabaseAdmin.from('users').select('id').eq('username', username).single();
        if (!data) isUnique = true;
    }
    return username;
};

const createToken = (user, sessionId) => {
    const payload = {
        sub: user.id,
        role: 'authenticated',
        email: user.email,
        sid: sessionId,
        app_metadata: {
            username: user.username,
        }
    };
    return jwt.sign(payload, SESSION_SECRET, {});
};

const sendOtpEmail = async (email, otp) => {
    const mailOptions = {
        from: `"CipherChat" <${EMAIL_FROM}>`,
        to: email,
        subject: 'Your CipherChat Login OTP',
        html: `<div style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; max-width: 600px; margin: auto; border: 1px solid #ddd; padding: 20px;"><h2 style="color: #0088ff; text-align: center;">Your CipherChat One-Time Password</h2><p>Hello,</p><p>Please use the following One-Time Password (OTP) to log in. This code is valid for <strong>${OTP_EXPIRATION_MINUTES} minutes</strong>.</p><p style="font-size: 28px; font-weight: bold; letter-spacing: 4px; color: #0056b3; background-color: #f0f2f5; padding: 15px 20px; border-radius: 8px; text-align: center; margin: 20px 0;">${otp}</p><p>If you did not request this code, please ignore this email.</p><p>Thank you,<br/>The CipherChat Team</p><hr style="border: none; border-top: 1px solid #eee;" /><p style="font-size: 12px; color: #888; text-align: center;">This is an automated message. Please do not reply.</p></div>`,
    };
    await transporter.sendMail(mailOptions);
};

const sendToUser = (userId, payload) => {
    const client = clients.get(userId);
    if (client && client.readyState === client.OPEN) {
        client.send(JSON.stringify(payload));
    }
};

const broadcastToUsers = (userIds, payload) => {
    userIds.forEach(userId => sendToUser(userId, payload));
};

const createSupabaseClientForUser = (token) => {
    return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        global: { headers: { Authorization: `Bearer ${token}` } }
    });
};

const getGroupMemberIds = async (groupId) => {
    const { data, error } = await supabaseAdmin.from('group_members').select('user_id').eq('group_id', groupId);
    if (error) throw error;
    return data.map(member => member.user_id);
};

const isGroupAdmin = async (groupId, userId) => {
    const { data, error } = await supabaseAdmin
        .from('group_members')
        .select('role')
        .eq('group_id', groupId)
        .eq('user_id', userId)
        .single();
    if (error) throw error;
    return data.role === 'admin';
};

// --- 6. WEBSOCKET SERVER LOGIC ---
wss.on('connection', async (ws, req) => {
    const token = req.headers.cookie?.split('; ').find(c => c.startsWith('jwt='))?.split('=')[1];
    let userId, sessionId;
    try {
        const decodedToken = jwt.verify(token, SESSION_SECRET);
        userId = decodedToken.sub;
        sessionId = decodedToken.sid;

        const { data: userRecord, error: userError } = await supabaseAdmin.from('users').select('session_id').eq('id', userId).single();
        if (userError || !userRecord || userRecord.session_id !== sessionId) {
            return ws.close(4001, 'Session Expired');
        }

        ws.userId = userId;
        clients.set(userId, ws);
        console.log(`WebSocket Client connected: ${userId}`);
    } catch (err) {
        return ws.close(1008, 'Invalid token');
    }

    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            switch (data.type) {
                case 'typing':
                    broadcastToUsers(data.recipientIds, { type: 'typing-status', from: userId, status: 'typing', chatId: data.chatId });
                    break;
                case 'stop-typing':
                    broadcastToUsers(data.recipientIds, { type: 'typing-status', from: userId, status: 'idle', chatId: data.chatId });
                    break;
            }
        } catch (e) {
            console.error('Failed to process WebSocket message:', e);
        }
    });

    ws.on('close', async () => {
        clients.delete(userId);
        // Clean up subscriptions
        if (userSubscriptions.has(userId)) {
            const subscription = userSubscriptions.get(userId);
            subscription.unsubscribe();
            userSubscriptions.delete(userId);
            console.log(`Unsubscribed from messages for user: ${userId}`);
        }
        console.log(`WebSocket Client disconnected: ${userId}`);
        await supabaseAdmin.from('users').update({ last_seen: new Date().toISOString() }).eq('id', userId);
    });
});

const interval = setInterval(() => {
    wss.clients.forEach(ws => {
        if (ws.isAlive === false) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
    });
}, WEBSOCKET_HEARTBEAT_INTERVAL);

wss.on('close', () => clearInterval(interval));

// --- 7. PAGE ROUTING ---
app.use(checkUser);
app.get('/', (req, res) => res.redirect(res.locals.user ? '/chats' : '/login'));
app.get('/login', (req, res) => res.locals.user ? res.redirect('/chats') : res.render('login'));
app.get('/chats', requireAuth, (req, res) => res.render('chats', { user: req.user }));
app.get('/conversation/:userId', requireAuth, async (req, res) => {
    const userSupabase = createSupabaseClientForUser(req.cookies.jwt);
    const { data } = await userSupabase.from('users').select('id, username').eq('id', req.params.userId).single();
    if (!data) return res.redirect('/chats?error=UserNotFound');
    res.render('conversation', { user: req.user, peerUser: data });
});
app.get('/logout', (req, res) => {
    res.cookie('jwt', '', { maxAge: 1 });
    res.redirect('/login');
});

// --- 8. API ENDPOINTS ---

// 8.1 Authentication
app.post('/api/send-otp', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required.' });
    try {
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const { count } = await supabaseAdmin.from('otps').select('id', { count: 'exact', head: true }).eq('email', email).gte('created_at', twentyFourHoursAgo);
        if (count >= DAILY_OTP_LIMIT) return res.status(429).json({ error: 'Daily OTP limit reached.' });
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await supabaseAdmin.from('otps').insert({ email, otp, expires_at: new Date(Date.now() + OTP_EXPIRATION_MINUTES * 60 * 1000) });
        await sendOtpEmail(email, otp);
        res.status(200).json({ message: 'OTP sent successfully.' });
    } catch (error) {
        console.error("Error in /api/send-otp:", error);
        res.status(500).json({ error: 'Could not send OTP.' });
    }
});

app.post('/api/verify-otp', async (req, res) => {
    const { email, otp, publicKey } = req.body;
    if (!email || !otp || !publicKey) return res.status(400).json({ error: 'Email, OTP, and public key are required.' });
    try {
        const { data: otpData, error: otpError } = await supabaseAdmin.from('otps')
            .select('*')
            .eq('email', email)
            .eq('otp', otp)
            .gte('expires_at', 'now()')
            .single();
        
        if (otpError) {
            if (otpError.code === 'PGRST116') {
                return res.status(400).json({ error: 'Invalid or expired OTP.' });
            }
            throw otpError;
        }

        await supabaseAdmin.from('otps').delete().eq('id', otpData.id);
        
        const { data: existingUser, error: findUserError } = await supabaseAdmin.from('users').select('*').eq('email', email).single();
        if (findUserError && findUserError.code !== 'PGRST116') throw findUserError;

        const sessionId = crypto.randomUUID();
        let user;

        if (existingUser) {
            const { data: updatedUser, error: updateError } = await supabaseAdmin.from('users').update({ public_key: publicKey, last_seen: new Date(), session_id: sessionId }).eq('id', existingUser.id).select().single();
            if (updateError) throw updateError;
            user = updatedUser;
        } else {
            const newUsername = await generateUniqueUsername();
            const { data: newUser, error: createError } = await supabaseAdmin.from('users').insert({ email, username: newUsername, public_key: publicKey, last_seen: new Date(), session_id: sessionId }).select().single();
            if (createError) throw createError;
            user = newUser;
        }

        const token = createToken(user, sessionId);
        res.cookie('jwt', token, { httpOnly: true, secure: NODE_ENV === 'production', sameSite: 'strict' });
        res.status(200).json({ user });
    } catch (error) {
        console.error("Error in /api/verify-otp:", error);
        res.status(500).json({ error: 'Server error during OTP verification.' });
    }
});

// 8.2 User & Contact API
app.get('/api/users/search', requireAuth, async (req, res) => {
    const { searchTerm } = req.query;
    if (!searchTerm) return res.status(400).json({ error: "Search term is required." });
    
    try {
        const userSupabase = createSupabaseClientForUser(req.cookies.jwt);
        const { data, error } = await userSupabase
            .from('users')
            .select('id, username')
            .neq('id', req.user.id)
            .or(`username.ilike.%${searchTerm}%,email.ilike.%${searchTerm}%`)
            .limit(10);
            
        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        console.error("Error in /api/users/search:", error);
        return res.status(500).json({ error: 'Could not fetch users.' });
    }
});

app.get('/api/user/:userId', requireAuth, async (req, res) => {
    const userSupabase = createSupabaseClientForUser(req.cookies.jwt);
    const { data, error } = await userSupabase.from('users').select('id, username, public_key, last_seen').eq('id', req.params.userId).single();
    if (error || !data) return res.status(404).json({ error: 'User not found' });
    data.isOnline = clients.has(data.id);
    res.status(200).json(data);
});

// 8.3 Messaging API
app.get('/api/conversations', requireAuth, async (req, res) => {
    try {
        const userSupabase = createSupabaseClientForUser(req.cookies.jwt);
        const { data, error } = await userSupabase.rpc('get_conversations', { p_user_id: req.user.id });
        if (error) {
            console.error('Error calling get_conversations RPC:', error);
            throw error;
        }
        res.status(200).json(data || []);
    } catch (error) {
        res.status(500).json({ error: 'Could not fetch conversations.' });
    }
});

app.get('/api/messages/:peerId', requireAuth, async (req, res) => {
    const { peerId } = req.params;
    let { before } = req.query; // The cursor timestamp (optional)
    const userSupabase = createSupabaseClientForUser(req.cookies.jwt);
    
    const filter1 = `and(sender_id.eq.${req.user.id},receiver_id.eq.${peerId})`;
    const filter2 = `and(sender_id.eq.${peerId},receiver_id.eq.${req.user.id})`;

    let query = userSupabase
        .from('messages')
        .select('*')
        .or(`${filter1},${filter2}`)
        .is('group_id', null)
        .order('created_at', { ascending: false }) // Get newest first
        .limit(MESSAGE_PAGE_LIMIT);

    if (before) {
        // Sanitize the timestamp from the client. URL encoding can replace '+' with a space.
        const sanitizedBefore = new Date(before).toISOString();
        query = query.lt('created_at', sanitizedBefore);
    }

    const { data, error } = await query;

    if (error) {
        console.error(`Error fetching messages for user ${req.user.id} and peer ${peerId}:`, error);
        return res.status(500).json({ error: 'Could not fetch messages.' });
    }
    
    res.status(200).json(data ? data.reverse() : []);
});

app.post('/api/message', requireAuth, async (req, res) => {
    const { receiver_id, messageData } = req.body;
    if (!receiver_id || !messageData) return res.status(400).json({ error: 'Missing required message data.' });
    
    const userSupabase = createSupabaseClientForUser(req.cookies.jwt);
    
    const messageToInsert = {
        sender_id: req.user.id,
        receiver_id,
        status: 'delivered',
        ...messageData
    };

    const { data, error } = await userSupabase.from('messages').insert(messageToInsert).select().single();
    if (error) {
        console.error("Error inserting message:", error);
        return res.status(500).json({ error: 'Could not send message.' });
    }
    broadcastToUsers([req.user.id, receiver_id], { type: 'new-message', message: data });
    res.status(201).json(data);
});

app.post('/api/upload/signed-url', requireAuth, async (req, res) => {
    const { fileName, fileType, fileSize } = req.body;
    if (!fileName || !fileType || !fileSize) {
        return res.status(400).json({ error: 'File name, type, and size are required.' });
    }

    if (fileSize > MAX_FILE_SIZE) {
        return res.status(413).json({ error: `File size exceeds the ${MAX_FILE_SIZE / 1024 / 1024} MB limit.` });
    }
    
    const filePath = `${req.user.id}/${Date.now()}-${fileName}`;

    try {
        const { data, error } = await supabaseAdmin.storage
            .from('files')
            .createSignedUploadUrl(filePath);

        if (error) throw error;
        
        res.status(200).json({ signedUrl: data.signedUrl, path: data.path });
    } catch (error) {
        console.error("Error creating signed URL:", error);
        res.status(500).json({ error: 'Could not create upload URL.' });
    }
});

app.post('/api/storage/get-url', requireAuth, async (req, res) => {
    const { path } = req.body;
    if (!path) return res.status(400).json({ error: 'File path is required.' });

    try {
        const { data, error } = await supabaseAdmin.storage.from('files').getPublicUrl(path);
        if (error) throw error;
        if (!data.publicUrl) throw new Error('Could not retrieve file URL.');
        res.status(200).json({ publicUrl: data.publicUrl });
    } catch (error) {
        console.error("Error retrieving file URL:", error);
        res.status(500).json({ error: 'Could not retrieve file URL.' });
    }
});

app.post('/api/messages/mark-as-seen', requireAuth, async (req, res) => {
    const { senderId } = req.body;
    if (!senderId) {
        return res.status(400).json({ error: 'senderId is required.' });
    }

    try {
        const { error } = await supabaseAdmin
            .from('messages')
            .update({ status: 'seen' })
            .eq('receiver_id', req.user.id)
            .eq('sender_id', senderId)
            .eq('status', 'delivered');

        if (error) throw error;
        
        sendToUser(senderId, { type: 'seen-update', from: req.user.id });
        
        res.status(200).json({ message: 'Messages marked as seen.' });
    } catch (error) {
        console.error('Error marking messages as seen:', error);
        res.status(500).json({ error: 'Could not mark messages as seen.' });
    }
});

app.post('/api/subscribe/messages', requireAuth, async (req, res) => {
    const { userId } = req.body;
    if (!userId || userId !== req.user.id) {
        return res.status(400).json({ error: 'Invalid or missing userId.' });
    }

    try {
        // Create a user-specific Supabase client with the user's JWT
        const userSupabase = createSupabaseClientForUser(req.cookies.jwt);
        
        // Check if user already has an active subscription
        if (userSubscriptions.has(userId)) {
            userSubscriptions.get(userId).unsubscribe();
            userSubscriptions.delete(userId);
            console.log(`Previous subscription for user ${userId} removed.`);
        }

        // Subscribe to the public:messages channel
        const channel = userSupabase.channel(`public:messages:${userId}`);
        channel
            .on('postgres_changes', { 
                event: '*', 
                schema: 'public', 
                table: 'messages',
                filter: `sender_id=eq.${userId},receiver_id=eq.${userId}`
            }, (payload) => {
                const involvedUser = payload.new?.sender_id === userId || payload.new?.receiver_id === userId || 
                                    payload.old?.sender_id === userId || payload.old?.receiver_id === userId;
                if (involvedUser) {
                    let wsPayload;
                    switch (payload.eventType) {
                        case 'INSERT':
                            wsPayload = { type: 'new-message', message: payload.new };
                            break;
                        case 'UPDATE':
                            wsPayload = { type: 'message-updated', message: payload.new };
                            break;
                        case 'DELETE':
                            wsPayload = { type: 'message-deleted', messageId: payload.old.id };
                            break;
                        default:
                            return;
                    }
                    sendToUser(userId, wsPayload);
                }
            })
            .subscribe((status, err) => {
                if (status === 'SUBSCRIBED') {
                    console.log(`Subscribed to messages for user: ${userId}`);
                    userSubscriptions.set(userId, channel);
                } else if (status === 'CHANNEL_ERROR' && err) {
                    console.error(`Subscription error for user ${userId}:`, err);
                    sendToUser(userId, { type: 'subscription-error', error: err.message || 'Failed to subscribe to message updates.' });
                }
            });

        res.status(200).json({ message: 'Subscribed to message updates.' });
    } catch (error) {
        console.error("Error in /api/subscribe/messages:", error.message || 'Could not subscribe to message updates.');
        res.status(500).json({ error: 'Could not subscribe to message updates.' });
    }
});

app.put('/api/message/:messageId', requireAuth, async (req, res) => {
    const { messageId } = req.params;
    const { encrypted_content } = req.body;
    const userSupabase = createSupabaseClientForUser(req.cookies.jwt);
    const { data: msg, error: fetchError } = await userSupabase.from('messages').select('sender_id, receiver_id').eq('id', messageId).single();
    if (fetchError || !msg) return res.status(404).json({ error: "Message not found." });
    if (msg.sender_id !== req.user.id) return res.status(403).json({ error: "Forbidden." });
    const { data: updatedMsg, error: updateError } = await userSupabase.from('messages').update({ encrypted_message_for_sender: encrypted_content, encrypted_message_for_receiver: encrypted_content, is_edited: true }).eq('id', messageId).select().single();
    if (updateError) return res.status(500).json({ error: "Could not edit message." });
    broadcastToUsers([msg.sender_id, msg.receiver_id], { type: 'message-updated', message: updatedMsg });
    res.status(200).json(updatedMsg);
});

app.delete('/api/message/:messageId', requireAuth, async (req, res) => {
    const { messageId } = req.params;
    const userSupabase = createSupabaseClientForUser(req.cookies.jwt);
    const { data: msg, error: fetchError } = await userSupabase.from('messages').select('sender_id, receiver_id').eq('id', messageId).single();
    if (fetchError || !msg) return res.status(404).json({ error: "Message not found." });
    if (msg.sender_id !== req.user.id) return res.status(403).json({ error: "Forbidden." });
    const { error: deleteError } = await userSupabase.from('messages').delete().eq('id', messageId);
    if (deleteError) return res.status(500).json({ error: "Could not delete message." });
    broadcastToUsers([msg.sender_id, msg.receiver_id], { type: 'message-deleted', messageId });
    res.status(204).send();
});

// 8.4 Group Chat API
app.post('/api/groups', requireAuth, async (req, res) => {
    const { name, member_ids } = req.body;
    if (!name || !member_ids || !Array.isArray(member_ids) || member_ids.length === 0) {
        return res.status(400).json({ error: "Group name and at least one member are required." });
    }
    const allMemberIds = [...new Set([req.user.id, ...member_ids])];
    if (allMemberIds.length > MAX_GROUP_MEMBERS) return res.status(400).json({ error: "Exceeded max group members." });

    try {
        const { data: group, error: groupError } = await supabaseAdmin.from('groups').insert({ name, created_by: req.user.id }).select().single();
        if (groupError) throw groupError;

        const membersToInsert = allMemberIds.map(id => ({
            group_id: group.id,
            user_id: id,
            role: id === req.user.id ? 'admin' : 'member'
        }));
        const { error: memberError } = await supabaseAdmin.from('group_members').insert(membersToInsert);
        if (memberError) throw memberError;

        broadcastToUsers(allMemberIds, { type: 'new-group', group });
        res.status(201).json(group);
    } catch (error) {
        res.status(500).json({ error: "Could not create group." });
    }
});

app.post('/api/groups/:groupId/messages', requireAuth, async (req, res) => {
    const { groupId } = req.params;
    const { encrypted_content_map } = req.body;
    if (!encrypted_content_map) return res.status(400).json({ error: "Encrypted content map is required." });

    try {
        const userSupabase = createSupabaseClientForUser(req.cookies.jwt);
        const memberIds = await getGroupMemberIds(groupId);
        if (!memberIds.includes(req.user.id)) return res.status(403).json({ error: "You are not a member of this group." });

        const { data: message, error } = await userSupabase.from('messages').insert({
            sender_id: req.user.id,
            group_id: groupId,
            encrypted_content_map: encrypted_content_map,
            status: 'delivered'
        }).select().single();
        if (error) throw error;

        broadcastToUsers(memberIds, { type: 'new-group-message', message });
        res.status(201).json(message);
    } catch (error) {
        res.status(500).json({ error: "Could not send group message." });
    }
});

app.post('/api/groups/:groupId/members', requireAuth, async (req, res) => {
    const { groupId } = req.params;
    const { user_id_to_add } = req.body;
    if (!user_id_to_add) return res.status(400).json({ error: "User ID to add is required." });

    try {
        if (!await isGroupAdmin(groupId, req.user.id)) return res.status(403).json({ error: "Only admins can add members." });
        const { error } = await supabaseAdmin.from('group_members').insert({ group_id: groupId, user_id: user_id_to_add, role: 'member' });
        if (error) throw error;
        const memberIds = await getGroupMemberIds(groupId);
        broadcastToUsers(memberIds, { type: 'member-joined', groupId, userId: user_id_to_add });
        res.status(201).json({ message: "Member added successfully." });
    } catch (error) {
        res.status(500).json({ error: "Could not add member." });
    }
});

app.delete('/api/groups/:groupId/members/:userId', requireAuth, async (req, res) => {
    const { groupId, userId } = req.params;
    try {
        const isAdmin = await isGroupAdmin(groupId, req.user.id);
        if (!isAdmin && req.user.id !== userId) return res.status(403).json({ error: "Forbidden." });

        const { error } = await supabaseAdmin.from('group_members').delete().match({ group_id: groupId, user_id: userId });
        if (error) throw error;
        const memberIds = await getGroupMemberIds(groupId);
        broadcastToUsers([...memberIds, userId], { type: 'member-left', groupId, userId });
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ error: "Could not remove member." });
    }
});

// --- 9. ERROR HANDLING ---
app.use((err, req, res, next) => {
    console.error("Unhandled Error:", err.stack);
    res.status(500).json({ error: 'An unexpected error occurred.' });
});

// --- 10. SERVER STARTUP ---
server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 CipherChat server running on https://<your-local-ip>:${PORT}`);
    console.log(`      Mode: ${NODE_ENV || 'development'}`);
    console.log('      WebSocket server is listening.');
    console.log('      Waiting for connections...\n');
});