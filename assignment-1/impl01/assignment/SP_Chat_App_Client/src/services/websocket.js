class WebSocketService {
  constructor() {
    this.ws = null;
    this.messageHandlers = [];
    this.connected = false;
    this.userId = null;
    this.serverId = null;
  }

  connect(serverUrl, userId, publicKey) {
    return new Promise((resolve, reject) => {
      this.userId = userId;
      this.ws = new WebSocket(serverUrl);

      const connectionTimeout = setTimeout(() => {
        if (!this.connected) {
          this.ws.close();
          reject(new Error('Connection timeout'));
        }
      }, 10000);

      this.ws.onopen = () => {
        clearTimeout(connectionTimeout);
        console.log('[WebSocket] Connected to server');
        this.connected = true;
        this.sendHello(userId, publicKey);
        resolve();
      };

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          console.log('[WebSocket] Received:', message.type);
          this.handleMessage(message);
        } catch (error) {
          console.error('[WebSocket] Error parsing message:', error);
        }
      };

      this.ws.onerror = (error) => {
        clearTimeout(connectionTimeout);
        console.error('[WebSocket] Error:', error);
        this.connected = false;
        reject(error);
      };

      this.ws.onclose = () => {
        clearTimeout(connectionTimeout);
        console.log('[WebSocket] Connection closed');
        this.connected = false;
      };
    });
  }

  sendHello(userId, publicKey) {
    const message = {
      type: 'USER_HELLO',
      from: userId,
      to: 'server',
      ts: Date.now(),
      payload: {
        client: 'react-v1',
        pubkey: publicKey,
        enc_pubkey: publicKey,
        meta: {
          display_name: userId.substring(0, 8)
        }
      },
      sig: ''
    };
    this.send(message);
  }

  sendDirectMessage(to, ciphertext, senderPub, contentSig, ts) {
    const message = {
      type: 'MSG_DIRECT',
      from: this.userId,
      to,
      ts: ts || Date.now(),
      payload: {
        ciphertext,
        sender_pub: senderPub,
        content_sig: contentSig
      },
      sig: ''
    };
    this.send(message);
  }

  sendPublicChannelMessage(ciphertext, senderPub, contentSig, ts) {
    const message = {
      type: 'MSG_PUBLIC_CHANNEL',
      from: this.userId,
      to: 'public',
      ts: ts || Date.now(),
      payload: {
        ciphertext,
        sender_pub: senderPub,
        content_sig: contentSig
      },
      sig: ''
    };
    this.send(message);
  }

  requestUserList() {
    const message = {
      type: 'LIST_USERS',
      from: this.userId,
      to: 'server',
      ts: Date.now(),
      payload: {},
      sig: ''
    };
    this.send(message);
  }

  send(message) {
    if (this.ws && this.connected && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.error('[WebSocket] Not connected');
      throw new Error('WebSocket not connected');
    }
  }

  handleMessage(message) {
    if (message.type === 'ACK' && message.payload.server_id) {
      this.serverId = message.payload.server_id;
      console.log('[WebSocket] Connected to server:', this.serverId);
    }

    this.messageHandlers.forEach(handler => {
      try {
        handler(message);
      } catch (error) {
        console.error('[WebSocket] Error in message handler:', error);
      }
    });
  }

  onMessage(handler) {
    this.messageHandlers.push(handler);
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
      this.connected = false;
    }
  }

  isConnected() {
    return this.connected && this.ws && this.ws.readyState === WebSocket.OPEN;
  }
}

export default new WebSocketService();