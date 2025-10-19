const { signEnvelope, verifyEnvelope, verifyContentSigDM, verifyContentSigPublic, generateContentSigPublic } = require('../crypto/signing');
const routingTables = require('../tables/inMemory');
const crypto = require('crypto');

class UserProtocol {
  constructor(serverId, rsaCrypto, privateKey, serverProtocol, db) {
    this.serverId = serverId;
    this.rsaCrypto = rsaCrypto;
    this.privateKey = privateKey;
    this.serverProtocol = serverProtocol;
    this.db = db;
  }

  /**
   * Handles the USER_HELLO
   */
  async handleUserHello(ws, message) {
    const { from: user_id, payload } = message;
    const { pubkey, enc_pubkey, client } = payload;

    console.log(`[UserProtocol] USER_HELLO from ${user_id}`);

    // checking if the user_id already exists
    const existingLocation = routingTables.getUserLocation(user_id);
    if (existingLocation) {
      this.sendError(ws, user_id, 'NAME_IN_USE', 'User ID already in use on the network');
      ws.close();
      return;
    }

    // Validates the public key format
    if (!this.validatePublicKey(pubkey)) {
      this.sendError(ws, user_id, 'BAD_KEY', 'Invalid public key format');
      ws.close();
      return;
    }

    // adding local users
    routingTables.addLocalUser(user_id, ws);

    try {
      await this.db.upsertUser(user_id, pubkey, payload.meta || {});
    } catch (error) {
      console.error('[UserProtocol] Error storing user:', error);
      this.sendError(ws, user_id, 'DATABASE_ERROR', 'Failed to store user');
      return;
    }

    // broadcasts the USER_ADVERTISE 
    const advertiseMsg = {
      type: 'USER_ADVERTISE',
      from: this.serverId,
      to: '*',
      ts: Date.now(),
      payload: {
        user_id,
        server_id: this.serverId,
        pubkey: pubkey,
        meta: payload.meta || {}
      }
    };
    advertiseMsg.sig = signEnvelope(advertiseMsg.payload, this.rsaCrypto, this.privateKey);
    this.serverProtocol.broadcastToServers(advertiseMsg);

    // notifying all users about the new user
    routingTables.getAllLocalUserIds().forEach(existingUserId => {
      if (existingUserId !== user_id) {
        const existingWs = routingTables.getLocalUserConnection(existingUserId);
        if (existingWs && existingWs.readyState === 1) {
          existingWs.send(JSON.stringify(advertiseMsg));
        }
      }
    });

    // Sends the new user a list of all existing users
    await this.sendUserListToClient(ws, user_id);

    console.log(`[UserProtocol] Broadcasted USER_ADVERTISE for ${user_id}`);

    // adds user to public channel
    await this.addToPublicChannel(user_id, pubkey);

    // Sends acknowledgment to user
    const ack = {
      type: 'ACK',
      from: this.serverId,
      to: user_id,
      ts: Date.now(),
      payload: {
        message: 'Connected successfully',
        server_id: this.serverId
      }
    };
    ack.sig = signEnvelope(ack.payload, this.rsaCrypto, this.privateKey);
    ws.send(JSON.stringify(ack));
  }

  /**
   * Validates public key
   */
  validatePublicKey(pubkey) {
    try {
      const key = this.rsaCrypto.importKey(pubkey);
      
      return key !== null;
    } catch (error) {
      return false;
    }
  }

  /**
   * Handles the MSG_DIRECT
   */
  async handleDirectMessage(ws, message) {
  const { from, to, payload, ts } = message;
  const { ciphertext, sender_pub, content_sig } = payload;

  console.log(`[UserProtocol] MSG_DIRECT from ${from} to ${to}`);

  // verifys the user is local
  if (!routingTables.isLocalUser(from)) {
    this.sendError(ws, from, 'UNAUTHORIZED', 'You are not authenticated on this server');
    return;
  }

  // Prevent sending to self
  if (from === to) {
    console.log(`[UserProtocol] Rejecting message - sender and recipient are the same`);
    this.sendError(ws, from, 'INVALID_RECIPIENT', 'Cannot send message to yourself');
    return;
  }

  // Get recipient location
  const location = routingTables.getUserLocation(to);

  if (!location) {
    this.sendError(ws, from, 'USER_NOT_FOUND', `User ${to} not found in network`);
    return;
  }

  if (location === 'local') {
    // Delivering directly to local user ONLY (not back to sender)
    const recipientWs = routingTables.getLocalUserConnection(to);
    
    if (recipientWs && recipientWs.readyState === 1) {
      const deliverMsg = {
        type: 'USER_DELIVER',
        from: this.serverId,
        to,
        ts: ts,
        payload: {
          ciphertext,
          sender: from,
          sender_pub,
          content_sig
        }
      };
      deliverMsg.sig = signEnvelope(deliverMsg.payload, this.rsaCrypto, this.privateKey);

      recipientWs.send(JSON.stringify(deliverMsg));
      console.log(`[UserProtocol] Delivered locally from ${from} to ${to}`);
    } else {
      console.error(`[UserProtocol] Recipient ${to} connection not available`);
      this.sendError(ws, from, 'RECIPIENT_OFFLINE', `User ${to} is not connected`);
    }
  } else {
    // forwards to the remote server via SERVER_DELIVER
    const targetServerId = routingTables.getUserServerID(to);
    const targetWs = routingTables.getServerConnection(targetServerId);

    if (targetWs && targetWs.readyState === 1) {
      const serverDeliverMsg = {
        type: 'SERVER_DELIVER',
        from: this.serverId,
        to: targetServerId,
        ts: ts,
        payload: {
          user_id: to,
          ciphertext,
          sender: from,
          sender_pub,
          content_sig
        }
      };
      serverDeliverMsg.sig = signEnvelope(serverDeliverMsg.payload, this.rsaCrypto, this.privateKey);

      targetWs.send(JSON.stringify(serverDeliverMsg));
      console.log(`[UserProtocol] Forwarded from ${from} to server ${targetServerId} for user ${to}`);
    } else {
      this.sendError(ws, from, 'SERVER_NOT_FOUND', `Cannot reach server for user ${to}`);
    }
  }
}

  /**
   * Handle MSG_PUBLIC_CHANNEL
   */
  async handlePublicChannelMessage(ws, message) {
  const { from, payload, ts } = message;
  const { ciphertext, sender_pub, content_sig } = payload;

  console.log(`[UserProtocol] MSG_PUBLIC_CHANNEL from ${from}`);

  // Verify the user is local
  if (!routingTables.isLocalUser(from)) {
    this.sendError(ws, from, 'UNAUTHORIZED', 'You are not authenticated on this server');
    return;
  }

  // Deliver to ALL local users with ORIGINAL timestamp
  routingTables.getAllLocalUserIds().forEach(user_id => {
    const userWs = routingTables.getLocalUserConnection(user_id);
    if (userWs && userWs.readyState === 1) {
      const deliverMsg = {
        type: 'PUBLIC_CHANNEL_MSG',
        from: this.serverId,
        to: user_id,
        ts: ts,
        payload: {
          sender: from,
          ciphertext,
          sender_pub,
          content_sig
        }
      };
      deliverMsg.sig = signEnvelope(deliverMsg.payload, this.rsaCrypto, this.privateKey);
      
      userWs.send(JSON.stringify(deliverMsg));
    }
  });

  console.log(`[UserProtocol] Delivered public message to ${routingTables.getAllLocalUserIds().length} users`);

  // Also broadcast to other servers if they exist
  const broadcastMsg = {
    type: 'MSG_PUBLIC_CHANNEL',
    from: this.serverId,
    to: '*',
    ts: ts, 
    payload: {
      sender: from,
      ciphertext,
      sender_pub,
      content_sig
    }
  };
  broadcastMsg.sig = signEnvelope(broadcastMsg.payload, this.rsaCrypto, this.privateKey);
  this.serverProtocol.broadcastToServers(broadcastMsg);
}

  /**
   * Deliver public channel message to all local users
   */
  deliverPublicChannelToLocalUsers(message) {
    const { payload } = message;

    routingTables.getAllLocalUserIds().forEach(user_id => {
      const ws = routingTables.getLocalUserConnection(user_id);
      if (ws && ws.readyState === 1) {
        const deliverMsg = {
          type: 'PUBLIC_CHANNEL_MSG',
          from: this.serverId,
          to: user_id,
          ts: Date.now(),
          payload
        };
        deliverMsg.sig = signEnvelope(deliverMsg.payload, this.rsaCrypto, this.privateKey);

        ws.send(JSON.stringify(deliverMsg));
      }
    });
  }

  /**
   * Handle FILE_START
   */
  async handleFileStart(ws, message) {
    const { from, to, payload } = message;
    const { file_id, name, size, sha256, mode } = payload;

    console.log(`[UserProtocol] FILE_START: ${name} (${size} bytes) from ${from} to ${to}`);

    // Verify sender is local
    if (!routingTables.isLocalUser(from)) {
      this.sendError(ws, from, 'UNAUTHORIZED', 'Not authenticated');
      return;
    }

    // Route like a direct message
    const location = routingTables.getUserLocation(to);

    if (!location) {
      this.sendError(ws, from, 'USER_NOT_FOUND', `User ${to} not found`);
      return;
    }

    // Forward the FILE_START message
    if (location === 'local') {
      const recipientWs = routingTables.getLocalUserConnection(to);
      if (recipientWs && recipientWs.readyState === 1) {
        recipientWs.send(JSON.stringify(message));
      }
    } else {
      const targetServerId = routingTables.getUserServerID(to);
      const targetWs = routingTables.getServerConnection(targetServerId);
      if (targetWs && targetWs.readyState === 1) {
        targetWs.send(JSON.stringify(message));
      }
    }
  }

  /**
   * Handle FILE_CHUNK
   */
  async handleFileChunk(ws, message) {
    const { from, to, payload } = message;
    const { file_id, index } = payload;

    console.log(`[UserProtocol] FILE_CHUNK: ${file_id} chunk ${index}`);

    // Verify sender is local
    if (!routingTables.isLocalUser(from)) {
      this.sendError(ws, from, 'UNAUTHORIZED', 'Not authenticated');
      return;
    }

    const location = routingTables.getUserLocation(to);

    if (location === 'local') {
      const recipientWs = routingTables.getLocalUserConnection(to);
      if (recipientWs && recipientWs.readyState === 1) {
        recipientWs.send(JSON.stringify(message));
      }
    } else {
      const targetServerId = routingTables.getUserServerID(to);
      const targetWs = routingTables.getServerConnection(targetServerId);
      if (targetWs && targetWs.readyState === 1) {
        targetWs.send(JSON.stringify(message));
      }
    }
  }

  /**
   * Handling the FILE_END
   */
  async handleFileEnd(ws, message) {
    const { from, to, payload } = message;
    const { file_id } = payload;

    console.log(`[UserProtocol] FILE_END: ${file_id}`);

    // verifys sender is local 
    if (!routingTables.isLocalUser(from)) {
      this.sendError(ws, from, 'UNAUTHORIZED', 'Not authenticated');
      return;
    }

    // route like direct message
    const location = routingTables.getUserLocation(to);

    if (location === 'local') {
      const recipientWs = routingTables.getLocalUserConnection(to);
      if (recipientWs && recipientWs.readyState === 1) {
        recipientWs.send(JSON.stringify(message));
      }
    } else {
      const targetServerId = routingTables.getUserServerID(to);
      const targetWs = routingTables.getServerConnection(targetServerId);
      if (targetWs && targetWs.readyState === 1) {
        targetWs.send(JSON.stringify(message));
      }
    }
  }

  /**
   * handles /list command - return all online users
   */
  handleListUsers(ws, user_id) {
    this.sendUserListToClient(ws, user_id);
  }

  /**
   * adds user to public channel with proper key encryption
   */
  async addToPublicChannel(user_id, pubkey) {
    try {
      // generates a random 256-bit group key
      const groupKey = crypto.randomBytes(32);

      // Encrypt group key using RSA-OAEP
      const wrappedKey = this.rsaCrypto.encrypt(groupKey, pubkey);

      await this.db.addUserToPublicChannel(user_id, pubkey, wrappedKey);

      // broadcast PUBLIC_CHANNEL_ADD 
      const addMsg = {
        type: 'PUBLIC_CHANNEL_ADD',
        from: this.serverId,
        to: '*',
        ts: Date.now(),
        payload: {
          add: [user_id],
          if_version: 1
        }
      };
      addMsg.sig = signEnvelope(addMsg.payload, this.rsaCrypto, this.privateKey);

      this.serverProtocol.broadcastToServers(addMsg);

      // Sending the wrapped key to user
      const userWs = routingTables.getLocalUserConnection(user_id);
      if (userWs && userWs.readyState === 1) {
        const keyMsg = {
          type: 'PUBLIC_CHANNEL_KEY',
          from: this.serverId,
          to: user_id,
          ts: Date.now(),
          payload: {
            wrapped_key: wrappedKey,
            creator_pub: this.rsaCrypto.getPublicKey()
          }
        };
        keyMsg.sig = signEnvelope(keyMsg.payload, this.rsaCrypto, this.privateKey);
        userWs.send(JSON.stringify(keyMsg));
      }

      console.log(`[UserProtocol] Added ${user_id} to public channel`);
    } catch (error) {
      console.error('[UserProtocol] Error adding to public channel:', error);
    }
  }

  /**
   * sends current user list to a specific client
   */
  async sendUserListToClient(ws, user_id) {
    const allUsers = routingTables.getAllOnlineUsers();
    const otherUsers = allUsers.filter(u => u !== user_id);

    const usersWithKeys = [];
    for (const userId of otherUsers) {
      try {
        const user = await this.db.getUser(userId);
        if (user && user.pubkey) {
          usersWithKeys.push({
            user_id: userId,
            pubkey: user.pubkey,
            meta: user.meta || {}
          });
        } else {
          usersWithKeys.push({
            user_id: userId,
            pubkey: null,
            meta: {}
          });
        }
      } catch (error) {
        console.error(`[UserProtocol] Error getting user ${userId}:`, error);
      }
    }

    const response = {
      type: 'USER_LIST',
      from: this.serverId,
      to: user_id,
      ts: Date.now(),
      payload: {
        users: usersWithKeys
      }
    };
    response.sig = signEnvelope(response.payload, this.rsaCrypto, this.privateKey);

    if (ws && ws.readyState === 1) {
      ws.send(JSON.stringify(response));
      console.log(`[UserProtocol] Sent user list to ${user_id}: ${usersWithKeys.length} users`);
    }
  }

  /**
   * sends error to user
   */
  sendError(ws, user_id, code, detail) {
    if (!ws || ws.readyState !== 1) return;

    const error = {
      type: 'ERROR',
      from: this.serverId,
      to: user_id,
      ts: Date.now(),
      payload: { code, detail }
    };
    error.sig = signEnvelope(error.payload, this.rsaCrypto, this.privateKey);
    ws.send(JSON.stringify(error));
  }
}

module.exports = UserProtocol;