const { v4: uuidv4 } = require('uuid');
const WebSocket = require('ws');
const { signEnvelope, verifyEnvelope } = require('../crypto/signing');
const routingTables = require('../tables/inMemory');

class ServerProtocol {
  constructor(serverId, rsaCrypto, privateKey, publicKey) {
    this.serverId = serverId;
    this.rsaCrypto = rsaCrypto;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Handles SERVER_HELLO_JOIN (Bootstrap - Introducer side)
   */
  async handleServerHelloJoin(ws, message) {
    const { from, payload } = message;
    const { host, port, pubkey } = payload;

    console.log(`[ServerProtocol] Received SERVER_HELLO_JOIN from ${from}`);

    // verifing the signature
    if (message.sig && !verifyEnvelope(payload, message.sig, this.rsaCrypto, pubkey)) {
      console.error('[ServerProtocol] Invalid signature on SERVER_HELLO_JOIN');
      this.sendError(ws, 'INVALID_SIG', 'Invalid signature');
      return;
    }

    // if server_id is unique, assign new one if collision
    let assigned_id = from;
    if (routingTables.servers.has(from) || from === this.serverId) {
      assigned_id = uuidv4();
      console.log(`[ServerProtocol] ID collision, assigning new ID: ${assigned_id}`);
    }

    // adds to routing tables
    routingTables.addServer(assigned_id, ws, host, port, pubkey);

    // constructs the list of all servers
    const clients = routingTables.getAllServerIds()
      .filter(id => id !== assigned_id)
      .map(id => {
        const addr = routingTables.getServerAddress(id);
        return {
          server_id: id,
          host: addr.host,
          port: addr.port,
          pubkey: routingTables.getServerPubKey(id)
        };
      });

    // SERVER_WELCOME
    const response = {
      type: 'SERVER_WELCOME',
      from: this.serverId,
      to: assigned_id,
      ts: Date.now(),
      payload: {
        assigned_id,
        clients
      }
    };
    response.sig = signEnvelope(response.payload, this.rsaCrypto, this.privateKey);

    ws.send(JSON.stringify(response));
    console.log(`[ServerProtocol] Sent SERVER_WELCOME to ${assigned_id} with ${clients.length} servers`);
  }

  /**
   * handles SERVER_WELCOME 
   */
  async handleServerWelcome(ws, message, introducerInfo = null) {
    const { from, payload } = message;
    const { assigned_id, clients } = payload;

    console.log(`[ServerProtocol] Received SERVER_WELCOME from ${from}`);
    console.log(`[ServerProtocol] Assigned ID: ${assigned_id}, Network has ${clients.length} servers`);

    // verifs signature
    const introducerPubkey = introducerInfo ? introducerInfo.pubkey : routingTables.getServerPubKey(from);
    if (introducerPubkey && !verifyEnvelope(payload, message.sig, this.rsaCrypto, introducerPubkey)) {
      console.error('[ServerProtocol] Invalid signature on SERVER_WELCOME');
      return;
    }

    // update our server ID if it was changed
    if (assigned_id !== this.serverId) {
      console.log(`[ServerProtocol] Server ID changed from ${this.serverId} to ${assigned_id}`);
    }

    // store introducer connection
    ws.connectionType = 'server';
    ws.identifier = from;
    if (introducerInfo) {
      routingTables.addServer(from, ws, introducerInfo.host, introducerInfo.port, introducerInfo.pubkey);
    }

    // Connect to all other servers in the network
    for (const server of clients) {
      if (server.server_id !== this.serverId && server.server_id !== from) {
        this.connectToServer(server);
      }
    }

    // boadcasting our presence to the network
    const announceMsg = {
      type: 'SERVER_ANNOUNCE',
      from: this.serverId,
      to: '*',
      ts: Date.now(),
      payload: {
        host: require('../config').SERVER_HOST,
        port: require('../config').PORT,
        pubkey: this.publicKey
      }
    };
    announceMsg.sig = signEnvelope(announceMsg.payload, this.rsaCrypto, this.privateKey);
    
    // sending to introducer
    if (ws.readyState === 1) {
      ws.send(JSON.stringify(announceMsg));
    }

    console.log('[ServerProtocol] Network join complete');
  }

  /**
   * connecting to another server
   */
  async connectToServer(serverInfo) {
    const { server_id, host, port, pubkey } = serverInfo;
    
    try {
      console.log(`[ServerProtocol] Connecting to server ${server_id} at ${host}:${port}`);
      
      const ws = new WebSocket(`ws://${host}:${port}`);

      ws.on('open', () => {
        console.log(`[ServerProtocol] Connected to ${server_id}`);
        
        // mark as server connection
        ws.connectionType = 'server';
        ws.identifier = server_id;
        ws.isAlive = true;

        // add to routing tables
        routingTables.addServer(server_id, ws, host, port, pubkey);

        // send SERVER_ANNOUNCE
        const announceMsg = {
          type: 'SERVER_ANNOUNCE',
          from: this.serverId,
          to: server_id,
          ts: Date.now(),
          payload: {
            host: require('../config').SERVER_HOST,
            port: require('../config').PORT,
            pubkey: this.publicKey
          }
        };
        announceMsg.sig = signEnvelope(announceMsg.payload, this.rsaCrypto, this.privateKey);
        
        ws.send(JSON.stringify(announceMsg));
      });

      ws.on('error', (error) => {
        console.error(`[ServerProtocol] Error connecting to ${server_id}:`, error.message);
      });

      ws.on('close', () => {
        console.log(`[ServerProtocol] Connection to ${server_id} closed`);
        routingTables.removeServer(server_id);
      });

    } catch (error) {
      console.error(`[ServerProtocol] Failed to connect to ${server_id}:`, error.message);
    }
  }

  /**
   * Handles SERVER_ANNOUNCE
   */
  async handleServerAnnounce(ws, message) {
    const { from, payload } = message;
    const { host, port, pubkey } = payload;

    console.log(`[ServerProtocol] Received SERVER_ANNOUNCE from ${from}`);

    // Verifys signature
    if (!verifyEnvelope(payload, message.sig, this.rsaCrypto, pubkey)) {
      console.error('[ServerProtocol] Invalid signature on SERVER_ANNOUNCE');
      return;
    }

    // Register the new server if not already known
    if (!routingTables.servers.has(from)) {
      routingTables.addServer(from, ws, host, port, pubkey);
      ws.connectionType = 'server';
      ws.identifier = from;
      ws.isAlive = true;
    }
  }

  /**
   * Handles the USER_ADVERTISE
   */
  async handleUserAdvertise(message) {
    const { from: server_id, payload } = message;
    const { user_id, server_id: user_server_id, meta } = payload;

    console.log(`[ServerProtocol] USER_ADVERTISE: ${user_id} on ${user_server_id}`);

    // Verifys signature
    const serverPubKey = routingTables.getServerPubKey(server_id);
    if (!serverPubKey || !verifyEnvelope(payload, message.sig, this.rsaCrypto, serverPubKey)) {
      console.error('[ServerProtocol] Invalid signature on USER_ADVERTISE');
      return;
    }

    // Update routing table
    routingTables.advertiseRemoteUser(user_id, user_server_id);

    this.broadcastToServers(message, server_id);

    this.notifyLocalUsers(message);
  }

  /**
   * Handles the USER_REMOVE
   */
  async handleUserRemove(message) {
    const { from: server_id, payload } = message;
    const { user_id, server_id: user_server_id } = payload;

    console.log(`[ServerProtocol] USER_REMOVE: ${user_id} from ${user_server_id}`);

    // Verify signature
    const serverPubKey = routingTables.getServerPubKey(server_id);
    if (!serverPubKey || !verifyEnvelope(payload, message.sig, this.rsaCrypto, serverPubKey)) {
      console.error('[ServerProtocol] Invalid signature on USER_REMOVE');
      return;
    }

    const currentLocation = routingTables.getUserLocation(user_id);
    if (currentLocation === `server_${user_server_id}`) {
      routingTables.user_locations.delete(user_id);
      console.log(`[ServerProtocol] Removed user ${user_id} from routing table`);
    }

    this.broadcastToServers(message, server_id);

    // Notify local users
    this.notifyLocalUsers(message);
  }

  /**
   * Handle message delivery
   */
  async handleServerDeliver(ws, message) {
    const { from, to, payload, ts } = message;
    const { user_id } = payload;

    console.log(`[ServerProtocol] SERVER_DELIVER: message for ${user_id} from ${from}`);

    // Check for duplicate 
    if (routingTables.isDuplicate(ts, from, to, payload)) {
      console.log('[ServerProtocol] Duplicate message detected, dropping');
      return;
    }

    // Verifys signature
    const serverPubKey = routingTables.getServerPubKey(from);
    if (!serverPubKey || !verifyEnvelope(payload, message.sig, this.rsaCrypto, serverPubKey)) {
      console.error('[ServerProtocol] Invalid signature on SERVER_DELIVER');
      this.sendError(ws, 'INVALID_SIG', 'Invalid signature');
      return;
    }

    // Route the message
    const location = routingTables.getUserLocation(user_id);

    if (location === 'local') {
      // Deliver to local user
      const userWs = routingTables.getLocalUserConnection(user_id);
      if (userWs && userWs.readyState === 1) {
        const deliverMsg = {
          type: 'USER_DELIVER',
          from: this.serverId,
          to: user_id,
          ts: Date.now(),
          payload: {
            ciphertext: payload.ciphertext,
            sender: payload.sender,
            sender_pub: payload.sender_pub,
            content_sig: payload.content_sig
          }
        };
        deliverMsg.sig = signEnvelope(deliverMsg.payload, this.rsaCrypto, this.privateKey);
        
        userWs.send(JSON.stringify(deliverMsg));
        console.log(`[ServerProtocol] Delivered to local user: ${user_id}`);
      }
    } else if (location && location.startsWith('server_')) {
      // Forward to another server
      const targetServerId = location.replace('server_', '');
      const targetWs = routingTables.getServerConnection(targetServerId);
      
      if (targetWs && targetWs.readyState === 1) {
        targetWs.send(JSON.stringify(message));
        console.log(`[ServerProtocol] Forwarded to server: ${targetServerId}`);
      } else {
        console.error(`[ServerProtocol] Server ${targetServerId} not connected`);
        this.sendError(ws, 'SERVER_NOT_FOUND', `Server ${targetServerId} not connected`);
      }
    } else {
      console.error(`[ServerProtocol] User ${user_id} not found`);
      this.sendError(ws, 'USER_NOT_FOUND', `User ${user_id} not found`);
    }
  }

  /**
   * Handles the HEARTBEAT
   */
  handleHeartbeat(message) {
    const { from } = message;
    routingTables.updateHeartbeat(from);
  }

  /**
   * Handles the PUBLIC_CHANNEL_ADD
   */
  async handlePublicChannelAdd(message) {
    const { from, payload } = message;
    const { add } = payload;

    console.log(`[ServerProtocol] PUBLIC_CHANNEL_ADD: ${add.join(', ')}`);

    // Verifing signature
    const serverPubKey = routingTables.getServerPubKey(from);
    if (!serverPubKey || !verifyEnvelope(payload, message.sig, this.rsaCrypto, serverPubKey)) {
      console.error('[ServerProtocol] Invalid signature on PUBLIC_CHANNEL_ADD');
      return;
    }

    this.broadcastToServers(message, from);

    this.notifyLocalUsers(message);
  }

  /**
   * Handles the PUBLIC_CHANNEL_KEY_SHARE
   */
  async handlePublicChannelKeyShare(message) {
    const { from, payload } = message;
    const { shares, creator_pub, content_sig } = payload;

    console.log(`[ServerProtocol] PUBLIC_CHANNEL_KEY_SHARE: ${shares.length} shares`);

    // Verifys the signature
    const serverPubKey = routingTables.getServerPubKey(from);
    if (!serverPubKey || !verifyEnvelope(payload, message.sig, this.rsaCrypto, serverPubKey)) {
      console.error('[ServerProtocol] Invalid signature on PUBLIC_CHANNEL_KEY_SHARE');
      return;
    }

    // Route shares to appropriate servers/users
    for (const share of shares) {
      const { member, wrapped_public_channel_key } = share;
      const location = routingTables.getUserLocation(member);

      if (location === 'local') {
        const userWs = routingTables.getLocalUserConnection(member);
        if (userWs && userWs.readyState === 1) {
          const deliverMsg = {
            type: 'PUBLIC_CHANNEL_KEY',
            from: this.serverId,
            to: member,
            ts: Date.now(),
            payload: {
              wrapped_key: wrapped_public_channel_key,
              creator_pub
            }
          };
          deliverMsg.sig = signEnvelope(deliverMsg.payload, this.rsaCrypto, this.privateKey);
          userWs.send(JSON.stringify(deliverMsg));
        }
      }
    }

    // Forward to other servers
    this.broadcastToServers(message, from);
  }

/**
 * Handles the public channel broadcast
 */
async handlePublicChannelBroadcast(message) {
  const { from, payload } = message;

  console.log(`[ServerProtocol] PUBLIC_CHANNEL broadcast from server ${from}`);

  // Verifying the SERVER signature 
  const serverPubKey = routingTables.getServerPubKey(from);
  if (!serverPubKey || !verifyEnvelope(payload, message.sig, this.rsaCrypto, serverPubKey)) {
    console.error('[ServerProtocol] Invalid server signature on PUBLIC_CHANNEL broadcast');
    return;
  }

  console.log(`[ServerProtocol] Verified server signature from ${from}`);

  // delivers to all local users
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
  
  console.log(`[ServerProtocol] Delivered public message to ${routingTables.getAllLocalUserIds().length} local users`);
}

  /**
   * broadcast message to all servers
   */
  broadcastToServers(message, excludeServerId = null) {
    routingTables.getAllServerIds().forEach(server_id => {
      if (server_id !== excludeServerId && server_id !== this.serverId) {
        const ws = routingTables.getServerConnection(server_id);
        if (ws && ws.readyState === 1) { // OPEN
          ws.send(JSON.stringify(message));
        }
      }
    });
  }

  /**
   * notify all local users with a message
   */
  notifyLocalUsers(message) {
    routingTables.getAllLocalUserIds().forEach(user_id => {
      const ws = routingTables.getLocalUserConnection(user_id);
      if (ws && ws.readyState === 1) {
        ws.send(JSON.stringify(message));
      }
    });
  }

  /**
   * sending the error message
   */
  sendError(ws, code, detail) {
    if (!ws || ws.readyState !== 1) return;
    
    const error = {
      type: 'ERROR',
      from: this.serverId,
      to: 'client',
      ts: Date.now(),
      payload: { code, detail }
    };
    error.sig = signEnvelope(error.payload, this.rsaCrypto, this.privateKey);
    ws.send(JSON.stringify(error));
  }

  /**
   * Sending heartbeat to a specific server
   */
  sendHeartbeat(server_id) {
    const ws = routingTables.getServerConnection(server_id);
    if (ws && ws.readyState === 1) {
      const heartbeat = {
        type: 'HEARTBEAT',
        from: this.serverId,
        to: server_id,
        ts: Date.now(),
        payload: {}
      };
      heartbeat.sig = signEnvelope(heartbeat.payload, this.rsaCrypto, this.privateKey);
      ws.send(JSON.stringify(heartbeat));
    }
  }

  /**
   * sending the heartbeats to all servers
   */
  sendHeartbeatToAll() {
    routingTables.getAllServerIds().forEach(server_id => {
      this.sendHeartbeat(server_id);
    });
  }
}

module.exports = ServerProtocol;