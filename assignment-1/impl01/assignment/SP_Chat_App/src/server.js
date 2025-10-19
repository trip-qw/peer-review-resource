const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const config = require('../config');
const RSACrypto = require('./crypto/rsa');
const routingTables = require('./tables/inMemory');
const ServerProtocol = require('./protocol/serverProtocol');
const UserProtocol = require('./protocol/userProtocol');
const Database = require('./database/database');

class SOCPServer {
  constructor() {
    this.serverId = uuidv4();
    this.rsaCrypto = new RSACrypto();
    this.publicKey = null;
    this.privateKey = null;
    this.wss = null;
    this.serverProtocol = null;
    this.userProtocol = null;
    this.db = null;
    this.heartbeatInterval = null;
    this.timeoutCheckInterval = null;
    this.hasJoinedNetwork = false;
  }

  async initialize() {
    console.log('========================================');
    console.log('   SOCP Chat Server Initializing');
    console.log('========================================');
    console.log(`Server ID: ${this.serverId}`);
    console.log(`Port: ${config.PORT}`);
    console.log('----------------------------------------');

    // Generate RSA keys
    const keys = this.rsaCrypto.generateKeyPair();
    this.publicKey = keys.publicKey;
    this.privateKey = keys.privateKey;
    console.log('✓ Generated RSA-4096 key pair');
    console.log(`Public Key (first 64 chars):\n${this.publicKey.substring(0, 64)}...`);

    // Connect to database
    this.db = new Database(config.MONGODB_URI);
    await this.db.connect();
    await this.db.initializePublicChannel();
    console.log('✓ Connected to MongoDB');

    // Initialize protocol handlers
    this.serverProtocol = new ServerProtocol(
      this.serverId,
      this.rsaCrypto,
      this.privateKey,
      this.publicKey
    );

    this.userProtocol = new UserProtocol(
      this.serverId,
      this.rsaCrypto,
      this.privateKey,
      this.serverProtocol,
      this.db
    );

    console.log('✓ Protocol handlers initialized');
    console.log('----------------------------------------');
  }

  start() {
    // creating WebSocket server
    this.wss = new WebSocket.Server({ port: config.PORT });

    this.wss.on('listening', () => {
      console.log(`✓ WebSocket server listening on port ${config.PORT}`);
      console.log('========================================');
      console.log('Server is ready to accept connections!');
      console.log('========================================\n');

      // Try to join network after server is listening
      this.joinNetwork();
    });

    this.wss.on('connection', (ws, req) => {
      const clientIp = req.socket.remoteAddress;
      console.log(`[Connection] New connection from ${clientIp}`);

      ws.isAlive = true;
      ws.connectionType = null; // 'server' or 'user'
      ws.identifier = null; // server_id or user_id

      ws.on('pong', () => {
        ws.isAlive = true;
      });

      ws.on('message', async (data) => {
        try {
          const message = JSON.parse(data.toString());
          await this.handleMessage(ws, message);
        } catch (error) {
          console.error('[Server] Error handling message:', error.message);
          this.sendError(ws, 'UNKNOWN_TYPE', error.message);
        }
      });

      ws.on('close', () => {
        this.handleDisconnect(ws);
      });

      ws.on('error', (error) => {
        console.error('[Server] WebSocket error:', error.message);
      });
    });

    // Starts heartbeat mechanism
    this.startHeartbeat();

    // Starts connection timeout checker
    this.startTimeoutChecker();

    // Handle graceful shutdown
    process.on('SIGINT', () => this.shutdown());
    process.on('SIGTERM', () => this.shutdown());
  }

  /**
   * joining the network via bootstrap servers
   */
  async joinNetwork() {
    if (this.hasJoinedNetwork) return;

    console.log('[Bootstrap] Attempting to join network...');

    for (const bootstrap of config.BOOTSTRAP_SERVERS) {
      try {
        console.log(`[Bootstrap] Trying introducer at ${bootstrap.host}:${bootstrap.port}`);
        
        const ws = new WebSocket(`ws://${bootstrap.host}:${bootstrap.port}`);
        
        await new Promise((resolve, reject) => {
          const timeout = setTimeout(() => {
            ws.close();
            reject(new Error('Connection timeout'));
          }, 5000);

          ws.on('open', () => {
            clearTimeout(timeout);
            console.log(`[Bootstrap] Connected to introducer ${bootstrap.host}:${bootstrap.port}`);
            
            const joinMsg = {
              type: 'SERVER_HELLO_JOIN',
              from: this.serverId,
              to: `${bootstrap.host}:${bootstrap.port}`,
              ts: Date.now(),
              payload: {
                host: config.SERVER_HOST,
                port: config.PORT,
                pubkey: this.publicKey
              }
            };
            const { signEnvelope } = require('./crypto/signing');
            joinMsg.sig = signEnvelope(joinMsg.payload, this.rsaCrypto, this.privateKey);
            
            ws.send(JSON.stringify(joinMsg));
            console.log('[Bootstrap] Sent SERVER_HELLO_JOIN');
          });

          ws.on('message', async (data) => {
            try {
              const message = JSON.parse(data.toString());
              
              if (message.type === 'SERVER_WELCOME') {
                console.log('[Bootstrap] Received SERVER_WELCOME');
                await this.serverProtocol.handleServerWelcome(ws, message, bootstrap);
                this.hasJoinedNetwork = true;
                resolve();
              }
            } catch (error) {
              console.error('[Bootstrap] Error handling message:', error);
            }
          });

          ws.on('error', (error) => {
            clearTimeout(timeout);
            reject(error);
          });
        });

        // Successfully joined
        break;

      } catch (error) {
        console.error(`[Bootstrap] Failed to connect to ${bootstrap.host}:${bootstrap.port}:`, error.message);
      }
    }

    if (!this.hasJoinedNetwork) {
      console.log('[Bootstrap] Could not connect to any introducer - running as standalone');
    }
  }

  async handleMessage(ws, message) {
  const { type, from, to } = message;

  // routing based on message type
  switch (type) {
    case 'SERVER_HELLO_JOIN':
      ws.connectionType = 'server';
      ws.identifier = from;
      await this.serverProtocol.handleServerHelloJoin(ws, message);
      break;

    case 'SERVER_WELCOME':
      await this.serverProtocol.handleServerWelcome(ws, message);
      break;

    case 'SERVER_ANNOUNCE':
      await this.serverProtocol.handleServerAnnounce(ws, message);
      break;

    case 'USER_ADVERTISE':
      await this.serverProtocol.handleUserAdvertise(message);
      break;

    case 'USER_REMOVE':
      await this.serverProtocol.handleUserRemove(message);
      break;

    case 'SERVER_DELIVER':
      await this.serverProtocol.handleServerDeliver(ws, message);
      break;

    case 'HEARTBEAT':
      this.serverProtocol.handleHeartbeat(message);
      break;

    case 'PUBLIC_CHANNEL_ADD':
      await this.serverProtocol.handlePublicChannelAdd(message);
      break;

    case 'PUBLIC_CHANNEL_KEY_SHARE':
      await this.serverProtocol.handlePublicChannelKeyShare(message);
      break;

    case 'MSG_PUBLIC_CHANNEL':
      // handle based on sender type
      if (ws.connectionType === 'user') {
        // from local user - handle and broadcast to network
        await this.userProtocol.handlePublicChannelMessage(ws, message);
      } else if (ws.connectionType === 'server' || routingTables.servers.has(from)) {
        // from another server - deliver to local users
        await this.serverProtocol.handlePublicChannelBroadcast(message);
      }
      break;

    // User-to-Server messages
    case 'USER_HELLO':
      ws.connectionType = 'user';
      ws.identifier = from;
      await this.userProtocol.handleUserHello(ws, message);
      break;

    case 'MSG_DIRECT':
      await this.userProtocol.handleDirectMessage(ws, message);
      break;

    case 'FILE_START':
      await this.userProtocol.handleFileStart(ws, message);
      break;

    case 'FILE_CHUNK':
      await this.userProtocol.handleFileChunk(ws, message);
      break;

    case 'FILE_END':
      await this.userProtocol.handleFileEnd(ws, message);
      break;

    case 'LIST_USERS':
      this.userProtocol.handleListUsers(ws, from);
      break;

    default:
      console.warn(`[Server] Unknown message type: ${type}`);
      this.sendError(ws, 'UNKNOWN_TYPE', `Unknown message type: ${type}`);
  }
}

  handleDisconnect(ws) {
    if (ws.connectionType === 'user' && ws.identifier) {
      const user_id = ws.identifier;
      console.log(`[Disconnect] User ${user_id} disconnected`);

      // Removinf from routing tables
      routingTables.removeLocalUser(user_id);

      // Broadcast USER_REMOVE
      const removeMsg = {
        type: 'USER_REMOVE',
        from: this.serverId,
        to: '*',
        ts: Date.now(),
        payload: {
          user_id,
          server_id: this.serverId
        }
      };
      const { signEnvelope } = require('./crypto/signing');
      removeMsg.sig = signEnvelope(removeMsg.payload, this.rsaCrypto, this.privateKey);
      
      this.serverProtocol.broadcastToServers(removeMsg);

    } else if (ws.connectionType === 'server' && ws.identifier) {
      const server_id = ws.identifier;
      console.log(`[Disconnect] Server ${server_id} disconnected`);
      
      routingTables.removeServer(server_id);
      
      // reconnect after a delay
      setTimeout(() => this.reconnectToServer(server_id), 5000);
    }
  }

  async reconnectToServer(server_id) {
    const addr = routingTables.getServerAddress(server_id);
    if (addr) {
      console.log(`[Reconnect] Attempting to reconnect to ${server_id} at ${addr.host}:${addr.port}`);
    }
  }

  startHeartbeat() {
    this.heartbeatInterval = setInterval(() => {
      // Send heartbeat to all connected servers
      this.serverProtocol.sendHeartbeatToAll();

      // ping all WebSocket connections
      this.wss.clients.forEach((ws) => {
        if (ws.isAlive === false) {
          return ws.terminate();
        }
        ws.isAlive = false;
        ws.ping();
      });
    }, config.HEARTBEAT_INTERVAL);
  }

  startTimeoutChecker() {
    this.timeoutCheckInterval = setInterval(() => {
      routingTables.getAllServerIds().forEach(server_id => {
        const timeSince = routingTables.getTimeSinceHeartbeat(server_id);
        if (timeSince > config.CONNECTION_TIMEOUT) {
          console.log(`[Timeout] Server ${server_id} timed out (${timeSince}ms since last heartbeat)`);
          
          const ws = routingTables.getServerConnection(server_id);
          if (ws) {
            ws.close();
          }
          routingTables.removeServer(server_id);
        }
      });
    }, 10000); // 10 seconds
  }

  sendError(ws, code, detail) {
    if (!ws || ws.readyState !== 1) return;
    
    const error = {
      type: 'ERROR',
      from: this.serverId,
      to: 'client',
      ts: Date.now(),
      payload: { code, detail }
    };
    const { signEnvelope } = require('./crypto/signing');
    error.sig = signEnvelope(error.payload, this.rsaCrypto, this.privateKey);
    ws.send(JSON.stringify(error));
  }

  async shutdown() {
    console.log('\n[Shutdown] Gracefully shutting down...');

    // Clear intervals
    if (this.heartbeatInterval) clearInterval(this.heartbeatInterval);
    if (this.timeoutCheckInterval) clearInterval(this.timeoutCheckInterval);

    // Close all WebSocket connections
    if (this.wss) {
      this.wss.clients.forEach(ws => {
        ws.close(1000, 'Server shutting down');
      });

      // Close WebSocket server
      this.wss.close();
    }

    // Disconnect database
    if (this.db) {
      await this.db.disconnect();
    }

    console.log('[Shutdown] Server stopped');
    process.exit(0);
  }

  printStats() {
    setInterval(async () => {
      const routingStats = routingTables.getStats();
      const dbStats = await this.db.getStats();
      
      console.log('\n========== Server Statistics ==========');
      console.log(`Server ID: ${this.serverId}`);
      console.log(`Connected Servers: ${routingStats.servers}`);
      console.log(`Local Users: ${routingStats.local_users}`);
      console.log(`Total Known Users: ${routingStats.total_users}`);
      console.log(`Messages Seen: ${routingStats.seen_messages}`);
      console.log(`Database Users: ${dbStats.users}`);
      console.log(`Public Channel Members: ${dbStats.groupMembers}`);
      console.log('======================================\n');
    }, 30000); // 30 seconds
  }
}

// Starting the server
(async () => {
  const server = new SOCPServer();
  await server.initialize();
  server.start();
  server.printStats();
})();