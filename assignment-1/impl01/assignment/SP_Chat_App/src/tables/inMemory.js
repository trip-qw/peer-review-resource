const crypto = require('crypto');

class RoutingTables {
  constructor() {
    // server_id -> WebSocket connection
    this.servers = new Map();
    
    // server_id -> {host, port, pubkey}
    this.server_addrs = new Map();
    
    // server_id -> public key (for signature verification)
    this.server_pubkeys = new Map();
    
    // user_id -> WebSocket connection
    this.local_users = new Map();
    
    // user_id -> "local" | "server_{id}"
    this.user_locations = new Map();
    
    // Set of message hashes to prevent duplicates
    // Format: "ts-from-to-hash"
    this.seen_ids = new Set();
    this.maxSeenIds = 1000; // Keep last 1000 message hashes
    
    // Last heartbeat received from each server
    this.last_heartbeat = new Map();
  }

  /**
   * ading a server connection to the mesh
   */
  addServer(server_id, ws, host, port, pubkey) {
    this.servers.set(server_id, ws);
    this.server_addrs.set(server_id, { host, port });
    this.server_pubkeys.set(server_id, pubkey);
    this.last_heartbeat.set(server_id, Date.now());
    console.log(`[RoutingTable] Added server: ${server_id} at ${host}:${port}`);
  }

  /**
   * removeing the server from the mesh
   */
  removeServer(server_id) {
    this.servers.delete(server_id);
    this.last_heartbeat.delete(server_id);

    for (const [user_id, location] of this.user_locations.entries()) {
      if (location === `server_${server_id}`) {
        this.user_locations.delete(user_id);
        console.log(`[RoutingTable] Removed stale route for user: ${user_id}`);
      }
    }
    console.log(`[RoutingTable] Removed server: ${server_id}`);
  }

  /**
   * get server WebSocket connection
   */
  getServerConnection(server_id) {
    return this.servers.get(server_id);
  }

  /**
   * get server address
   */
  getServerAddress(server_id) {
    return this.server_addrs.get(server_id);
  }

  /**
   * get server public key
   */
  getServerPubKey(server_id) {
    return this.server_pubkeys.get(server_id);
  }

  /**
   * get all server IDs
   */
  getAllServerIds() {
    return Array.from(this.servers.keys());
  }

  /**
   * adding the local user
   */
  addLocalUser(user_id, ws) {
    this.local_users.set(user_id, ws);
    this.user_locations.set(user_id, 'local');
    console.log(`[RoutingTable] Added local user: ${user_id}`);
  }

  /**
   * removes the local user
   */
  removeLocalUser(user_id) {
    this.local_users.delete(user_id);
    this.user_locations.delete(user_id);
    console.log(`[RoutingTable] Removed local user: ${user_id}`);
  }

  /**
   * Checking if user is local
   */
  isLocalUser(user_id) {
    return this.user_locations.get(user_id) === 'local';
  }

  /**
   *  local user WebSocket
   */
  getLocalUserConnection(user_id) {
    return this.local_users.get(user_id);
  }

  /**
   * all local user IDs
   */
  getAllLocalUserIds() {
    return Array.from(this.local_users.keys());
  }

  /**
   * Advertiseing remote user (from gossip)
   */
  advertiseRemoteUser(user_id, server_id) {
    this.user_locations.set(user_id, `server_${server_id}`);
    console.log(`[RoutingTable] User ${user_id} is on server ${server_id}`);
  }

  /**
   * Gets user location
   * @returns {string|null} "local", "server_{id}", or null if not found
   */
  getUserLocation(user_id) {
    return this.user_locations.get(user_id) || null;
  }

  /**
   * Gets server ID for a remote user
   */
  getUserServerID(user_id) {
    const location = this.user_locations.get(user_id);
    if (location && location.startsWith('server_')) {
      return location.replace('server_', '');
    }
    return null;
  }

  /**
   * checks for duplicate message 
   */
  isDuplicate(ts, from, to, payload) {
    const payloadHash = crypto.createHash('sha256')
      .update(JSON.stringify(payload))
      .digest('hex')
      .substring(0, 16); // First 16 chars
    
    const key = `${ts}-${from}-${to}-${payloadHash}`;
    
    if (this.seen_ids.has(key)) {
      return true;
    }
    
    this.seen_ids.add(key);
    
    // Limit cache size
    if (this.seen_ids.size > this.maxSeenIds) {
      const firstKey = this.seen_ids.values().next().value;
      this.seen_ids.delete(firstKey);
    }
    
    return false;
  }

  /**
   * updates heartbeat timestamp for a server
   */
  updateHeartbeat(server_id) {
    this.last_heartbeat.set(server_id, Date.now());
  }

  /**
   * geting time since last heartbeat
   */
  getTimeSinceHeartbeat(server_id) {
    const last = this.last_heartbeat.get(server_id);
    if (!last) return Infinity;
    return Date.now() - last;
  }

  /**
   * geting all online users (local + remote)
   */
  getAllOnlineUsers() {
    return Array.from(this.user_locations.keys());
  }

  /**
   * gets statistics
   */
  getStats() {
    return {
      servers: this.servers.size,
      local_users: this.local_users.size,
      total_users: this.user_locations.size,
      seen_messages: this.seen_ids.size
    };
  }
}

// Singleton instance
module.exports = new RoutingTables();