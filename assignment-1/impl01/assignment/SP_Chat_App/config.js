require('dotenv').config();

module.exports = {
  PORT: process.env.PORT || 12345,
  SERVER_HOST: process.env.SERVER_HOST || 'localhost',
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/socp_chat',

  // Bootstrap servers (introducers) - UPDATE WITH ACTUAL IPs FROM OTHER GROUPS
  BOOTSTRAP_SERVERS: [
    {
      host: '192.168.0.42',
      port: 12345,
      pubkey: 'PLACEHOLDER_PUBKEY_1'
    },
    // Add more bootstrap servers...
  ],

  HEARTBEAT_INTERVAL: 15000, // 15s
  CONNECTION_TIMEOUT: 45000  // 45s
};