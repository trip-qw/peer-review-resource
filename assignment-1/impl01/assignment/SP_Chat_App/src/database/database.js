const { MongoClient } = require('mongodb');

class Database {
  constructor(uri) {
    this.uri = uri;
    this.client = null;
    this.db = null;
  }

  async connect() {
    try {
      this.client = new MongoClient(this.uri);
      await this.client.connect();
      this.db = this.client.db('socp_chat');

      // Create indexes
      await this.db.collection('users').createIndex({ user_id: 1 }, { unique: true });
      await this.db.collection('group_members').createIndex({ group_id: 1, member_id: 1 }, { unique: true });

      console.log('[Database] Connected to MongoDB');
    } catch (error) {
      console.error('[Database] Connection error:', error);
      throw error;
    }
  }

  async disconnect() {
    if (this.client) {
      await this.client.close();
      console.log('[Database] Disconnected from MongoDB');
    }
  }

  /**
   * upserts the user 
   */
  async upsertUser(user_id, pubkey, meta = {}) {
    const users = this.db.collection('users');

    await users.updateOne(
      { user_id },
      {
        $set: {
          user_id,
          pubkey,
          meta,
          updated_at: new Date()
        },
        $setOnInsert: {
          created_at: new Date(),
          version: 1
        }
      },
      { upsert: true }
    );

    console.log(`[Database] Upserted user: ${user_id}`);
  }

  /**
   * user by ID
   */
  async getUser(user_id) {
    const users = this.db.collection('users');
    return await users.findOne({ user_id });
  }

  /**
   * user's public key
   */
  async getUserPubKey(user_id) {
    const user = await this.getUser(user_id);
    return user ? user.pubkey : null;
  }

  /**
   * adds user to public channel with encrypted group key
   */
  async addUserToPublicChannel(user_id, pubkey, wrapped_key) {
    const groupMembers = this.db.collection('group_members');

    await groupMembers.updateOne(
      { group_id: 'public', member_id: user_id },
      {
        $set: {
          group_id: 'public',
          member_id: user_id,
          role: 'member',
          wrapped_key, // Now actually encrypted!
          added_at: new Date()
        }
      },
      { upsert: true }
    );

    console.log(`[Database] Added ${user_id} to public channel with encrypted key`);
  }

  /**
   * get public channel members
   */
  async getPublicChannelMembers() {
    const groupMembers = this.db.collection('group_members');
    return await groupMembers.find({ group_id: 'public' }).toArray();
  }

  /**
   * getting wrapped key for a member
   */
  async getWrappedKey(group_id, member_id) {
    const groupMembers = this.db.collection('group_members');
    const member = await groupMembers.findOne({ group_id, member_id });
    return member ? member.wrapped_key : null;
  }

/**
   * initializing public channel group
   */
  async initializePublicChannel() {
    const groups = this.db.collection('groups');

    await groups.updateOne(
      { group_id: 'public' },
      {
        $set: {
          group_id: 'public',
          creator_id: 'system',
          created_at: new Date(),
          meta: {
            title: 'Public Channel',
            description: 'Network-wide public channel'
          },
          version: 1
        }
      },
      { upsert: true }
    );

    console.log('[Database] Initialized public channel');
  }

  /**
   * Geting database statistics
   */
  async getStats() {
    const users = await this.db.collection('users').countDocuments();
    const groupMembers = await this.db.collection('group_members').countDocuments();

    return { users, groupMembers };
  }
}

module.exports = Database;