import React, { useState, useEffect } from 'react';
import UserList from './UserList';
import ChatWindow from './ChatWindow';
import PublicChannel from './PublicChannel';
import websocketService from '../services/websocket';
import cryptoService from '../services/crypto';
import './ChatInterface.css';

function ChatInterface({ userId, keys, onLogout }) {
  const [users, setUsers] = useState([]);
  const [userPublicKeys, setUserPublicKeys] = useState({});
  const [selectedUser, setSelectedUser] = useState(null);
  const [activeTab, setActiveTab] = useState('public');
  const [directMessages, setDirectMessages] = useState({});
  const [publicMessages, setPublicMessages] = useState([]);
  const [publicChannelKey, setPublicChannelKey] = useState(null);

  useEffect(() => {
    websocketService.requestUserList();

    const handleMessage = (message) => {
      switch (message.type) {
        case 'USER_LIST':
          handleUserList(message);
          break;

        case 'USER_DELIVER':
          handleDirectMessageReceived(message);
          break;

        case 'PUBLIC_CHANNEL_MSG':
          handlePublicMessageReceived(message);
          break;

        case 'PUBLIC_CHANNEL_KEY':
          handlePublicChannelKey(message);
          break;

        case 'USER_ADVERTISE':
          handleUserAdvertise(message);
          break;

        case 'USER_REMOVE':
          handleUserRemove(message);
          break;

        case 'ERROR':
          console.error('Server error:', message.payload);
          alert(`Error: ${message.payload.code} - ${message.payload.detail}`);
          break;

        default:
          console.log('Unhandled message type:', message.type);
      }
    };

    websocketService.onMessage(handleMessage);

    const interval = setInterval(() => {
      websocketService.requestUserList();
    }, 30000);

    return () => clearInterval(interval);
  }, [userId]);

  const handleUserList = (message) => {
    const userList = message.payload.users;
    
    if (!Array.isArray(userList) || userList.length === 0) {
      setUsers([]);
      return;
    }

    if (typeof userList[0] === 'object' && userList[0].user_id) {
      const userIds = userList.map(u => u.user_id).filter(id => id !== userId);
      const pubkeys = {};
      
      userList.forEach(u => {
        if (u.user_id !== userId && u.pubkey) {
          pubkeys[u.user_id] = u.pubkey;
        }
      });
      
      setUsers(userIds);
      setUserPublicKeys(prev => ({ ...prev, ...pubkeys }));
      console.log(`[ChatInterface] Updated user list: ${userIds.length} users with public keys`);
    } else {
      setUsers(userList.filter(u => u !== userId));
      console.log(`[ChatInterface] Updated user list: ${userList.length} users`);
    }
  };

  const handleDirectMessageReceived = (message) => {
  const { sender, ciphertext, sender_pub, content_sig } = message.payload;
  
  // ignore our own messages
  if (sender === userId || sender.toLowerCase() === userId.toLowerCase()) {
    console.log('[ChatInterface] Ignoring own message echo from server');
    return;
  }
  
  console.log(`[ChatInterface] Received message from ${sender} at ${message.ts}`);
  
  try {
    // verifing content signature
    if (!cryptoService.verifyContentSigDM(
      ciphertext,
      sender,
      userId,
      message.ts,
      content_sig,
      sender_pub
    )) {
      console.error(`[ChatInterface] Invalid signature from ${sender}`);
      alert(`Warning: Message from ${sender} has invalid signature. Message rejected.`);
      return;
    }

    // decrypt
    const plaintext = cryptoService.decrypt(ciphertext);
    
    console.log(`[ChatInterface] Verified and decrypted message: "${plaintext}"`);
    
    // duplicate timestamp checking
    setDirectMessages(prev => {
      const existingMessages = prev[sender] || [];
      
      // duplicate message with this exact timestamp
      const isDuplicate = existingMessages.some(msg => msg.timestamp === message.ts);
      
      if (isDuplicate) {
        console.log('[ChatInterface] Duplicate message detected by timestamp, ignoring');
        return prev;
      }
      
      return {
        ...prev,
        [sender]: [
          ...existingMessages,
          {
            from: sender,
            text: plaintext,
            timestamp: message.ts,
            incoming: true
          }
        ]
      };
    });

    // adding sender's public key
    if (sender_pub && !userPublicKeys[sender]) {
      setUserPublicKeys(prev => ({ ...prev, [sender]: sender_pub }));
    }
  } catch (error) {
    console.error('Failed to process message:', error);
    alert(`Failed to decrypt message from ${sender}: ${error.message}`);
  }
};

  const handlePublicMessageReceived = (message) => {
  const { sender, ciphertext, sender_pub, content_sig } = message.payload;
  
  // removing our own messages
  if (sender === userId || sender.toLowerCase() === userId.toLowerCase()) {
    return;
  }
  
  try {
    // verifing signature
    if (!cryptoService.verifyContentSigPublic(
      ciphertext,
      sender,
      message.ts,
      content_sig,
      sender_pub
    )) {
      console.error(`[ChatInterface] Invalid signature from ${sender}`);
      return;
    }

    // decoding base64
    const plaintext = atob(ciphertext);
    
    // chekcing for detectes
    setPublicMessages(prev => {
      const isDuplicate = prev.some(msg => 
        msg.timestamp === message.ts && msg.from === sender
      );
      
      if (isDuplicate) {
        return prev;
      }
      
      return [
        ...prev,
        {
          from: sender,
          text: plaintext,
          timestamp: message.ts
        }
      ];
    });
  } catch (error) {
    console.error('Failed to process public message:', error);
  }
};

  const handlePublicChannelKey = (message) => {
    const { wrapped_key } = message.payload;
    
    try {
      // decrypting wrapped group key with our private key
      const groupKey = cryptoService.decrypt(wrapped_key);
      setPublicChannelKey(groupKey);
      console.log('[ChatInterface] Received public channel key');
    } catch (error) {
      console.error('Failed to decrypt public channel key:', error);
    }
  };

  const handleUserAdvertise = (message) => {
    const { user_id, pubkey } = message.payload;
    
    if (user_id !== userId) {
      if (!users.includes(user_id)) {
        setUsers(prev => [...prev, user_id]);
        console.log(`[ChatInterface] New user joined: ${user_id}`);
      }
      
      if (pubkey) {
        setUserPublicKeys(prev => ({ ...prev, [user_id]: pubkey }));
      }
    }
  };

  const handleUserRemove = (message) => {
    const { user_id } = message.payload;
    setUsers(prev => prev.filter(u => u !== user_id));
    
    setUserPublicKeys(prev => {
      const newKeys = { ...prev };
      delete newKeys[user_id];
      return newKeys;
    });
    
    console.log(`[ChatInterface] User left: ${user_id}`);
  };

  const sendDirectMessage = (recipientId, text) => {
    const recipientPubKey = userPublicKeys[recipientId];
    
    if (!recipientPubKey) {
      alert(`Cannot send message: recipient public key not available. Please wait for user list to refresh.`);
      return;
    }
    
    try {
      const ciphertext = cryptoService.encrypt(text, recipientPubKey);
      const ts = Date.now();
      
      // Generate content signature
      const contentSig = cryptoService.generateContentSigDM(
        ciphertext,
        userId,
        recipientId,
        ts
      );
      
      websocketService.sendDirectMessage(
        recipientId,
        ciphertext,
        keys.publicKey,
        contentSig,
        ts
      );

      setDirectMessages(prev => ({
        ...prev,
        [recipientId]: [
          ...(prev[recipientId] || []),
          {
            from: userId,
            text,
            timestamp: ts,
            incoming: false
          }
        ]
      }));
      
      console.log(`[ChatInterface] Message sent to ${recipientId}`);
    } catch (error) {
      console.error('Failed to send message:', error);
      alert('Failed to send message: ' + error.message);
    }
  };

  const sendPublicMessage = (text) => {
  try {
    const ciphertext = btoa(text); // Base64 encode
    const ts = Date.now();
    
    const contentSig = cryptoService.generateContentSigPublic(
      ciphertext,
      userId,
      ts
    );
    
    websocketService.sendPublicChannelMessage(
      ciphertext,
      keys.publicKey,
      contentSig,
      ts
    );

    setPublicMessages(prev => [
      ...prev,
      {
        from: userId,
        text,
        timestamp: ts
      }
    ]);
  } catch (error) {
    console.error('Failed to send public message:', error);
    alert('Failed to send public message: ' + error.message);
  }
};

  return (
    <div className="chat-interface">
      <div className="header">
        <h2>SOCP Chat - {userId.substring(0, 8)}...</h2>
        <button onClick={onLogout} className="logout-button">
          Logout
        </button>
      </div>

      <div className="main-content">
        <div className="sidebar">
          <div className="tabs">
            <button 
              className={activeTab === 'public' ? 'active' : ''}
              onClick={() => setActiveTab('public')}
            >
              Public Channel
            </button>
            <button 
              className={activeTab === 'direct' ? 'active' : ''}
              onClick={() => setActiveTab('direct')}
            >
              Direct Messages
            </button>
          </div>

          {activeTab === 'direct' && (
            <UserList 
              users={users}
              selectedUser={selectedUser}
              onSelectUser={setSelectedUser}
            />
          )}
        </div>

        <div className="chat-area">
          {activeTab === 'public' ? (
            <PublicChannel 
              messages={publicMessages}
              currentUser={userId}
              onSendMessage={sendPublicMessage}
            />
          ) : (
            selectedUser ? (
              <ChatWindow
                recipientId={selectedUser}
                messages={directMessages[selectedUser] || []}
                currentUser={userId}
                onSendMessage={(text) => sendDirectMessage(selectedUser, text)}
              />
            ) : (
              <div className="no-chat-selected">
                Select a user to start chatting
              </div>
            )
          )}
        </div>
      </div>
    </div>
  );
}

export default ChatInterface;