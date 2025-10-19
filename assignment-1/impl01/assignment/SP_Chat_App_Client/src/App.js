import React, { useState } from 'react';
import './App.css';
import Login from './components/Login';
import ChatInterface from './components/ChatInterface';
import cryptoService from './services/crypto';
import websocketService from './services/websocket';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userId, setUserId] = useState('');
  const [keys, setKeys] = useState(null);

  const handleLogin = async (userId, serverUrl) => {
    try {
      console.log('Generating RSA-4096 keys...');
      const keyPair = cryptoService.generateKeyPair();
      setKeys(keyPair);
      setUserId(userId);
      
      cryptoService.loadKeys(keyPair.publicKey, keyPair.privateKey);

      console.log('Connecting to server...');
      await websocketService.connect(serverUrl, userId, keyPair.publicKey);
      
      setIsLoggedIn(true);
      console.log('Login successful!');
    } catch (error) {
      console.error('Login failed:', error);
      alert('Failed to connect to server: ' + error.message);
    }
  };

  const handleLogout = () => {
    websocketService.disconnect();
    setIsLoggedIn(false);
    setUserId('');
    setKeys(null);
  };

  return (
    <div className="App">
      {!isLoggedIn ? (
        <Login onLogin={handleLogin} />
      ) : (
        <ChatInterface 
          userId={userId} 
          keys={keys} 
          onLogout={handleLogout}
        />
      )}
    </div>
  );
}

export default App;