import React, { useState } from 'react';
import { v4 as uuidv4 } from 'uuid';
import './Login.css';

function Login({ onLogin }) {
  const [userId, setUserId] = useState('');
  const [serverUrl, setServerUrl] = useState('ws://localhost:12345');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    const finalUserId = userId || uuidv4();
    
    try {
      await onLogin(finalUserId, serverUrl);
    } catch (error) {
      console.error('Login error:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateRandomId = () => {
    setUserId(uuidv4());
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <h1>SOCP Chat</h1>
        <h2>Secure Overlay Chat Protocol</h2>
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>User ID (UUID):</label>
            <div className="input-with-button">
              <input
                type="text"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                placeholder="Leave empty for auto-generate"
              />
              <button type="button" onClick={generateRandomId}>
                Generate
              </button>
            </div>
          </div>

          <div className="form-group">
            <label>Server URL:</label>
            <input
              type="text"
              value={serverUrl}
              onChange={(e) => setServerUrl(e.target.value)}
              placeholder="ws://localhost:12345"
              required
            />
          </div>

          <button 
            type="submit" 
            className="login-button"
            disabled={loading}
          >
            {loading ? 'Connecting...' : 'Connect'}
          </button>
        </form>

        <div className="info-box">
          <p>RSA-4096 keys will be generated on connect (may take 5-10 seconds)</p>
        </div>
      </div>
    </div>
  );
}

export default Login;