import React, { useState, useEffect, useRef } from 'react';
import './PublicChannel.css';

function PublicChannel({ messages, currentUser, onSendMessage }) {
  const [input, setInput] = useState('');
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (input.trim()) {
      onSendMessage(input);
      setInput('');
    }
  };

  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
  };

  return (
    <div className="public-channel">
      <div className="chat-header">
        <h3>Public Channel</h3>
        <span className="channel-desc">Visible to all users</span>
      </div>

      <div className="messages-container">
        {messages.length === 0 ? (
          <div className="no-messages">
            No messages yet. Be the first to post!
          </div>
        ) : (
          messages.map((msg, index) => (
            <div
              key={index}
              className={`message ${msg.from === currentUser ? 'own' : 'other'}`}
            >
              <div className="message-header">
                <span className="message-sender">
                  {msg.from.substring(0, 8)}...
                </span>
                <span className="message-time">{formatTime(msg.timestamp)}</span>
              </div>
              <div className="message-text">{msg.text}</div>
            </div>
          ))
        )}
        <div ref={messagesEndRef} />
      </div>

      <form onSubmit={handleSubmit} className="message-input">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Message public channel..."
        />
        <button type="submit">Send</button>
      </form>
    </div>
  );
}

export default PublicChannel;