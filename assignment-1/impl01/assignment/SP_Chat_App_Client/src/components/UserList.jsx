import React from 'react';
import './UserList.css';

function UserList({ users, selectedUser, onSelectUser }) {
  return (
    <div className="user-list">
      <h3>Online Users ({users.length})</h3>
      <div className="user-items">
        {users.length === 0 ? (
          <div className="no-users">No other users online</div>
        ) : (
          users.map(user => (
            <div
              key={user}
              className={`user-item ${selectedUser === user ? 'selected' : ''}`}
              onClick={() => onSelectUser(user)}
            >
              <div className="user-avatar">{user.substring(0, 2).toUpperCase()}</div>
              <div className="user-name">{user.substring(0, 12)}...</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default UserList;