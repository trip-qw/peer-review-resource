const NodeRSA = require('node-rsa');
const crypto = require('crypto');

class RSACrypto {
  constructor() {
    this.key = null;
  }

  /**
   * generating RSA-4096 pair
   */
  generateKeyPair() {
    console.log('Generating RSA-4096 key pair (this may take a moment)...');
    this.key = new NodeRSA({ b: 4096 });
    this.key.setOptions({
      encryptionScheme: 'pkcs1_oaep',
      signingScheme: 'pss-sha256'
    });

    return {
      publicKey: this.key.exportKey('public'),
      privateKey: this.key.exportKey('private')
    };
  }

  /**
   * load existing pair
   */
  loadKeyPair(publicKey, privateKey) {
    this.key = new NodeRSA(privateKey);
    this.key.setOptions({
      encryptionScheme: 'pkcs1_oaep',
      signingScheme: 'pss-sha256'
    });
  }

  /**
   * importing and validating key
   */
  importKey(keyPEM) {
    try {
      const key = new NodeRSA(keyPEM);
      return key;
    } catch (error) {
      console.error('Failed to import key:', error.message);
      return null;
    }
  }

  /**
   * encrypts data with RSA-OAEP (SHA-256)
   */
  encrypt(data, publicKeyPEM) {
    const key = new NodeRSA(publicKeyPEM);
    key.setOptions({
      encryptionScheme: {
        scheme: 'pkcs1_oaep',
        hash: 'sha256'
      }
    });
    const encrypted = key.encrypt(data, 'buffer');
    return this.toBase64Url(encrypted);
  }

  /**
   * Decrypt data with RSA-OAEP (SHA-256)
   * @param {string} ciphertext - Base64url encoded ciphertext
   * @param {string} privateKeyPEM - Private key in PEM format
   * @returns {string} Decrypted plaintext
   */
  decrypt(ciphertext, privateKeyPEM) {
    const key = new NodeRSA(privateKeyPEM);
    key.setOptions({
      encryptionScheme: {
        scheme: 'pkcs1_oaep',
        hash: 'sha256'
      }
    });
    const buffer = this.fromBase64Url(ciphertext);
    return key.decrypt(buffer, 'utf8');
  }

  /**
   * signing the message with RSASSA-PSS (SHA-256)
   */
  sign(message, privateKeyPEM) {
    const key = new NodeRSA(privateKeyPEM);
    key.setOptions({ signingScheme: 'pss-sha256' });

    const signature = key.sign(message, 'buffer');
    return this.toBase64Url(signature);
  }

  /**
   * verifing signature with RSASSA-PSS (SHA-256)
   */
  verify(message, signature, publicKeyPEM) {
    try {
      const key = new NodeRSA(publicKeyPEM);
      key.setOptions({ signingScheme: 'pss-sha256' });

      const signatureBuffer = this.fromBase64Url(signature);
      return key.verify(message, signatureBuffer);
    } catch (error) {
      console.error('Signature verification failed:', error.message);
      return false;
    }
  }

  /**
   * Converting Buffer to base64url (no padding)
   */
  toBase64Url(buffer) {
    return buffer.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * convert base64url -> Buffer
   */
  fromBase64Url(base64url) {
    let base64 = base64url
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    while (base64.length % 4) {
      base64 += '=';
    }

    return Buffer.from(base64, 'base64');
  }

  /**
   * hashing data with SHA-256
   */
  hash(data) {
    return crypto.createHash('sha256').update(data).digest();
  }

  /**
   * Get public key from current key pair
   */
  getPublicKey() {
    return this.key ? this.key.exportKey('public') : null;
  }

  /**
   * Get private key from current key pair
   */
  getPrivateKey() {
    return this.key ? this.key.exportKey('private') : null;
  }
}

module.exports = RSACrypto;