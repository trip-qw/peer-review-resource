import NodeRSA from 'node-rsa';
import crypto from 'crypto-browserify';

class CryptoService {
  constructor() {
    this.key = null;
  }

  generateKeyPair() {
    console.log('Generating RSA-4096 key pair...');
    this.key = new NodeRSA({ b: 4096 });
    this.key.setOptions({
      encryptionScheme: {
        scheme: 'pkcs1_oaep',
        hash: 'sha256'
      },
      signingScheme: 'pss-sha256'
    });

    return {
      publicKey: this.key.exportKey('public'),
      privateKey: this.key.exportKey('private')
    };
  }

  loadKeys(publicKey, privateKey) {
    this.key = new NodeRSA(privateKey);
    this.key.setOptions({
      encryptionScheme: {
        scheme: 'pkcs1_oaep',
        hash: 'sha256'
      },
      signingScheme: 'pss-sha256'
    });
  }

  encrypt(data, publicKeyPEM) {
    try {
      const key = new NodeRSA(publicKeyPEM);
      key.setOptions({ 
        encryptionScheme: {
          scheme: 'pkcs1_oaep',
          hash: 'sha256'
        }
      });
      const encrypted = key.encrypt(data, 'buffer');
      return this.toBase64Url(encrypted);
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Failed to encrypt data');
    }
  }

  decrypt(ciphertext) {
    if (!this.key) throw new Error('No private key loaded');
    
    try {
      const buffer = this.fromBase64Url(ciphertext);
      return this.key.decrypt(buffer, 'utf8');
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Failed to decrypt message');
    }
  }

  sign(message) {
    if (!this.key) throw new Error('No private key loaded');
    
    try {
      const signature = this.key.sign(message, 'buffer');
      return this.toBase64Url(signature);
    } catch (error) {
      console.error('Signing error:', error);
      throw new Error('Failed to sign message');
    }
  }

  verify(message, signature, publicKeyPEM) {
    try {
      const key = new NodeRSA(publicKeyPEM);
      key.setOptions({ signingScheme: 'pss-sha256' });
      
      const signatureBuffer = this.fromBase64Url(signature);
      return key.verify(message, signatureBuffer);
    } catch (error) {
      console.error('Verification error:', error);
      return false;
    }
  }

  generateContentSigDM(ciphertext, from, to, ts) {
    const message = `${ciphertext}||${from}||${to}||${ts}`;
    const hash = crypto.createHash('sha256').update(message).digest();
    return this.sign(hash);
  }

  verifyContentSigDM(ciphertext, from, to, ts, contentSig, senderPubKey) {
    const message = `${ciphertext}||${from}||${to}||${ts}`;
    const hash = crypto.createHash('sha256').update(message).digest();
    return this.verify(hash, contentSig, senderPubKey);
  }

  generateContentSigPublic(ciphertext, from, ts) {
    const message = `${ciphertext}||${from}||${ts}`;
    const hash = crypto.createHash('sha256').update(message).digest();
    return this.sign(hash);
  }

  verifyContentSigPublic(ciphertext, from, ts, contentSig, senderPubKey) {
    const message = `${ciphertext}||${from}||${ts}`;
    const hash = crypto.createHash('sha256').update(message).digest();
    return this.verify(hash, contentSig, senderPubKey);
  }

  toBase64Url(buffer) {
    return buffer.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  fromBase64Url(base64url) {
    let base64 = base64url
      .replace(/-/g, '+')
      .replace(/_/g, '/');
    
    while (base64.length % 4) {
      base64 += '=';
    }
    
    return Buffer.from(base64, 'base64');
  }

  getPublicKey() {
    return this.key ? this.key.exportKey('public') : null;
  }

  getPrivateKey() {
    return this.key ? this.key.exportKey('private') : null;
  }
}

export default new CryptoService();