// Derive a key from the passphrase and salt using PBKDF2
// salt is simply hashed passphrase
async function deriveKey(passphrase) {
    const encoder = new TextEncoder();
    const passphraseKey = encoder.encode(passphrase);
    const salt = await crypto.subtle.digest('SHA-256', encoder.encode(passphrase));

    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      passphraseKey,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const key = await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    return key;
  }

async function decrypt(encryptedB64, key) {
    const encryptedBytes = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
    const iv = encryptedBytes.slice(0, 12);
    const ciphertext = encryptedBytes.slice(12);

    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);
  }

function base64ToUtf8(base64Str) {
    const binaryStr = atob(base64Str);
    const bytes = Uint8Array.from(binaryStr, c => c.charCodeAt(0));
    const decoder = new TextDecoder('utf-8');
    return decoder.decode(bytes);
}

async function loadHTMLIntoDiv(url, targetDiv, passphrase) {
    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error('Failed to load encrypted HTML');

        const encryptedB64 = await response.text();
        key = await deriveKey(passphrase);
        decryptedB64 = await decrypt(encryptedB64, key);
        decoded = base64ToUtf8(decryptedB64);
        targetDiv.innerHTML = decoded;
    } catch (error) {
        alert("Wrong password or fetching encrypted content failed.");
    }
}

function validatePassword(url, targetDiv, passphrase) {
    loadHTMLIntoDiv(url, targetDiv, passphrase);
}

async function showPasswordMsg(targetDiv) {
  const fetched = await fetch("../2025/js/password_msg.html");
  const text = await fetched.text();
  console.log(text);
  targetDiv.insertAdjacentHTML('afterbegin', text);
}