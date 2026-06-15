<?php
$masterKeyHex = "";
$error = "";
$success = "";
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['token'])) {
    $tokenInput = preg_replace('/\s+/', '', $_POST['token']);
    try {
        while (openssl_error_string());
        if (!file_exists('private.pem')) {
            throw new Exception("The file 'private.pem' was not found in the directory!");
        }
        $privatePemContent = file_get_contents('private.pem');
        $tokenBytes = base64_decode($tokenInput, true);
        if ($tokenBytes === false) {
            throw new Exception("Invalid Base64 format in the token!");
        }
        $tokenLen = strlen($tokenBytes);
        if ($tokenLen !== 92) {
            throw new Exception("Invalid token size! Exactly 92 bytes expected (received: {$tokenLen} bytes).");
        }
        $ephemeralPubBytes = substr($tokenBytes, 0, 32);
        $tokenNonce        = substr($tokenBytes, 32, 12);
        $encryptedPayload  = substr($tokenBytes, 44, 48);
        $ciphertext        = substr($encryptedPayload, 0, 32);
        $authTag           = substr($encryptedPayload, 32, 16);
        $spkiPrefix = hex2bin("302a300506032b656e032100");
        $derBytes = $spkiPrefix . $ephemeralPubBytes;
        $ephemeralPubPem = "-----BEGIN PUBLIC KEY-----\n" . 
                           chunk_split(base64_encode($derBytes), 64, "\n") . 
                           "-----END PUBLIC KEY-----\n";

        $privateKeyRes = openssl_pkey_get_private($privatePemContent);
        if (!$privateKeyRes) {
            throw new Exception("Could not load 'private.pem' as a valid X25519 private key.");
        }
        $ephemeralPubKeyRes = openssl_pkey_get_public($ephemeralPubPem);
        if (!$ephemeralPubKeyRes) {
            throw new Exception("Could not process the ephemeral public key from the token.");
        }
        $sharedSecret = openssl_pkey_derive($ephemeralPubKeyRes, $privateKeyRes);
        if (!$sharedSecret) {
            throw new Exception("Could not calculate the shared secret via ECDH.");
        }
        $masterKeyRaw = openssl_decrypt(
            $ciphertext,
            'chacha20-poly1305',
            $sharedSecret,
            OPENSSL_RAW_DATA,
            $tokenNonce,
            $authTag
        );

        if ($masterKeyRaw === false) {
            throw new Exception("Decryption failed! The token is corrupt or the key pair does not match.");
        }
        $masterKeyHex = bin2hex($masterKeyRaw);
        $success = "Token successfully decrypted!";

    } catch (Exception $e) {
        $error = $e->getMessage();
    } finally {
        unset($privatePemContent, $sharedSecret, $masterKeyRaw, $privateKeyRes, $ephemeralPubKeyRes);
        while (openssl_error_string());
    }
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RAN - Recovery</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #0f172a;
            color: #f8fafc;
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }
        .container {
            width: 100%;
            max-width: 700px;
            background-color: #1e293b;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
            border: 1px solid #334155;
        }
        h1 {
            font-size: 24px;
            margin-top: 0;
            color: #38bdf8;
            border-bottom: 2px solid #334155;
            padding-bottom: 10px;
        }
        .alert {
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-weight: 500;
        }
        .alert-error {
            background-color: #7f1d1d;
            border: 1px solid #f87171;
            color: #fca5a5;
        }
        .alert-success {
            background-color: #064e3b;
            border: 1px solid #34d399;
            color: #a7f3d0;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #cbd5e1;
        }
        textarea {
            width: 100%;
            height: 100px;
            background-color: #0f172a;
            border: 1px solid #475569;
            border-radius: 6px;
            color: #38bdf8;
            padding: 12px;
            font-family: 'Courier New', Courier, monospace;
            font-size: 14px;
            resize: none;
            box-sizing: border-box;
            margin-bottom: 20px;
        }
        textarea:focus {
            outline: none;
            border-color: #38bdf8;
            box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2);
        }
        button {
            background-color: #0284c7;
            color: white;
            border: none;
            padding: 12px 24px;
            font-size: 16px;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.2s, transform 0.1s;
            width: 100%;
        }
        button:hover {
            background-color: #0369a1;
        }
        button:active {
            transform: scale(0.98);
        }
        .result-box {
            margin-top: 25px;
            background-color: #0f172a;
            border: 1px dashed #38bdf8;
            padding: 20px;
            border-radius: 6px;
        }
        .key-display {
            font-family: 'Courier New', Courier, monospace;
            font-size: 16px;
            background-color: #1e293b;
            padding: 10px;
            border-radius: 4px;
            word-break: break-all;
            color: #4ade80;
            border: 1px solid #334155;
            user-select: all;
        }
    </style>
</head>
<body>

<div class="container">
    <h1>🔑 RAN - Recovery</h1>
    <p style="color: #94a3b8; font-size: 14px;">Paste the token generated by RAN here to get the master key.</p>

    <?php if ($error): ?>
        <div class="alert alert-error">❌ <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
    <?php endif; ?>

    <?php if ($success): ?>
        <div class="alert alert-success">✅ <?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></div>
    <?php endif; ?>

    <form action="" method="POST">
        <label for="token">Base64 Backup Token:</label>
        <textarea id="token" name="token" placeholder="🎁 Paste here..." required autofocus><?php 
            // Clear textarea on success; retain input token on error
            echo !$masterKeyHex && isset($_POST['token']) ? htmlspecialchars($_POST['token'], ENT_QUOTES, 'UTF-8') : ''; 
        ?></textarea>
        
        <button type="submit">Recover Key</button>
    </form>

    <?php if ($masterKeyHex): ?>
        <div class="result-box">
            <label style="color: #4ade80;">🔓 Recovered Master Key (Hex):</label>
            <div class="key-display"><?php echo htmlspecialchars($masterKeyHex, ENT_QUOTES, 'UTF-8'); ?></div>
            <p style="color: #94a3b8; font-size: 12px; margin-top: 8px; margin-bottom: 0;">Tip: Click or triple-click inside the box to select the entire key for copying.</p>
        </div>
    <?php endif; ?>
</div>

</body>
</html>