// Get the HEX in a Byte[]
byte[] msg = hexStr2Bytes(time);
byte[] k = hexStr2Bytes(key);
byte[] hash = hmac_sha(crypto, k, msg);

// put selected bytes into result int
int offset = hash[hash.length - 1] & 0xf;

int binary = ((hash[offset] & 0x7f) << 24) |
             ((hash[offset + 1] & 0xff) << 16) |
             ((hash[offset + 2] & 0xff) << 8) |
             (hash[offset + 3] & 0xff);

int otp = binary % DIGITS_POWER[codeDigits];
result = Integer.toString(otp);
