module.exports = [
	{ name: "aes-128-cbc", keyLength:16, ivLength:16 },
{ name: "aes-128-cbc-hmac-sha1", keyLength:16, ivLength:16 },
{ name: "aes-128-cbc-hmac-sha256", keyLength:16, ivLength:16 },
{ name: "aes-128-ccm", keyLength:16, ivLength:12 },
{ name: "aes-128-cfb", keyLength:16, ivLength:16 },
{ name: "aes-128-cfb1", keyLength:16, ivLength:16 },
{ name: "aes-128-cfb8", keyLength:16, ivLength:16 },
{ name: "aes-128-ctr", keyLength:16, ivLength:16 },
{ name: "aes-128-ecb", keyLength:16, ivLength:0 },
{ name: "aes-128-gcm", keyLength:16, ivLength:12 },
{ name: "aes-128-ofb", keyLength:16, ivLength:16 },
{ name: "aes-128-xts", keyLength:32, ivLength:16 },
{ name: "aes-192-cbc", keyLength:24, ivLength:16 },
{ name: "aes-192-ccm", keyLength:24, ivLength:12 },
{ name: "aes-192-cfb", keyLength:24, ivLength:16 },
{ name: "aes-192-cfb1", keyLength:24, ivLength:16 },
{ name: "aes-192-cfb8", keyLength:24, ivLength:16 },
{ name: "aes-192-ctr", keyLength:24, ivLength:16 },
{ name: "aes-192-ecb", keyLength:24, ivLength:0 },
{ name: "aes-192-gcm", keyLength:24, ivLength:12 },
{ name: "aes-192-ofb", keyLength:24, ivLength:16 },
{ name: "aes-256-cbc", keyLength:32, ivLength:16 },
{ name: "aes-256-cbc-hmac-sha1", keyLength:32, ivLength:16 },
{ name: "aes-256-cbc-hmac-sha256", keyLength:32, ivLength:16 },
{ name: "aes-256-ccm", keyLength:32, ivLength:12 },
{ name: "aes-256-cfb", keyLength:32, ivLength:16 },
{ name: "aes-256-cfb1", keyLength:32, ivLength:16 },
{ name: "aes-256-cfb8", keyLength:32, ivLength:16 },
{ name: "aes-256-ctr", keyLength:32, ivLength:16 },
{ name: "aes-256-ecb", keyLength:32, ivLength:0 },
{ name: "aes-256-gcm", keyLength:32, ivLength:12 },
{ name: "aes-256-ofb", keyLength:32, ivLength:16 },
{ name: "aes-256-xts", keyLength:64, ivLength:16 },
{ name: "aes128", keyLength:16, ivLength:16 },
{ name: "aes192", keyLength:24, ivLength:16 },
{ name: "aes256", keyLength:32, ivLength:16 },
{ name: "bf", keyLength:16, ivLength:8 },
{ name: "bf-cbc", keyLength:16, ivLength:8 },
{ name: "bf-cfb", keyLength:16, ivLength:8 },
{ name: "bf-ecb", keyLength:16, ivLength:0 },
{ name: "bf-ofb", keyLength:16, ivLength:8 },
{ name: "blowfish", keyLength:16, ivLength:8 },
{ name: "camellia-128-cbc", keyLength:16, ivLength:16 },
{ name: "camellia-128-cfb", keyLength:16, ivLength:16 },
{ name: "camellia-128-cfb1", keyLength:16, ivLength:16 },
{ name: "camellia-128-cfb8", keyLength:16, ivLength:16 },
{ name: "camellia-128-ctr", keyLength:16, ivLength:16 },
{ name: "camellia-128-ecb", keyLength:16, ivLength:0 },
{ name: "camellia-128-ofb", keyLength:16, ivLength:16 },
{ name: "camellia-192-cbc", keyLength:24, ivLength:16 },
{ name: "camellia-192-cfb", keyLength:24, ivLength:16 },
{ name: "camellia-192-cfb1", keyLength:24, ivLength:16 },
{ name: "camellia-192-cfb8", keyLength:24, ivLength:16 },
{ name: "camellia-192-ctr", keyLength:24, ivLength:16 },
{ name: "camellia-192-ecb", keyLength:24, ivLength:0 },
{ name: "camellia-192-ofb", keyLength:24, ivLength:16 },
{ name: "camellia-256-cbc", keyLength:32, ivLength:16 },
{ name: "camellia-256-cfb", keyLength:32, ivLength:16 },
{ name: "camellia-256-cfb1", keyLength:32, ivLength:16 },
{ name: "camellia-256-cfb8", keyLength:32, ivLength:16 },
{ name: "camellia-256-ctr", keyLength:32, ivLength:16 },
{ name: "camellia-256-ecb", keyLength:32, ivLength:0 },
{ name: "camellia-256-ofb", keyLength:32, ivLength:16 },
{ name: "camellia128", keyLength:16, ivLength:16 },
{ name: "camellia192", keyLength:24, ivLength:16 },
{ name: "camellia256", keyLength:32, ivLength:16 },
{ name: "cast", keyLength:16, ivLength:8 },
{ name: "cast-cbc", keyLength:16, ivLength:8 },
{ name: "cast5-cbc", keyLength:16, ivLength:8 },
{ name: "cast5-cfb", keyLength:16, ivLength:8 },
{ name: "cast5-ecb", keyLength:16, ivLength:0 },
{ name: "cast5-ofb", keyLength:16, ivLength:8 },
{ name: "des", keyLength:8, ivLength:8 },
{ name: "des-cbc", keyLength:8, ivLength:8 },
{ name: "des-cfb", keyLength:8, ivLength:8 },
{ name: "des-cfb1", keyLength:8, ivLength:8 },
{ name: "des-cfb8", keyLength:8, ivLength:8 },
{ name: "des-ecb", keyLength:8, ivLength:0 },
{ name: "des-ede", keyLength:16, ivLength:0 },
{ name: "des-ede-cbc", keyLength:16, ivLength:8 },
{ name: "des-ede-cfb", keyLength:16, ivLength:8 },
{ name: "des-ede-ofb", keyLength:16, ivLength:8 },
{ name: "des-ede3", keyLength:24, ivLength:0 },
{ name: "des-ede3-cbc", keyLength:24, ivLength:8 },
{ name: "des-ede3-cfb", keyLength:24, ivLength:8 },
{ name: "des-ede3-cfb1", keyLength:24, ivLength:8 },
{ name: "des-ede3-cfb8", keyLength:24, ivLength:8 },
{ name: "des-ede3-ofb", keyLength:24, ivLength:8 },
{ name: "des-ofb", keyLength:8, ivLength:8 },
{ name: "des3", keyLength:24, ivLength:8 },
{ name: "desx", keyLength:24, ivLength:8 },
{ name: "desx-cbc", keyLength:24, ivLength:8 },
{ name: "idea", keyLength:16, ivLength:8 },
{ name: "idea-cbc", keyLength:16, ivLength:8 },
{ name: "idea-cfb", keyLength:16, ivLength:8 },
{ name: "idea-ecb", keyLength:16, ivLength:0 },
{ name: "idea-ofb", keyLength:16, ivLength:8 },
{ name: "rc2", keyLength:16, ivLength:8 },
{ name: "rc2-40-cbc", keyLength:5, ivLength:8 },
{ name: "rc2-64-cbc", keyLength:8, ivLength:8 },
{ name: "rc2-cbc", keyLength:16, ivLength:8 },
{ name: "rc2-cfb", keyLength:16, ivLength:8 },
{ name: "rc2-ecb", keyLength:16, ivLength:0 },
{ name: "rc2-ofb", keyLength:16, ivLength:8 },
{ name: "rc4", keyLength:16, ivLength:0 },
{ name: "rc4-40", keyLength:5, ivLength:0 },
{ name: "rc4-hmac-md5", keyLength:16, ivLength:0 },
{ name: "seed", keyLength:16, ivLength:16 },
{ name: "seed-cbc", keyLength:16, ivLength:16 },
{ name: "seed-cfb", keyLength:16, ivLength:16 },
{ name: "seed-ecb", keyLength:16, ivLength:0 },
{ name: "seed-ofb", keyLength:16, ivLength:16 }
];