const crypto = require('crypto'), algorithm = 'aes-256-ctr', passie = 'tux.indigo';
var express    = require('express');        // call express
var app        = express();                 // define our app using express

// configure app to use bodyParser()
// this will let us get the data from a POST
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

var port = process.env.PORT || 3000;        // set our port

// ROUTES FOR OUR API
// =============================================================================
var router = express.Router();              // get an instance of the express Router



// Allowed Algorithms and Encoding values
// const allowed_algos = ['sha1','sha224','sha256','sha384','sha512','md4','md5','md5-sha1','ripemd','blake2b512','blake2s256','whirlpool'];
const allowed_algos = crypto.getHashes();
// const allowed_ciphers = crypto.getCiphers();
const allowedCiphers = require('./ciphers.js');
const allowed_encodings = ['base64','hex'];

// test route to make sure everything is working (accessed at GET http://localhost:8080/api)
app.use('/', router);
router.get('/', function(req, res) {
    res.json({ message: 'Welcome to Hashing API', allowedHashAlgos: allowed_algos, allowedEncodings: allowed_encodings, allowedCiphers: allowedCiphers, method: 'Send to /hash with JSON body with variables: "text", "algo", and "enc" with allowed values as strings.' });
});

// more routes for our API will happen here

// REGISTER OUR ROUTES -------------------------------
// all of our routes will be prefixed with /api
// app.use('/api', router);
app.use('/pbkdf2', function(req, res) {
	
	let startTime = process.hrtime()[1];
	let text = req.body.text;
	let salt = req.body.salt;
	let algo = req.body.algo;
	let enc = req.body.enc;
	let iterations = req.body.iterations;
	let keylen = req.body.keylen;
	let msg, timeTaken;
	
	pbkdf2(text, salt, iterations, keylen, algo, enc, function (encryptResponse) {
		if (encryptResponse == false) { 
			msg = 'Unacceptable values Algorithm or Encoding'; timeTaken = process.hrtime()[1] - startTime;
			res.json({message: msg, status: {algorithm: algo, encoding: enc, timeTaken: timeTaken} });
		} else { 
			msg = 'Received and Processed'; timeTaken = encryptResponse.t - startTime;
			res.json({message: msg, status: {algorithm: algo, encoding: enc, timeTaken: timeTaken}, encryptValue: encryptResponse.encValue });
		}
	});
});

app.use('/hash', function(req, res) {
	
	let startTime = process.hrtime()[1];
	let text = req.body.text;
	let algo = req.body.algo;
	let enc = req.body.enc;
	let msg, timeTaken;
	
	let h = hashit(text,algo,enc);
	if (h == false) { msg = 'Unacceptable values Algorithm or Encoding'; timeTaken = process.hrtime()[1] - startTime; }
	else { msg = 'Received and Processed'; timeTaken = h.t - startTime; }
	
	res.json({message: msg, status: {algorithm: algo, encoding: enc, timeTaken: timeTaken}, hashValue: h.hashValue });
});

function hashit(text, algo, enc) {
	let a = allowed_algos.indexOf(algo);
	let e = allowed_encodings.indexOf(enc);
	if (a === -1) { a = false } else {a = true};
	if (e === -1) { e = false } else {e = true};
	
	if (a && e) {
		return {hashValue: crypto.createHash(algo).update(text).digest(enc), t: process.hrtime()[1]};
	} else {
		return false;
	}
}

app.use('/encrypt', function(req, res) {
	
	let startTime = process.hrtime()[1];
	let text = req.body.text;
	let key = req.body.key;
	let algo = req.body.algo;
	let enc = req.body.enc;
	let msg, timeTaken;
	
	encrypt(text, algo, key, enc, (eR) => {
		if (eR.status == false) { 
			msg = 'Unacceptable values Algorithm or Encoding. Or, insufficient length for key or IV.'; timeTaken = process.hrtime()[1] - startTime;
			res.json({message: msg, status: {algorithm: algo, encoding: enc, timeTaken: timeTaken}, cipherRequirements: eR.cipherRequirements });
		} else { 
			msg = 'Received and Processed'; timeTaken = eR.t - startTime;
			res.json({message: msg, status: {algorithm: eR.cipherRequirements, encoding: enc, timeTaken: timeTaken}, encryptedString: { encryptedData: eR.encryptedData, iv: eR.iv } });
		}
	});
});

app.use('/decrypt', function(req, res) {
	
	let startTime = process.hrtime()[1];
	let text = req.body.text;
	let key = req.body.key;
	let algo = req.body.algo;
	let enc = req.body.enc;
	let msg, timeTaken;
	
	decrypt(text, algo, key, enc, (dR) => {
		if (dR.status == false) { 
			msg = 'Unacceptable values Algorithm or Encoding. Or, insufficient length for key or IV.'; timeTaken = process.hrtime()[1] - startTime;
			res.json({message: msg, status: {algorithm: algo, encoding: enc, timeTaken: timeTaken}, cipherRequirements: dR.cipherRequirements });
		} else { 
			msg = 'Received and Processed'; timeTaken = dR.t - startTime;
			res.json({message: msg, status: {algorithm: dR.cipherRequirements, encoding: enc, timeTaken: timeTaken}, decryptedString: dR.decryptedText });
		}
	});
});

function encrypt(text, ciphalgo='aes-256-cbc', key, enc='hex', callback) {
	let i = allowedCiphers.findIndex(x => x.name == ciphalgo);
	let a; let e = allowed_encodings.indexOf(enc);
	let iv = crypto.randomBytes(allowedCiphers[i].ivLength);
	// console.log(`a(${ciphalgo}): ${a}, e(${enc}): ${e}, iv.length: ${iv.length}, key.length: ${key.length}`);
	if (i === -1) { a = false } else {a = true};
	if (e === -1) { e = false } else {e = true};

	if (a && e && key.length == allowedCiphers[i].keyLength) {
		let cipher = crypto.createCipheriv(ciphalgo, Buffer.from(key), iv);
		let encrypted = cipher.update(text);
		encrypted = Buffer.concat([encrypted, cipher.final()]);
		return callback({ status: true, iv: iv.toString(enc), encryptedData: encrypted.toString(enc), t: process.hrtime()[1], cipherRequirements: allowedCiphers[i] });
	} else {
		return callback({status: false, cipherRequirements: allowedCiphers[i] });
	}
}

function decrypt(text, ciphalgo='aes-256-cbc', key, enc='hex', callback) {
	let i = allowedCiphers.findIndex(x => x.name == ciphalgo);
	let a; let e = allowed_encodings.indexOf(enc);
	if (i === -1) { a = false } else {a = true};
	if (e === -1) { e = false } else {e = true};
	let iv = Buffer.from(text.iv, enc);

	if (a && e && key.length == allowedCiphers[i].keyLength && iv.length == allowedCiphers[i].ivLength) {
		let encryptedText = Buffer.from(text.encryptedData, enc);
		let decipher = crypto.createDecipheriv(ciphalgo, Buffer.from(key), iv);
		let decrypted = decipher.update(encryptedText);
		decrypted = Buffer.concat([decrypted, decipher.final()]);
		return callback({decryptedText: decrypted.toString(), t: process.hrtime()[1] });
	} else {
		return callback({status: false, cipherRequirements: allowedCiphers[i] });
	}
}


function pbkdf2(secret, salt='saltie', iterations=2048, keylen=256, algo='sha1', enc='hex', callback) {
	let a = allowed_algos.indexOf(algo);
	let e = allowed_encodings.indexOf(enc);
	let response;
	if (a === -1) { a = false } else {a = true};
	if (e === -1) { e = false } else {e = true};
	if (iterations > 10000 || iterations < 100) iterations = 9999;
	if (keylen > 2048 || keylen < 128) keylen = 256;

	if (a && e) {
		crypto.pbkdf2(secret, salt, iterations, keylen, algo, function(err, key) {
		  if (err)
		    throw err;
		  response = { encValue: key.toString(enc), t: process.hrtime()[1] };
		  callback(response);
		});
	} else {
		return callback(false);
	}
}

// START THE SERVER
// =============================================================================
app.listen(port);
console.log('Script: EnDeCrypt is running on port: ' + port);