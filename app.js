var http = require('http');
var https = require('https');
var basicAuth = require('basic-auth');
var fs = require('fs');
var path = require('path');
var express = require("express");
var session = require("express-session");
var MemoryStore = session.MemoryStore;
var bodyParser = require("body-parser");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
var formidable = require("formidable");
var mqtt = require('mqtt');
var red = require("node-red");
var moment = require('moment-timezone');
var request = require('request');
var OAuth2Provider = require('oauth2-provider').OAuth2Provider;
var mysql = require('mysql');

// load config
var config = JSON.parse(fs.readFileSync(__dirname + "/config.json"));

// connect to database
var dbpool = mysql.createPool({
	connectionLimit: 100,
	host: config.database.host,
	user: config.database.username,
	password: config.database.password,
	database: config.database.database,
	debug: false
});

// ensure directories exist
try { fs.mkdirSync(__dirname + '/firmware'); } catch (err) {}
try { fs.mkdirSync(__dirname + '/nodered'); } catch (err) {}

// create express app and server
var app = express();
var server;
if (config.web.ssl.enabled) {
	var certs = {
		key: fs.readFileSync(config.web.ssl.keyfile),
		cert: fs.readFileSync(config.web.ssl.certfile)
	};
	server = https.createServer(certs, app);
} else {
	server = http.createServer(app);
}

// create express app and server for (unencrypted) FOTA download
var fotaApp = express();
var fotaServer = http.createServer(fotaApp);

// logging incoming requests
app.use(logger('dev'));
fotaApp.use(logger('dev'));
//app.use(logger(':remote-addr :referrer :method :url :status :response-time ms - :res[content-length]'));

// global request parsing and session handling
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.query());
app.use(cookieParser());
app.use(session({store: new MemoryStore({reapInterval: 5 * 60 * 1000}), secret: 'abracadabra', resave: true, saveUninitialized: true}));

// serve static content
app.use('/hoco', express.static(__dirname + '/static'));

// basic authentication handler
function checkBasicAuth(req, res, next) {
    function unauthorized(res) {
        res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
        return res.sendStatus(401);
    };
    if (!config.web.auth.basic)
        next();
    else {
        var user = basicAuth(req);
        if (!user || !user.name || !user.pass)
            return unauthorized(res);
        if (user.name == config.web.auth.username && user.pass == config.web.auth.password) {
            req.validuser = user.name;
            next();
        } else
            return unauthorized(res);
    }
}

// login with amazon oauth provider for alexa
function getAmazonProfile(token, cb) {
	var url = 'https://api.amazon.com/user/profile?access_token=' + token;
	request(url, function(error, response, body) {
		if (response.statusCode == 200)
			cb(JSON.parse(body));
		else
			cb(null);
	});
}

function checkAmazonAuth(req, res, next) {
	var token = req.query.token;
        getAmazonProfile(token, function(profile) {
                if (profile) {
                        if (profile.email === config.api.amazonEmail) {
				next();
				return;
			}
		}
	        res.writeHead(403);
	        res.end('{}');
	});
}

// local oauth2 provider for alexa
var oauthGrants = {};
var oauthProvider = new OAuth2Provider(config.api.localOAuthOptions);

oauthProvider.on('enforce_login', function(req, res, authorize_url, next) {
	console.log("oauthProvider.on enforce_login");
	if(req.session.user) {
		next(req.session.user);
	} else {
		res.writeHead(303, {Location: '/hoco/login?next=' + encodeURIComponent(authorize_url)});
		res.end();
	}
});

oauthProvider.on('authorize_form', function(req, res, client_id, authorize_url) {
	console.log("oauthProvider.on authorize_form");
	res.end('<html>this app wants to access your account... <form method="post" action="' + authorize_url + '"><button name="allow">Allow</button><button name="deny">Deny</button></form>');
});

oauthProvider.on('save_grant', function(req, client_id, code, next) {
	console.log("oauthProvider.on save_grant");
	if(!(req.session.user in oauthGrants))
		oauthGrants[req.session.user] = {};
	oauthGrants[req.session.user][client_id] = code;
	next();
});

oauthProvider.on('remove_grant', function(user_id, client_id, code) {
	console.log("oauthProvider.on remove_grant");
	if(oauthGrants[user_id] && oauthGrants[user_id][client_id])
		delete oauthGrants[user_id][client_id];
});

oauthProvider.on('lookup_grant', function(client_id, client_secret, code, next) {
	console.log("oauthProvider.on lookup_grant");
	if(client_id in config.api.localOAuthClients && config.api.localOAuthClients[client_id] == client_secret) {
		for(var user in oauthGrants) {
			var clients = oauthGrants[user];
			if(clients[client_id] && clients[client_id] == code)
				return next(null, user);
		}
	}
	next(new Error('no such grant found'));
});

oauthProvider.on('create_access_token', function(user_id, client_id, next) {
	console.log("oauthProvider.on create_access_token");
	var extra_data = 'blah'; // can be any data type or null
	//var oauth_params = {token_type: 'bearer'};
	//next(extra_data, oauth_params);
	next(extra_data);
});

oauthProvider.on('save_access_token', function(user_id, client_id, access_token) {
	console.log("oauthProvider.on save_access_token");
	console.log('saving access token %s for user_id=%s client_id=%s', JSON.stringify(access_token), user_id, client_id);
});

oauthProvider.on('access_token', function(req, token, next) {
	console.log("oauthProvider.on access_token");
	var TOKEN_TTL = 10 * 60 * 1000; // 10 minutes
	if(token.grant_date.getTime() + TOKEN_TTL > Date.now()) {
		req.session.user = token.user_id;
		req.session.data = token.extra_data;
	} else {
		console.warn('access token for user %s has expired', token.user_id);
	}
	next();
});

oauthProvider.on('client_auth', function(client_id, client_secret, username, password, next) {
	console.log("oauthProvider.on client_auth");
	if(client_id == 'alexa_skill' && username == 'hoco') {
		var user_id = '1337';
		return next(null, user_id);
	}
	return next(new Error('client authentication denied'));
});

//app.use(oauthProvider.oauth());
//app.use(oauthProvider.login());

app.get('/hoco/login', function(req, res, next) {
	if(req.session.user) {
		res.writeHead(303, {Location: '/'});
		return res.end();
	}
	var next_url = req.query.next ? req.query.next : '/';
	res.end('<html><form method="post" action="/hoco/login"><input type="hidden" name="next" value="' + next_url + '"><input type="text" placeholder="username" name="username"><input type="password" placeholder="password" name="password"><button type="submit">Login</button></form>');
});

app.post('/hoco/login', function(req, res, next) {
	if (req.body.username in config.api.localOAuthCredentials && config.api.localOAuthCredentials[req.body.username] == req.body.password) {
		req.session.user = req.body.username;
		res.writeHead(303, {Location: req.body.next || '/'});
		res.end();
	} else {
		res.writeHead(401);
		res.end("Access Denied");
	}
});

app.get('/hoco/logout', function(req, res, next) {
	req.session.destroy(function(err) {
		res.writeHead(303, {Location: '/'});
		res.end();
	});
});

function checkLocalOAuth(req, res, next) {
	oauthProvider.oauth()(req, res, oauthProvider.login()(req, res,next));
}

// oauth2 dispatcher (local or amazon)
function checkOAuth(req, res, next) {
	if (config.api.loginWithAmazon) {
		checkAmazonAuth(req, res, next);
	} else if (config.api.localOAuth) {
		checkLocalOAuth(req, res, next);
	} else {
		next();
	}
}

// api for alexa discovery
app.get('/hoco/api/devices', checkOAuth, function(req, res, next) {
	devices = [];
	Object.keys(data.devices).forEach(function(key) {
		var val = data.devices[key];
		var actions = [];
		if (val.type === 'onoff') {
			actions.push("turnOn");
                        actions.push("turnOff");
		}
		var device = {
                        "applianceId": key,
                        "manufacturerName": "HoCo",
                        "modelName": "Virtual Node:Device Combination",
                        "version": "1.1",
                        "friendlyName": val.name,
                        "friendlyDescription": val.description,
                        "isReachable": true,
                        "actions": actions,
                        "additionalApplianceDetails": {
                        }
		};
		devices.push(device);
	});
	console.log('send result');
	res.end(JSON.stringify(devices));
});

// api for alexa control
app.get('/hoco/api/:applianceId', checkOAuth, function(req, res, next) {
        console.log('applianceId: ' + req.params.applianceId);
        console.log('value: ' + req.query.value);
	var device = data.devices[req.params.applianceId];
	if (device.type === "onoff") {
		var val;
		if (req.query.value === "on")
			val = device.onvalue;
                if (req.query.value === "off")
                        val = device.offvalue;
		if (val)
			mqttPublish('/hoco/' + device.node + '/' + device.device + '/' + device.property + '/$set', val, false);
	}
        console.log('send result');
        response = {
        };
        res.end(JSON.stringify(response));
});

// FOTA helper functions
function fotaGetFilename(fields) {
	return fields.hw + '_r' + fields.rev + '_' + fields.type + "_v" + fields.major + "." + fields.minor + "-" + fields.build + ".bin";
}

function fotaSetLatest(fields) {
	dbpool.query('INSERT INTO firmware SET hwtype = ?, hwrev = ?, fwtype = ?, major = ?, minor = ?, build = ?', [fields.hw, fields.rev, fields.type, fields.major, fields.minor, fields.build], function(err, rows, fields) {
		if (err)
			console.log("Error in fotaSetLatest: " + err);
	});
}

function fotaGetLatest(fields, cb) {
	dbpool.query('SELECT major, minor, build FROM firmware WHERE hwtype = ? AND hwrev = ? AND fwtype = ? ORDER BY major DESC, minor DESC, build DESC LIMIT 1', [fields.hw, fields.rev, fields.type], function(err, rows, fields) {
		if (err) {
			console.log("Error in fotaGetLatest: " + err);
			cb(null);
		} else if (rows.length > 0) {
	        	var latestRes = {
        	        	hw: fields.hw,
       		        	rev: fields.rev,
       		        	type: fields.type,
       	        		major: rows[0].major,
       	        		minor: rows[0].minor,
				build: rows[0].build
			};
			cb(latestRes);
		} else {
			cb(null);
		}
	});
}

function fotaCheckForUpdate(cver, hw, rev, type, cb) {
	fotaGetLatest({ hw: hw, rev: rev, type: type }, function(nver) {
		if (!nver)
			cb(null);
		else if (!cver)
			cb(nver);
		else if (nver.major > cver.major)
			cb(nver);
		else if (nver.major == cver.major) {
			if (nver.minor > cver.minor)
				cb(nver);
			else if (nver.minor == cver.minor) {
				if (nver.build > cver.build)
					cb(nver);
				else
					cb(null);
			}
		} else {
			cb(null);
		}
	});
}

// FOTA file upload
app.get('/hoco/fota/upload', checkBasicAuth, (req, res) => {
	res.redirect('/hoco/fota/upload.html');
});

app.post('/hoco/fota/upload', checkBasicAuth, (req, res) => {
	var form = new formidable.IncomingForm();
	form.parse(req, (err, fields, files) => {
		if (err)
			console.log('Parse error: ' + err);
		form.myfields = fields;
		form.myfiles = files;
	});
	form.on('end', function() {
		try {
			var fn = fotaGetFilename(form.myfields);
			var source = fs.createReadStream(form.myfiles.upload.path);
			var dest = fs.createWriteStream(__dirname + '/firmware/' + fn);
			source.pipe(dest);
			source.on('end', function() {
				fotaSetLatest(form.myfields);
				res.writeHead(200);
				res.end();
				console.log('Uploaded ' + fn);
			});
			source.on('error', function(err) {
				res.writeHead(500);
				res.end();
				console.log('Error writing file ' + fn);
			});
		} catch (err) {
			console.log("Move error: " + err);
		}
	});
});

// FOTA file download (unencrypted port)
fotaApp.get('/hoco/fota/download', checkBasicAuth, (req, res) => {
	var fn = fotaGetFilename(req.query);
	var fullfn = __dirname + '/firmware/' + fn;
	fs.access(fullfn, (err) => {
		if (err) {
			res.writeHead(404);
			res.end();
		} else {
			res.sendFile(fullfn);
			console.log('Downloaded ' + fn);
		}
	});
});

// node config helper
function getConfig(deviceId, hw, rev, cb) {
	console.log("getConfig");
	dbpool.query('SELECT name, type, config FROM device WHERE nodeid = ? ORDER BY sequence, name', [deviceId], function(err, rows, fields) {
		if (err) {
			console.log("Error in fotaGetLatest: " + err);
			return;
		}
		var c = { d: [] };
		for (var i = 0; i < rows.length; i++) {
			d.push({
				t: rows[i].type,
				n: rows[i].name,
				c: JSON.parse(rows[i].config)
			});
		}
		cb(c);
	});
}

// MQTT connection
var mqttUrl = config.mqtt.protocol + '://' + config.mqtt.host + ':' + config.mqtt.port;
var mqttConn = mqtt.connect(mqttUrl, { username: config.mqtt.username, password: config.mqtt.password });
var mqttLogConn = mqtt.connect(mqttUrl, { username: config.mqtt.username, password: config.mqtt.password });

mqttLogConn.on('connect', () => {
        mqttLogConn.subscribe('/hoco/#');
});

mqttLogConn.on('message', (topic, message) => {
	var topicParts = topic.split('/');
	if (topicParts[1] != "hoco")
		return;
	if (topicParts[2].lastIndexOf("$", 0) != 0) {
		var nodeid = topicParts[2];
		var devicename = '';
		var property = '';
		var command = '';
		if (topicParts[3].lastIndexOf("$", 0) == 0) {
			command = topicParts[3];
		} else if (topicParts[4].lastIndexOf("$", 0) == 0) {
			devicename = topicParts[3];
			command = topicParts[4];
		} else if (topicParts[5].lastIndexOf("$", 0) == 0) {
			devicename = topicParts[3];
			property = topicParts[4];
			command = topicParts[5];
		}
		dbpool.query('INSERT INTO mqttlog SET ts = NOW(), ?', {nodeid: nodeid, devicename: devicename, property: property, command: command, message: message}, function(err, result) {
				conn.release();
				if (err)
					console.log("error writing to database");
			});
		});
	}
});

mqttConn.on('error', (err) => {
	console.log('MQTT error: ' + err);
	clearInterval(publishTimeInterval);
});

mqttConn.on('connect', () => {
	console.log('MQTT connected');
	mqttConn.subscribe('/hoco/+/$fota/check');
	mqttConn.subscribe('/hoco/+/$config');
	mqttConn.subscribe('/hoco/+/$time');
	publishTimeInterval = setInterval(() => {
		mqttPublishTime();
	}, config.time.publish * 1000);	
	mqttPublishTimezone();
	mqttPublishDates();
});

mqttConn.on('message', (topic, message) => {
	console.log('MQTT received');
	console.log('topic: ' + topic);
	console.log('data: ' + message);
	var topicParts = topic.split('/');
	if (topicParts[1] != "hoco")
		return;
	if (topicParts[2].lastIndexOf("$", 0) != 0) {
		var deviceId = topicParts[2];
		if (topicParts[3] == "$time") {
			mqttPublishTime();
		} else if (topicParts[3] == "$config" && topicParts.length == 4) {
			var entries = JSON.parse(message);
			getConfig(deviceId, entries.hw, entries.rev, function(hwc) {
				mqttPublish("/hoco/" + deviceId + "/$config/$set", JSON.stringify(hwc), false);
			});
		} else if (topicParts[3] == "$fota" && topicParts[4] == "check") {
			var entries = JSON.parse(message);
			if (entries.HARDWARE) {
				var hw = entries.HARDWARE.type;
				var rev = entries.HARDWARE.rev;
				fotaCheckForUpdate(entries.BOOTLOADER, hw, rev, "BOOTLOADER", function(nver) {
					if (nver)
						mqttPublish("/hoco/" + deviceId + "/$fota", JSON.stringify(nver), false);
					else {
						fotaCheckForUpdate(entries.FACTORY, hw, rev, "FACTORY", function(nver) {
				 			if (nver)
								mqttPublish("/hoco/" + deviceId + "/$fota", JSON.stringify(nver), false);
							else {
								fotaCheckForUpdate(entries.FIRMWARE, hw, rev, "FIRMWARE", function(nver) {
									if (nver)
										mqttPublish("/hoco/" + deviceId + "/$fota", JSON.stringify(nver), false);
									else
										mqttPublish("/hoco/" + deviceId + "/$fota", JSON.stringify({ type: "none" }), false);
								});
							}
						});
					}
				});
			}
		}
	}
});

// MQTT helper
function mqttPublish(topic, message, retain) {
	console.log('MQTT publishing');
	console.log('topic: ' + topic);
	console.log('data: ' + message);
	mqttConn.publish(topic, message, { qos: 0, retain: retain ? 1 : 0 });
}

var publishTimeInterval;

function mqttPublishTime() {
	var utc = moment.utc();
	mqttPublish('/hoco/$time/$epoch', Math.floor(utc / 1000).toString(), false);
}

function mqttPublishTimezone() {
	var utc = moment.utc();
	var off = -moment.tz.zone(config.time.timezone).offset(utc);
	mqttPublish('/hoco/$time/$zone', (off * 60).toString(), true);
}

function mqttPublishDates() {
	var dates = {
		h: [],
		v: {}
	};
	dbpool.query('SELECT day FROM holiday WHERE day > ? ORDER BY day LIMIT 2', [moment.tz(config.time.timezone).format("YYYY-MM-DD")], function(err, rows, fields) {
		if (err) {
			console.log("Error in mqttPublishDates: " + err);
			return;
		}
		for (var i = 0; i < rows.length; i++)
			dates.h.push(moment(rows[i].day).tz(config.time.timezone).unix());
	        dbpool.query('SELECT first, last FROM vacation WHERE last > ? ORDER BY first LIMIT 1', [moment.tz(config.time.timezone).format("YYYY-MM-DD")], function(err, rows, fields) {
	                if (err) {
	                        console.log("Error in mqttPublishDates: " + err);
	                        return;
	                }
	                if (rows.length > 0) {
	                        dates.v = {
	                                f: moment(rows[0].first).tz(config.time.timezone).unix(),
	                                t: moment(rows[0].last).tz(config.time.timezone).unix()
	                        };
	                }
		        mqttPublish('/hoco/$time/$dates', JSON.stringify(dates), true);	
	        });
	});
}

// other mandatory pages
app.get('/hoco/privacypolicy', function (req, res) {
	res.send('this is the hoco Privacy Policy URL placeholder');
});

app.get('/hoco/termsofuse', function (req, res) {
        res.send('this is the hoco Terms of Use URL placeholder');
});

// initialize node-red
var redSettings = {
    httpAdminRoot: '/hoco/red',
    httpNodeRoot: '/hoco/redapi',
    userDir: __dirname + '/nodered',
    functionGlobalContext: { }
};
red.init(server, redSettings);
app.use(redSettings.httpAdminRoot, checkBasicAuth, red.httpAdmin);
app.use(redSettings.httpNodeRoot, checkBasicAuth, red.httpNode);

// start listening
server.listen(config.web.port);
//red.start();
console.log("Web listening on port " + config.web.port);
fotaServer.listen(config.web.fotaPort);
console.log("FOTA listening on port " + config.web.fotaPort);
