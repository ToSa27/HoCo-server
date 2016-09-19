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
//var OAuth2Provider = require('oauth2-provider').OAuth2Provider;

// load config and data
var config = JSON.parse(fs.readFileSync(__dirname + "/config.json"));
var data = {
	dates: {
		"holidays": [],
		"vacation": []
	},
	devices: []
};
try { data = JSON.parse(fs.readFileSync(__dirname + "/data.json")); } catch (err) {}

data.dates = {
	"holidays": [
		1473379200,
		1473811200
	],
	"vacation": [
		{
			"from": 1473033600,
			"to": 1473206400
		}
	]
};

data.devices = {
	"HoCo001": { "name": "light", "node": "HoCo_0C23FA", "device": "LedRed", "property": "on", "type": "onoff", "onvalue": "1", "offvalue": "0", "description": "Deckenleuchte Wohnzimmer" },
        "HoCo002": { "name": "garden", "node": "HoCo_0C23FA", "device": "WaterFlow", "property": "count", "type": "read", "description": "Durchfluss Gartenbewaesserung" }
};

// ensure directories exist
try { fs.mkdirSync(__dirname + '/firmware'); } catch (err) {}
try { fs.mkdirSync(__dirname + '/hwconfig'); } catch (err) {}
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

// logging requests
app.use(logger('dev'));
//app.use(logger(':remote-addr :referrer :method :url :status :response-time ms - :res[content-length]'));

// parsing requests
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.query());
app.use(cookieParser());
app.use(session({store: new MemoryStore({reapInterval: 5 * 60 * 1000}), secret: 'abracadabra', resave: true, saveUninitialized: true}));

// basic authentication handler
app.use(function(req, res, next) {
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
});

// serve static content
app.use('/hoco', express.static(__dirname + '/static'));

// initialize node-red
var redSettings = {
    httpAdminRoot: '/hoco/red',
    httpNodeRoot: '/hoco/redapi',
    userDir: __dirname + '/nodered',
    functionGlobalContext: { }
};
red.init(server, redSettings);
app.use(redSettings.httpAdminRoot, red.httpAdmin);
app.use(redSettings.httpNodeRoot, red.httpNode);

// oauth2 for alexa
/*
var oauthClients = {
	'alexa-skill': 'HoCoClientSecret'
};

var oauthGrants = {};

var oauthProvider = new OAuth2Provider({
	crypt_key: 'encryption secret',
	sign_key: 'signing secret',
	authorize_uri: '/hoco/authorise',
        access_token_uri: '/hoco/token'
});

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
	if(client_id in oauthClients && oauthClients[client_id] == client_secret) {
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
//	next(extra_data, oauth_params);
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

app.use(oauthProvider.oauth());
app.use(oauthProvider.login());

app.get('/hoco/login', function(req, res, next) {
	if(req.session.user) {
		res.writeHead(303, {Location: '/'});
		return res.end();
	}
	var next_url = req.query.next ? req.query.next : '/';
	res.end('<html><form method="post" action="/hoco/login"><input type="hidden" name="next" value="' + next_url + '"><input type="text" placeholder="username" name="username"><input type="password" placeholder="password" name="password"><button type="submit">Login</button></form>');
});

app.post('/hoco/login', function(req, res, next) {
	req.session.user = req.body.username;
	res.writeHead(303, {Location: req.body.next || '/'});
	res.end();
});

app.get('/hoco/logout', function(req, res, next) {
	req.session.destroy(function(err) {
		res.writeHead(303, {Location: '/'});
		res.end();
	});
});
*/

app.get('/hoco/privacypolicy', function (req, res) {
	res.send('this is the hoco Privacy Policy URL placeholder');
});

app.get('/hoco/termsofuse', function (req, res) {
        res.send('this is the hoco Terms of Use URL placeholder');
});

function getAmazonProfile(token, cb) {
	var url = 'https://api.amazon.com/user/profile?access_token=' + token;
	request(url, function(error, response, body) {
		if (response.statusCode == 200)
			cb(JSON.parse(body));
		else
			cb(null);
	});
//	https.get(url, function(res) {
//		if (res.statusCode == 200) {
//			cb(JSON.parse(res.body));
//		} else
//			cb(null);
//	});
}

app.get('/hoco/api/devices', function(req, res, next) {
	var token = req.query.token;
	getAmazonProfile(token, function(profile) {
		console.log('Amazon profile: ' + JSON.stringify(profile));
		if (profile) {
			if (profile.email === config.api.amazonEmail) {
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
				return;
			}
		}
		console.log('send failure');
		res.writeHead(403);
		res.end('{}');
	});
});

app.get('/hoco/api/:applianceId', function(req, res, next) {
        console.log('applianceId: ' + req.params.applianceId);
        console.log('value: ' + req.query.value);
        var token = req.query.token;
        getAmazonProfile(token, function(profile) {
                console.log('Amazon profile: ' + JSON.stringify(profile));
                if (profile) {
                        if (profile.email === config.api.amazonEmail) {
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
                                return;
                        }
                }
                console.log('send failure');
                res.writeHead(403);
                res.end('{}');
        });
});

// save changed data
function dataSave() {
	fs.writeFile(__dirname + "/data.json", JSON.stringify(data), {encoding: 'utf8'}, (err) => {
		if (err)
			console.log('Error writing data');
	});
}

// FOTA file upload and download
function fotaGetFilename(fields) {
	return fields.hw + '_r' + fields.rev + '_' + fields.type + "_v" + fields.major + "." + fields.minor + "-" + fields.build + ".bin";
}

function fotaSetLatest(fields) {
	if (!("firmware" in data))
		data["firmware"] = {};
	var fw = data.firmware;
	if (!(fields.hw in fw))
		fw[fields.hw] = {};
	var hw = fw[fields.hw];
	if (!(fields.rev in hw))
		hw[fields.rev] = {};
	var rev = hw[fields.rev];
	if (!(fields.type in rev))
		rev[fields.type] = {};
	var type = rev[fields.type];
	type["major"] = fields.major;
	type["minor"] = fields.minor;
	type["build"] = fields.build;
	dataSave();
}

function fotaGetLatest(fields) {
	if (!("firmware" in data))
		return null;
	var fw = data.firmware;
	if (!(fields.hw in fw))
		return null;
	var hw = fw[fields.hw];
	if (!(fields.rev in hw))
		return null;
	var rev = hw[fields.rev];
	if (!(fields.type in rev))
		return null;
	var type = rev[fields.type];
	var latestRes = {
		hw: fields.hw,
		rev: fields.rev,
		type: fields.type,
		major: type.major,
		minor: type.minor,
		build: type.build
	};
	return latestRes;
}

function fotaCheckForUpdate(cver, hw, rev, type) {
	var nver = fotaGetLatest({ hw: hw, rev: rev, type: type });
	if (!nver)
		return null;
	if (!cver)
		return nver;
	if (nver.major > cver.major)
		return nver;
	else if (nver.major == cver.major) {
		if (nver.minor > cver.minor)
			return nver;
		else if (nver.minor == cver.minor) {
			if (nver.build > cver.build)
				return nver;
		}
	}
	return null;
}

app.get('/hoco/fota/upload', (req, res) => {
	res.redirect('/fota/upload.html');
});

app.post('/hoco/fota/upload', (req, res) => {
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

app.get('/hoco/fota/download', (req, res) => {
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

// Config
function getConfig(deviceId, hw, rev) {
	console.log("getConfig");
	try {
		var fn = deviceId + '.json';
		var fullfn = __dirname + '/hwconfig/device/' + fn;
		fs.accessSync(fullfn);
		var cs = fs.readFileSync(fullfn, {encoding: 'utf8'});
		var c = JSON.parse(cs);
		console.log("device level config: " + JSON.stringify(c));
		return c;
	} catch (ex) {
		try {
			var fn = hw + '_r' + rev + '.json';
			var fullfn = __dirname + '/hwconfig/hwrev/' + fn;
			fs.accessSync(fullfn);
			var cs = fs.readFileSync(fullfn, {encoding: 'utf8'});
			var c = JSON.parse(cs);
			console.log("hw/rev level config: " + JSON.stringify(c));
			return c;
		} catch (ex) {
			console.log("no config found");
			return null;
		}
	}
}

// MQTT connection
var mqttUrl = config.mqtt.protocol + '://' + config.mqtt.host + ':' + config.mqtt.port;
var mqttConn = mqtt.connect(mqttUrl, { username: config.mqtt.username, password: config.mqtt.password });

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
	var utc = moment.utc();
	var dates = {
		h: [],
		v: {}
	};
	// find next two holiday entries
	data.dates.holidays.sort((a,b) => { return a - b; });
	var c = 0;
	for (var i = 0; i < data.dates.holidays.length; i++) {
		if (data.dates.holidays[i] > Math.floor(utc / 1000)) {
			dates.h.push(data.dates.holidays[i]);
			c++;
			if (c >= 2)
				break;
		}
	}
	// find next vacation entry
	data.dates.vacation.sort((a,b) => { return a.from - b.from; });
	for (var i = 0; i < data.dates.vacation.length; i++) {
		if (data.dates.vacation[i].to > Math.floor(utc / 1000)) {
			dates.v = {
				f: data.dates.vacation[i].from,
				t: data.dates.vacation[i].to
			};
			break;
		}
	}
	mqttPublish('/hoco/$time/$dates', JSON.stringify(dates), true);
}

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
			var hwc = getConfig(deviceId, entries.hw, entries.rev);
			if (hwc)
				mqttPublish("/hoco/" + deviceId + "/$config/$set", JSON.stringify(hwc), false);
		} else if (topicParts[3] == "$fota" && topicParts[4] == "check") {
			var entries = JSON.parse(message);
			if (entries.HARDWARE) {
				var hw = entries.HARDWARE.type;
				var rev = entries.HARDWARE.rev;
				var nver = fotaCheckForUpdate(entries.BOOTLOADER, hw, rev, "BOOTLOADER");
				if (!nver)
					nver = fotaCheckForUpdate(entries.FACTORY, hw, rev, "FACTORY");
					if (!nver)
						nver = fotaCheckForUpdate(entries.FIRMWARE, hw, rev, "FIRMWARE");
				if (nver)
					mqttPublish("/hoco/" + deviceId + "/$fota", JSON.stringify(nver), false);
				else
					mqttPublish("/hoco/" + deviceId + "/$fota", JSON.stringify({ type: "none" }), false);
			}
		}
	}
});

server.listen(config.web.port);
red.start();
console.log("Listening on port " + config.web.port);
