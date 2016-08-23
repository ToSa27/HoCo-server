var http = require('http');
var https = require('https');
var basicAuth = require('basic-auth');
var fs = require('fs');
var path = require('path');
var express = require("express");
var formidable = require("formidable");
var mqtt = require('mqtt');
var red = require("node-red");
var moment = require('moment-timezone');

// load config
var config = JSON.parse(fs.readFileSync(__dirname + "/config.json"));

// ensure directories exist
try { fs.mkdirSync(config.ota.bindir); } catch (err) {}

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

// initialize node-red
if (config.web.red.enabled) {
	var redSettings = {
	    httpAdminRoot: config.web.path + config.web.red.uipath,
	    httpNodeRoot: config.web.path + config.web.red.apipath,
	    userDir: config.web.red.datadir,
	    functionGlobalContext: { }
	};
	red.init(server, redSettings);
	if (config.web.red.admin)
		app.use(redSettings.httpAdminRoot, red.httpAdmin);
	if (config.web.red.httpnodes)
		app.use(redSettings.httpNodeRoot, red.httpNode);
}

// other useless stuff
app.get('/favicon.ico', (req, res) => {
	res.sendFile(__dirname + '/favicon.ico');
});

app.get(config.web.path + config.ota.path + '/images/ajax-loader.gif', (req, res) => {
	res.sendFile(__dirname + '/ajax-loader.gif');
});

// OTA file upload and download
function otaGetFilename(fields) {
	return fields.hw + '_r' + fields.rev + '_' + fields.type + "_v" + fields.major + "." + fields.minor + "-" + fields.build + ".bin";
}

function otaGetLatestFilename(fields) {
	return fields.hw + '_r' + fields.rev + '_' + fields.type + ".latest";
}

function otaSetLatest(fields) {
	var fn = otaGetLatestFilename(fields);
	var fullfn = config.ota.bindir + '/' + fn;
	fs.writeFile(fullfn, fields.major + '.' + fields.minor + '.' + fields.build, {encoding: 'utf8'}, (err) => {
		if (err)
			console.log('Error writing file ' + fullfn);
	});
}

function otaGetLatest(fields) {
	var fn = otaGetLatestFilename(fields);
	var fullfn = config.ota.bindir + '/' + fn;
	try {
		fs.accessSync(fullfn);
		var latestStr = fs.readFileSync(fullfn, {encoding: 'utf8'});
		var latestStrs = latestStr.split('.');
		var latestRes = {
			hw: hw,
			rev: rev,
			type: type,
			major: parseInt(latestStrs[0], 10),
			minor: parseInt(latestStrs[1], 10),
			build: parseInt(latestStrs[2], 10)
		};
		return latestRes;
	} catch (ex) {
		return null;
	}
}

function otaCheckForUpdate(cver, hw, rev, type) {
	var nver = otaGetLatest({ hw: hw, rev: rev, type: type });
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

app.get(config.web.path + config.ota.path + '/upload', (req, res) => {
	res.sendFile(__dirname + '/upload.html');
});

app.post(config.web.path + config.ota.path + '/upload', (req, res) => {
	var form = new formidable.IncomingForm();
	form.parse(req, (err, fields, files) => {
		if (err)
			console.log('Parse error: ' + err);
		form.myfields = fields;
		form.myfiles = files;
	});
	form.on('end', function() {
		try {
			var fn = otaGetFilename(form.myfields);
			var source = fs.createReadStream(form.myfiles.upload.path);
			var dest = fs.createWriteStream(config.ota.bindir + '/' + fn);
			source.pipe(dest);
			source.on('end', function() {
				otaSetLatest(form.myfields);
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

app.get(config.web.path + config.ota.path + '/download', (req, res) => {
	var fn = otaGetFilename(req.query);
	var fullfn = config.ota.bindir + '/' + fn;
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
	var off = moment.tz.zone(config.Timezone).offset(utc);
	mqttPublish('/hang/$time', Math.floor(utc / 1000).toString() + '/' + (off * 60).toString(), false);
}

mqttConn.on('error', (err) => {
	console.log('MQTT error: ' + err);
	clearInterval(publishTimeInterval);
});

mqttConn.on('connect', () => {
	console.log('MQTT connected');
	mqttConn.subscribe('/hang/+/$ota/check');
	mqttConn.subscribe('/hang/+/$time');
	publishTimeInterval = setInterval(() => {
		mqttPublishTime();
	}, config.PublishTimeInterval * 1000);	
});

mqttConn.on('message', (topic, message) => {
	console.log('MQTT received');
	console.log('topic: ' + topic);
	console.log('data: ' + message);
	var topicParts = topic.split('/');
	if (topicParts[1] != "hang")
		return;
	if (topicParts[2].lastIndexOf("$", 0) != 0) {
		var deviceId = topicParts[2];
		if (topicParts[3] == "$time")
			mqttPublishTime();
		else if (topicParts[3] == "$ota" && topicParts[4] == "check") {
			var entries = JSON.parse(message);
			if (entries.HARDWARE) {
				var hw = entries.HARDWARE.type;
				var rev = entries.HARDWARE.rev;
				var nver = otaCheckForUpdate(entries.BOOTLOADER, hw, rev, "BOOTLOADER");
				if (!nver)
					nver = otaCheckForUpdate(entries.FACTORY, hw, rev, "FACTORY");
					if (!nver)
						nver = otaCheckForUpdate(entries.FIRMWARE, hw, rev, "FIRMWARE");
				if (nver)
					mqttPublish("/hang/" + deviceId + "/$ota", JSON.stringify(nver), false);
			}
		}
	}
});

server.listen(config.web.port);
if (config.web.red.enabled)
	red.start();
console.log("Listening on port " + config.web.port);
