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

// load config and data
var config = JSON.parse(fs.readFileSync(__dirname + "/config.json"));
var data = JSON.parse(fs.readFileSync(__dirname + "/data.json"));

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

//function fotaGetLatestFilename(fields) {
//	return fields.hw + '_r' + fields.rev + '_' + fields.type + ".latest";
//}

function fotaSetLatest(fields) {
	if (!("firmware" in data))
		data.set("firmware", {});
	var fw = data.firmware;
	if (!(fields.hw in fw))
		fw.set(fields.hw, {});
	var hw = fw.get(fields.hw);
	if (!(fields.rev in hw))
		hw.set(fields.rev, {});
	var rev = hw.get(fields.rev);
	if (!(fields.type in rev))
		rev.set(fields.type, {});
	var type = rev.get(fields.type);
	type.set("major", fields.major);
	type.set("minor", fields.minor);
	type.set("build", fields.build);
	dataSave();
//	var fn = fotaGetLatestFilename(fields);
//	var fullfn = __dirname + '/firmware/' + fn;
//	fs.writeFile(fullfn, fields.major + '.' + fields.minor + '.' + fields.build, {encoding: 'utf8'}, (err) => {
//		if (err)
//			console.log('Error writing file ' + fullfn);
//	});
}

function fotaGetLatest(fields) {
	if (!("firmware" in data))
		return null;
	var fw = data.firmware;
	if (!(fields.hw in fw))
		return null;
	var hw = fw.get(fields.hw);
	if (!(fields.rev in hw))
		return null;
	var rev = hw.get(fields.rev);
	if (!(fields.type in rev))
		return null;
	var type = rev.get(fields.type);
	var latestRes = {
		hw: fields.hw,
		rev: fields.rev,
		type: fields.type,
		major: type.major,
		minor: type.minor,
		build: type.build
	};
	return latestRes;
//	var fn = fotaGetLatestFilename(fields);
//	var fullfn = __dirname + '/firmware/' + fn;
//	try {
//		fs.accessSync(fullfn);
//		var latestStr = fs.readFileSync(fullfn, {encoding: 'utf8'});
//		var latestStrs = latestStr.split('.');
//		var latestRes = {
//			hw: fields.hw,
//			rev: fields.rev,
//			type: fields.type,
//			major: parseInt(latestStrs[0], 10),
//			minor: parseInt(latestStrs[1], 10),
//			build: parseInt(latestStrs[2], 10)
//		};
//		return latestRes;
//	} catch (ex) {
//		return null;
//	}
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
//	var fn = deviceId + '.json';
	var fn = hw + '_r' + rev + '.json';
	var fullfn = __dirname + '/hwconfig/' + fn;
	try {
		fs.accessSync(fullfn);
		var cs = fs.readFileSync(fullfn, {encoding: 'utf8'});
		var c = JSON.parse(cs);
		console.log("c: " + JSON.stringify(c));
		return c;
	} catch (ex) {
		return null;
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
	var off = -moment.tz.zone(config.time.timezone).offset(utc);
	mqttPublish('/hoco/$time', Math.floor(utc / 1000).toString() + '/' + (off * 60).toString(), false);
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
			dates.v = data.dates.vacation[i];
			break;
		}
	}
	mqttPublish('/hoco/$dates', JSON.stringify(dates), true);
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
