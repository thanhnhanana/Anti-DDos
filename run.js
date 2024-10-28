const express = require('express')
const http2 = require("http2")
const path = require("path")
const rateLimit = require("express-rate-limit")
const helmet = require("helmet")
const slowDown = require('express-slow-down')
const https = require("https")
const tls = require("tls")
const crypto = require("crypto")
const app = express()
const ua = ["POLARIS", "Python-urllib", "SonyEricssonK550i", "BlackBerry9000"]
const redis = new Map()
const tracking = {}
const tracking2 = {}
let bypass = 0
let block_rate = 0
let block_slow = 0
let anti_mutiplexing = 0
let block = 0
let bad_header = 0
let bad_useragent = 0
let block_memory = 0
let miss_header = 0
let block_botnet = 0
let anti_query = 0
let bad_method = 0
let bad_connect = 0
let uni_ua = 0
let uni_lang = 0
let bad_req = 0
const limitSlow = rateLimit({
        windowMs: 1000,
        max: 9,
        message: "Forder 403 - Rate limit!",
        standardHeaders: false,
        legacyHeaders: false,
        handler: (req, res, next, options) => {
		block_slow +=1
                console.log(`Ratelimit slow ip ${req.ip}`)
                redis.set(req.ip, Date.now() + 1800 * 1000)
                res.status(403).send("You are speed limited!")
		res.socket.destroy()
        },
        skipFailedRequests: false,
        skipSuccessfulRequests: false,
})
const limit = rateLimit({
        windowMs: 800,
        max: 7,
        message: "Forder 403 - Rate limit!",
        standardHeaders: false,
        legacyHeaders: false,
        handler: (req, res, next, options) => {
		block_rate +=1
		console.log(`Ratelimit ip ${req.ip}`)
		redis.set(req.ip, Date.now() + 1800 * 1000)
		res.status(403).send("You are speed limited!")
		res.socket.destroy()
        },
        skipFailedRequests: false,
        skipSuccessfulRequests: false,
})
const antiMutiplexing = rateLimit({
        windowMs: 300,
        max: 2,
        message: "Forder 403 - Detect unusual behavior!!!",
        standardHeaders: false,
        legacyHeaders: false,
        handler: (req, res, next, options) => {
		anti_mutiplexing +=1
		console.log(`Anti mutiplexing ip ${req.ip}`)
		redis.set(req.ip, Date.now() + 1800 * 1000)
		res.status(403).send("Anti mutiplexing!")
		res.socket.destroy()
        },
        skipFailedRequests: false,
        skipSuccessfulRequests: false,
})
const slow = slowDown({
	windowMs: 30 * 60 * 1000,
	delayAfter: 2000,
	delayMs: () => 9000,
})
app.use(limitSlow)
app.set("trust proxy", true)
app.use(slow)
app.use(antiMutiplexing)
app.use(limit)
app.use(helmet())
let vaild = 0
app.use(async (req, res, next) => {
	req.on("aborted", () => {
		redis.set(req.ip, Date.now() + 1800 * 1000)
	})
	console.log(req.ip)
	const isBlock = redis.get(req.ip)
	if (isBlock && Date.now() < isBlock) {
		console.log(`Blocked IP: ${req.ip}`)
		res.status(403).send(`BlockedIP - IP ${req.ip}`)
		return res.socket.destroy()
	}
	try {
		if (req.headers["user-agent"].includes(ua)) {
			bad_useragent +=1
			console.log(`403 useragent ip ${req.ip}`)
			res.status(403).send("Useragent sucks and is garbage!")
			return res.socket.destroy()
		}
		if (!req.headers["user-agent"].includes("Mozilla/5.0", "Safari")) {
			bad_useragent +=1
			console.log(`403 useragent ip ${req.ip} | Mozila 5.0`)
			res.status(403).send("Useragent sucks and is garbage!")
			return res.socket.destroy()
		}
		if (Object.keys(req.query).length > 0) {
			anti_query +=1
			console.log(`403 query ip ${req.ip}`)
			return res.status(403).send("403 - Query not allowed!")
		}
        	if (req.headers['user-agent'] && req.headers['user-agent'].includes('curl')) {
			console.log(`403 curl ip ${req.ip}`)
                	res.status(403).send("Your request was not accepted!")
               	 	return
        	}
	} catch {
		console.log(`Unusual browser is not reliable ip ${req.ip}`)
		return res.status(403).send("Unusual connection is not reliable!")
	}
	if (!req.method.toLowerCase().includes("get", "post")) {
		console.log(req.method)
		bad_method +=1
		console.log(`403 bad method ip ${req.ip}`)
		res.status(403).send("Detect browsers using methods with unusual behavior!!!")
		return
	}
	const ip = req.ip
	const ugent = req.headers["user-agent"]
	const now = Date.now()
	if (!tracking[ip]) {
		tracking[ip] = [];
	}
	tracking[ip].push({ ugent, time: now })
	tracking[ip] = tracking[ip].filter(entry => now - entry.time <= 2000)
	if (tracking[ip].length >= 4) {
		const all = tracking[ip].every(entry => entry.ugent === ugent);
		if (!all) {
			console.log(`Unusual Useragent detected for IP: ${req.ip}`);
			uni_ua += 1;
			res.status(403).send("Detected abnormal user-agent!");
			redis.set(req.ip, Date.now() + 1800 * 1000)
        		return
		}
	}
	if (tracking[ip].length === 0) {
		delete tracking[ip];
	}
	const lang = req.headers["accept-language"]
        if (!tracking2[ip]) {
                tracking2[ip] = [];
        }
        tracking2[ip].push({ lang, time: now })
        tracking2[ip] = tracking2[ip].filter(entry => now - entry.time <= 2000)
        if (tracking2[ip].length >= 4) {
                const all = tracking2[ip].every(entry => entry.lang === lang);
                if (!all) {
                        console.log(`Unusual Accept language detected for IP: ${req.ip}`);
                        uni_lang += 1;
                        res.status(403).send("Detected abnormal accept-language!");
                        redis.set(req.ip, Date.now() + 1800 * 1000)
                        return
                }
        }
        if (tracking2[ip].length === 0) {
                delete tracking2[ip];
        }
	if (req.headers["host"]) vaild++
	if (req.headers["sec-ch-ua"]) vaild++
	if (req.headers["sec-ch-ua-mobile"]) vaild++
	if (req.headers["user-agent"]) vaild++
	if (req.headers["sec-ch-ua-platform"]) vaild++
	if (req.headers["accept"]) vaild++
	if (req.headers["sec-fetch-site"]) vaild++
	if (req.headers["sec-fetch-mode"]) vaild++
	if (req.headers["sec-fetch-dest"]) vaild++
	if (req.headers["accept-encoding"]) vaild++
	if (req.headers["accept-language"]) vaild++
	if (req.headers["cookie"]) vaild++
	if (vaild < 9) {
		let rate_ua = 0
		if (req.headers["user-agent"].toLowerCase().includes("safari")) rate_ua++
		if (req.headers["user-agent"].toLowerCase().includes("iphone")) rate_ua++
		if (req.headers["user-agent"].toLowerCase().includes("mac os x")) rate_ua++
		if (req.headers["user-agent"].toLowerCase().includes("cpu iphone os")) rate_ua++
		if (rate_ua > 2) {
			rate_ua = 0
			console.log(`Rate useragent iphone ip ${req.ip}`)
			return next()
		}
		vaild = 0
		miss_header +=1
		console.log(`403 miss header ip ${req.ip}`)
		res.status(403).send("Your browser is missing a header!")
		return
	}
        if (req.headers["from-unknown-botnet"]) {
		block_botnet +=1
		console.log(`403 botnet ip ${req.ip}`)
                res.status(403).send("Reject machines related to botnets!")
                return
        }
        if (req.headers["bypassmemory"]) {
		block_memory +=1
		console.log(`403 bypass memory ip ${req.ip}`)
                res.status(403).send("Reject machine with bypass memory header!")
                return
        }
        if (req.headers["service-worker-navigation-preload"] || req.headers["delta-base"] || req.headers["if-math"] || req.headers["if-range"] || req.headers["source-ip"] || req.headers["vary"] || req.headers["data-return"] || req.headers["a-im"]) {
		bad_header +=1
		console.log(`403 patch ip ${req.ip}`)
                res.status(403).send("Your header or browser does not meet our website's criteria!")
                return
        }
	if (res.statusCode !== 403) {
		vaild = 0
		bypass +=1
		console.log(`Bypass successfully request ${req.ip}`)
	}
	if (!req.headers.connection) {
		bad_connect +=1
		console.log(`403 bad connect ip ${req.ip}`)
		res.status(403).send("Unusual connection!")
		return
	}
	if (
		req.headers["te"] ||
		req.headers["vary"] ||
		req.headers["via"] ||
		req.headers["sss"] ||
		req.headers["upgrade"] ||
		req.headers["x-https"] ||
		req.headers["real-ip"] ||
		req.headers["client-ip"] ||
		req.headers["alt-svc"] ||
		req.headers["x-requested-with"] ||
		req.headers["strict-transport-security"] ||
		req.headers["x-xss-protection"] ||
		req.headers["x-content-type-options"] ||
		req.headers["referrer-policy"] ||
		req.headers["cross-origin-opener-policy"] ||
		req.headers["cross-origin-embedder-policy"] ||
		req.headers["x-download-options"] ||
		req.headers["access-control-allow-origin"] ||
		req.headers["no-vary-search"] ||
		req.headers["timing-allow-origin"] ||
		req.headers["expect-ct"] ||
		req.headers["supports-loading-mode"] ||
		req.headers["nel"] ||
		req.headers["x-https"] ||
		req.headers["x-custom-header1"] ||
		req.headers["x-custom-header2"] ||
		req.headers["x-content-duration"] ||
		req.headers["x-vercel-cache"] ||
		req.headers["tk"] ||
		req.headers["x-asp-net"] ||
		req.headers["from"] ||
		req.headers["expect"] ||
		req.headers["x-real-ip"] ||
		req.headers["sec-ch-ua-wow64"] ||
		req.headers["sec-ch-ua-model"] ||
		req.headers["rtt"] ||
		req.headers["downlink"] ||
		req.headers["sec-purpose"] ||
		req.headers["content-disposition"]
	) {
		bad_req +=1
		console.log(`403 unusual header ip ${req.ip}`)
		res.status(403).send("Your header is not trusted by our firewall!!!")
		return
	}
        next()
})
//app.get('/', (req, res) => {
  //console.log(`Successfully IP ${req.ip}`)
 // res.send('<h1>Hello from Express with HTTP!</h1>');
//})
app.use(express.static(path.join(__dirname, "source")))
app.get("/status", (req, res) => {
	res.set('Content-Type', 'text/plain');
	res.send(`Bypass successfull: ${bypass}\n
Ratelimit Fast: ${block_rate}\n
Ratelimit slow: ${block_slow}\n
Anti Mutiplexing: ${anti_mutiplexing}\n
Bad Header: ${bad_header}\n
Bad Useragent: ${bad_useragent}\n
Header is only available in ddos script: ${block_memory}\n
Block Botnet: ${block_botnet}\n
Missing Header: ${miss_header}\n
Unusual connection is not reliable: ${bad_connect}\n
Bad method: ${bad_method}\n
Change useragent irregularly and quickly: ${uni_ua}\n
Change language irregularly and quickly: ${uni_lang}\n
Bad Requests: ${bad_req}\n
Block Query: ${anti_query}`)
})
app.get("/status-clear-data-ddos", (req, res) => {
	res.send("Start new ddos")
	bypass = 0
	block_rate = 0
	block_slow = 0
	anti_mutiplexing = 0
	block = 0
	bad_header = 0
	bad_useragent = 0
	block_memory = 0
	miss_header = 0
	block_botnet = 0
	anti_query = 0
	bad_method = 0
	bad_connect = 0
	uni_ua = 0
	uni_lang = 0
	bad_req = 0
	console.log(`Reset data by ip ${req.ip}`)
})
app.listen(8080, () => {
  console.log('Server listening on http://localhost:8080');
})
