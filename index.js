/** cprest client access for API
 */
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;
'use strict'
const https = require('https')
const fs = require('fs');

// depreciated
const get = (p, o) =>
	p.reduce((xs, x) => (xs && xs[x]) ? xs[x] : null, o)


/**
 * API Site configuration required from auth/mycpapi.json file
 * @require auth/mycpapi.json
 * @example
 * create auth/mycpapi.json file
 * {
 *	"chkp": {
 *		"host": "SET.YOUR.HOSTNAME",
 *		"port": "443",
 *		"path": "/web_api",
 *		"method": "POST",
 *		"headers": {
 *			"Content-Type": "application/json"
 *		}
 *	  }
 * }
 */
const myapisite = require('./auth/mycpapi')

/**
 * API credentials required from auth/mycpauth.json
 * @require auth/mycpauth.json
 * @example
 * create auth/mycpauth.json file
 * {
 *		"user": "apiuser",
 *		"password": "PASSWORD"
 * }
 */
const mycred = require('./auth/mycpauth')

/* 
 * Define API call object options
 * @typedef {Object} Api 
 * @property {Object} options
 * @property {Object} options.headers
 * @property {String} options.host
 * @property {String} options.method
 * @property {String} options.path
 * @property {Number} options.port
 * @property {Object} data
 */

const CpApiClass = require('./cpclass')
const toApi = new CpApiClass(myapisite.chkp)
const CPobj = require('./cpobj')

var details = 'uid'
var usedobj = {}
var cleanobj = {}

/**
 * allobjs object data format
 * @typedef {Object} allobjs
 * @property {Object[]} access-rule
 * @property {String[]} backup
 * @property {Object[]} garbage
 * @property {Object[]} group
 * @property {String[]} hosts
 * @property {Object[]} restore
 */
var allobjs = {}
var mygroups = 'group'
allobjs[mygroups] = []
var myuids = 'hosts'
allobjs[myuids] = []
var myrules = 'access-rule'
allobjs[myrules] = []
var garbage = 'garbage'
allobjs[garbage] = []
var backup = 'backup'
allobjs[backup] = []
var restore = 'restore'
allobjs[restore] = []

var limit = '500'
var runcmd = 'show-objects'

var sessionid = {}
var myfilename = 'dump'

var nodata = {}
if (process.argv[2]) {
	ip = process.argv[2]
	nodata.filter = ip
	myfilename = ip
	nodata['ip-only'] = true
	nodata.type = 'host'
	usedobj[ip] = []
}



main()
//.then(admins)

async function main() {
	startSession(mycred)
		.then(sessiontoken => setSession(sessiontoken))
		.then(() => showObjects(nodata, runcmd))
		.then(objid => checkObject(objid))
		.then(() => whereUsed(allobjs[myuids]))
		.then(myuse => doParse(myuse))
		.then(() => writeJson(allobjs))
		.then(() => endSession())
		.then(exitstat => console.log(exitstat))
		.catch(endSession)
}

async function admins() {
	mycred.domain = 'System Data'
	details = 'standard'
	runcmd = 'show-administrators'
	myfilename = 'admins'
	nodata = {}
	startSession(mycred)
		.then(sessiontoken => setSession(sessiontoken))
		.then(() => showObjects(nodata, runcmd))
		.then(myout => writeJson(myout))
		.then(thindat => console.log(thindat))
		.then(() => endSession())
		.catch(endSession)
}

/**
 * @param
 * @param {*} mydata
 * @param {*} mycmd
 */

/**
 * Object use for an IP
 * @param {Object[]} mydata - Search filter for IP
 * @param {String} mycmd - show-objects API command to run
 * @returns {String[]} Direct and indirect object use UID array
 */

/**
 * @typedef {Object} sessionid
 * @property {Object} last-login-was-at
 * @property {Number} session-timeout
 * @property {String} sid
 * @property {String} uid
 * @property {String} url
 */

/**
 * Create an authenticated session with the Check Point API
 * @param {mycred} credentials Credentials used for API access
 * @return {sessionid} The prepared session handler
 */
async function startSession(myauth) {
	try {
		console.log('starting session')
		var setit = toApi.doPost(myauth, 'login')
		//toApi.showOpt()
		sessionid = await callOut(setit.options, setit.postData)
		//console.log(sessionid)
		return sessionid
	} catch (err) {
		console.log('error in startSession')
		console.log(err)
	}
}

/**
 * Class method set of API token authentication
 * @param {Api} options.headers x-chkp-sid Session ID token applied to header
 *
 */

// set session token to header
/**
 * Set the session handler for a Check Point API connection
 * @param {sessionid} sessionid A Check Point API session ID handler
 * @returns {myapicall} Header token set for session
 */
async function setSession(mysession) {
	try {
		console.log('setting session')
		toApi.setToken(mysession)
		toApi.showOpt()
		return
	} catch (err) {
		console.log('error in setSession')
		console.log(err)
	}
}

async function showObjects(mydata, mycmd) {
	try {
		var objdata = {}
		var objarr = []
		mydata.offset = 0
		mydata['details-level'] = details
		mydata.limit = limit
		console.log('showing session')
		var setit = toApi.doPost(mydata, mycmd)
		//toApi.showOpt()
		objdata = await callOut(setit.options, setit.postData)
		objarr = objarr.concat(objdata.objects)
		if (objdata.total > objdata.to) {
			while (objdata.total >= mydata.offset) {
				console.log('From ' + objdata.from + ' to ' + objdata.to + ' of ' + objdata.total + ' indexed')
				mydata.offset = Number(objdata.to)
				setit = toApi.doPost(mydata, mycmd)
				objdata = await callOut(setit.options, setit.postData)
				objarr = objarr.concat(objdata.objects)
			}
		}
		return objarr
	} catch (err) {
		console.log('error in showObjects : ' + err)
	}
}

/**
 * Object verify IP matches filter
 * @param {String[]} uid - UID to verify IP address filter
 * @returns {String[]} array of safe UID's to verify usage against
 */
async function checkObject(objarr) {
	try {
		var mydata = {}
		var mytagged = []
		let mycmd = 'show-object'
		for (var x in objarr) {
			let myobj = objarr[x]
			mydata.uid = myobj
			mydata['details-level'] = 'full'
			var setit = toApi.doPost(mydata, mycmd)
			let indat = await callOut(setit.options, setit.postData)
			if (indat.object['ipv4-address'] === ip) {
				console.log(indat.object.uid)
				mytagged = mytagged.concat(indat.object)
				allobjs[myuids] = allobjs[myuids].concat(indat.object.uid)
				allobjs[backup] = allobjs[backup].concat(indat.object.name)
				let myback = new CPobj(indat.object)
				//myback.name = indat.object.name
				//myback['ipv4-address'] = indat.object['ipv4-address']
				myback.cmd = 'add-host'
				myback['ignore-warnings'] = true
				allobjs[restore] = allobjs[restore].concat(myback)
			} else {
				throw new Error(indat.object.uid + ' object IP ' + indat.object['ipv4-address'] + ' does not match filter : ' + ip)
			}
		}
		//let tagdata = await tagObjects(mytagged)
		return allobjs[myuids]
	} catch (err) {
		console.log('error in checkObject : ' + err)
	}
}

/**
 * where-used returned data format by UID of each host
 * @typedef {Object[]} usage - Array of Host objects details by UID
 * @property {Object} used-directly - Direct use of object
 * @property {Number} used-directly.total - Total count of usage
 * @property {Object[]} used-directly.objects - Array of object dependencies
 * @property {Object[]} used-directly.access-control-rules - Array of access rule dependencies
 * @property {Object[]} used-directly.nat-rules - Array of nat rule dependencies
 * @property {Object[]} used-directly.threat-prevention-rules - Array of threat inspection rules
 * @property {Object} used-indirectly - Indirect or nested use of object
 * @property {Number} used-indirectly.total - Total count of indirect use
 * @property {Object[]} used-indirectly.objects - Array of object references
 * @property {Object[]} used-indirectly.access-control-rules - Array of nested access rule 
 * @property {Object[]} used-indirectly.nat-rules - Array of indirect nat rules
 * @property {Object[]} used-indirectly.threat-prevention-rules - Array of nested threat rules
 * @example 
 * { ip: [
 *        {
 *          uid: [
 *          	  { 
 * 	          used-directly: {
 * 	       			  total: 0,
 * 	        		  access-control-rules[],
 * 	        		  nat-rules[],
 * 	        		  threat-prevention-rules[],
 * 	        		  objects[]
 * 	        		  },
 * 	      	  used-indirectly: {
 * 	       			  total: 0,
 * 	        		  access-control-rules[],
 * 	        		  nat-rules[],
 * 	        		  threat-prevention-rules[],
 * 	        		  objects[]
 * 	        		  }
 *              }
 *           ] 
 *        }
 *     ]
 *  }
 */

/**
 * Determine where a set of objects is used in Check Point policies
 * @param {String[]} uid Any array of objects containing filter values by UID
 * @returns {usage} An array of objects where the parameter values were found in policy
 */
async function whereUsed(objarr) {
	try {
		var mydata = {}
		let mycmd = 'where-used'
		mydata['details-level'] = details
		mydata.indirect = true
		for (var x in objarr) {
			let myreturn = {}
			mydata.uid = objarr[x]
			var setit = toApi.doPost(mydata, mycmd)
			myreturn[objarr[x]] = await callOut(setit.options, setit.postData)
			usedobj[ip] = usedobj[ip].concat(myreturn)
		}
		return usedobj
	} catch (err) {
		console.log('error in whereUsed : ' + err)
	}
}

/**
 * Operations Object created with filter logic
 * @param {usage} usage - return values from API where-used
 * @returns {allobjs} -  array of operational changes
 */
async function doParse(objdat) {
	try {
		//const myres = {}
		console.log('Doing Search of IP : ' + ip)
		console.log('Number of host objects: ' + Object.values(objdat[ip]).length)
		if (Object.values(objdat[ip]).length < 0) {
			throw new Error('No HOST OBJECTS FOUND')
		}
		var myobjarr = []
		var myacl = []
		var mynat = []
		var mythreat = []
		Object.keys(objdat[ip]).forEach(uid => {
			Object.keys(objdat[ip][uid]).forEach(usetype => {
				console.log(usetype)
				cleanobj[usetype] = []
				Object.keys(objdat[ip][uid][usetype]).forEach(used => {
					var myres = {}
					myres[used] = []
					if (objdat[ip][uid][usetype][used]['total'] > 0) {
						mytotal = objdat[ip][uid][usetype][used]['total']
						console.log(used + ' : ' + objdat[ip][uid][usetype][used]['total'])
						Object.keys(objdat[ip][uid][usetype][used]).forEach(arrs => {
							if (Object.keys(objdat[ip][uid][usetype][used][arrs]).length > 0) {
								let myarrs = {}
								myarrs[arrs] = []
								let mycnt = Object.keys(objdat[ip][uid][usetype][used][arrs]).length
								console.log(mycnt + ' ' + arrs + ' ' + usetype + ' used: ' + used)
								if (used === 'used-directly') {
									if (arrs === 'objects') {
										let myused = objdat[ip][uid][usetype][used][arrs]
										myobjarr = myobjarr.concat(myused)
									} else if (arrs === 'access-control-rules') {
										let myused = objdat[ip][uid][usetype][used][arrs]
										myacl = myacl.concat(myused)
									} else if (arrs === 'nat-rules') {
										let myused = objdat[ip][uid][usetype][used][arrs]
										mynat = mynat.concat(myused)
									} else if (arrs === 'threat-prevention-rules') {
										let myused = objdat[ip][uid][usetype][used][arrs]
										mythreat = mythreat.concat(myused)
									} else {
										let myused = objdat[ip][uid][usetype][used][arrs]
										allobjs[garbage] = allobjs[garbagge].concat(myused)
									}
								}
							}
						});
					}
				});
			});
			console.log('---')
		});
		console.log('parsing objects')
		await parseObjectUse(myobjarr)
		console.log('parsing rules')
		await parseRuleUse(myacl)
		console.log('parsing nat')
		await parseNatUse(mynat)
		console.log('parsing threat')
		await parseThreatUse(mythreat)
		console.log('returning object data')
		return allobjs
	} catch (err) {
		console.log('error in doParse : ' + err)
	}
}

async function parseObjectUse(objdat) {
	try {
		var myret = []
		objdat = [...new Set(objdat)]
		for (var x of objdat) {
			let mychk = await getType(x)
			if (mychk.type === 'group') {
				let mygrp = {}
				let mygrpback = {}
				mygrp.uid = mychk.uid
				mygrpback.name = mychk.name
				mygrpback.cmd = 'set-group'
				//myret = myret.concat(mygrp)
				let memarr = []
				let memarrback = []
				Object.values(mychk.members).forEach(gmem => {
					memarr = memarr.concat(gmem.uid)
					memarrback = memarrback.concat(gmem.name)
				});
				let smembers = memarr.filter(x => allobjs[myuids].includes(x))
				let members = {}
				let members2 = {}
				members.remove = smembers
				mygrp.members = members
				allobjs[mygroups] = allobjs[mygroups].concat(mygrp)
				let bmembers = memarrback.filter(x => allobjs[backup].includes(x))
				//['members']add = bmembers
				members2.add = bmembers
				mygrpback.members = members2
				//delete mygrpback.members.remove
				allobjs[restore] = allobjs[restore].concat(mygrpback)
				//let smembers = mychk.members.filter(x => allobjs[myuids].includes(x))
				//if (mychk.length > 0) {
				//console.log(mychk)
				//}
			} else {
				let badobj = {}
				if (!mychk.type) {
					mychk.type = 'NULL TYPE'
				}
				badobj.type = mychk.type
				badobj.uid = mychk.uid
				badobj.name = mychk.name
				allobjs[garbage] = allobjs[garbage].concat(badobj)
			}
		}
		return allobjs
	} catch (err) {
		console.log('error in parseObjectUse : ' + err)
	}
}

async function parseRuleUse(objdat) {
	try {
		//let unique = [...new Set(myres)]
		//myres = [...new Set(myres)]
		for (var x of objdat) {
			if (x) {
				let rule = {}
				rule.uid = x.rule
				rule.layer = x.layer
				let ruleobj = await getRule(rule)
				//console.log(drule.uid)
				//console.log(cleangroups)
				let rulechk = {}
				rulechk.uid = ruleobj.uid
				rulechk.layer = ruleobj.layer
				//rulechk.name = ruleobj.name
				let sremove = ruleobj.source.filter(x => allobjs[myuids].includes(x))
				if (sremove.length > 0) {
					console.log(sremove + ' src remove ' + sremove.length)
					let source = {}
					source.remove = sremove
					rulechk.source = source
				}
				//rulechk.source = remove
				//rulechk.oldsource = ruleobj.source
				let dremove = ruleobj.destination.filter(x => allobjs[myuids].includes(x))
				if (dremove.length > 0) {
					console.log(dremove + ' dst remove ' + dremove.length)
					let destination = {}
					destination.remove = dremove
					rulechk.destination = destination
				}
				//rulechk.olddestination = ruleobj.destination
				allobjs[myrules] = allobjs[myrules].concat(rulechk)
			}
		}
		// run backup of myrules changes
		//console.log(allobjs[myrules])
		//	let mychk = await getType(myres[x])
		//	if (mychk.type === 'group') {
		//let mygrp = {}
		//mygrp.type = mychk.type
		//		mygrp.uid = mychk.uid
		//		myret = myret.concat(myres[x])
		//}
		for (var x of allobjs[myrules]) {
			//let source = {}
			let asource = []
			let adest = []
			let rulechk = {}
			if (x.source) {
				rulechk.uid = x.uid
				rulechk.layer = x.layer
				rulechk.cmd = 'set-access-rule'
				for (var y of x.source.remove) {
					let theobj = await getType(y)
					asource = asource.concat(theobj.name)
					console.log(theobj.name)
					//console.log(x)
				}
				let source = {}
				source.add = asource
				rulechk.source = source
			}
			if (x.destination) {
				rulechk.uid = x.uid
				rulechk.layer = x.layer
				rulechk.cmd = 'set-access-rule'
				for (var y of x.destination.remove) {
					let theobj = await getType(y)
					adest = adest.concat(theobj.name)
					console.log(theobj.name)
					//console.log(x)
				}
				let destination = {}
				destination.add = adest
				rulechk.destination = destination
			}
			allobjs[restore] = allobjs[restore].concat(rulechk)
		}
		return allobjs
	} catch (err) {
		console.log('error in parseRuleUse : ' + err)
	}
}

async function parseNatUse(objdat) {
	try {
		for (var x of objdat) {
			if (x) {
				x.type = 'nat-rule'
				allobjs[garbage] = allobjs[garbage].concat(x)
				//console.log(x)
			}
		}
		return allobjs
	} catch (err) {
		console.log('error in parseNatUse : ' + err)
	}
}

async function parseThreatUse(objdat) {
	try {
		for (var x of objdat) {
			if (x) {
				x.type = 'threat-prevention'
				allobjs[garbage] = allobjs[garbage].concat(x)
				//console.log(x)
			}
		}
		return allobjs
	} catch (err) {
		console.log('error in parseNatUse : ' + err)
	}
}

async function getType(myobj) {
	try {
		var mydata = {}
		let mycmd = 'show-object'
		mydata['details-level'] = 'full'
		mydata.uid = myobj
		var setit = toApi.doPost(mydata, mycmd)
		let indat = await callOut(setit.options, setit.postData)
		//console.log(indat.object.type)
		return await indat.object
	} catch (err) {
		console.log('error in getType : ' + err)
	}
}

async function getRule(myobj) {
	try {
		let mycmd = 'show-access-rule'
		myobj['details-level'] = details
		var setit = toApi.doPost(myobj, mycmd)
		let indat = await callOut(setit.options, setit.postData)
		//console.log(indat.object.type)
		return await indat
	} catch (err) {
		console.log('error in getRule : ' + err)
	}
}

async function tagObjects(myobj) {
	try {
		var tags = {}
		tags.add = 'DELETE'
		var mydata = {}
		var myreturn = []
		//mydata['details-level'] = details
		for (var x in myobj) {
			mydata.uid = myobj[x].uid
			mydata.tags = tags
			let mycmd = 'set-' + myobj[x].type
			var setit = toApi.doPost(mydata, mycmd)
			let indat = await callOut(setit.options, setit.postData)
			//console.log(mycmd)
			//console.log(mydata)
			myreturn = myreturn.concat(indat)
		}
		let mypub = await pubSession()
		return mypub
	} catch (err) {
		console.log('error in tagObject : ' + err)
	}
}



// pretty show json data to console
async function showJson(obj) {
	return (showpretty.render(obj, {
		keysColor: 'blue',
		dashColor: 'white',
		stringColor: 'green'
	}));
}

async function pubSession() {
	try {
		console.log('publishing session')
		let mycmd = 'publish'
		var nodata = {}
		var mysession = await callOut(toApi.doPost(nodata, mycmd).options, toApi.doPost(nodata, mycmd).postData)
		//toApi.showOpt()
		await sleep(3000)
		return mysession
	} catch (err) {
		console.log('error in pubSession : ' + err)
	}
}

/**
 * end session and expire token from header
 * @function
 *
 */
async function endSession() {
	try {
		console.log('ending api session')
		var nodata = {}
		var nosession = await callOut(toApi.doPost(nodata, 'logout').options, toApi.doPost(nodata, 'logout').postData)
		//toApi.showOpt()
		return nosession
	} catch (err) {
		console.log('error in endSession : ' + err)
	}
}

// go get the rest api data
async function callOut(options, postData) {
	return new Promise((resolve, reject) => {
		var req = https.request(options, (res) => {
			var myret = ''
			if (res.statusCode > 200) {
				process.stdout.write(res.statusCode + ' : ' + res.statusMessage + ' ' + options.path);
			}
			res.on('data', (d) => {
				myret += d
			});
			res.on('end', () => {
				resolve(JSON.parse(myret))
			});
		});
		req.on('error', (e) => {
			reject(e);
		});
		if (postData) {
			req.write(postData);
		}
		req.end();
	})
}

// save api output as json data to file
async function writeJson(content) {
	try {
		var newfile = myfilename + '.json'
		console.log('attempting to write to file . . . ' + newfile)
		console.log(typeof content.hosts)
		if (content.hosts.length > 0) {
			console.log(content.hosts.length)
			const data = await fs.writeFileSync(newfile, JSON.stringify(content, undefined, 2))
			//file written successfully
			console.log(content)
			console.log('Json data written to ' + newfile)
			console.log('  --  ')
		} else {
			console.log(' NO HOSTS FOUND ')
		}
		return content
	} catch (err) {
		console.error(err)
	}
}

// easy way to wait
function sleep(ms) {
	return new Promise(resolve => setTimeout(resolve, ms));
}

function countOf(obj) {
	return Object.keys(obj).length
}
