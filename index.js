/** cprest client access for API
 */
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;
'use strict'
const https = require('https')
const fs = require('fs');


/**
 * Traverse object collected in object
 * @param {String[]} getProps - Get object proerties and values with arry of filters
 * @param {Object[]} usedobj - Used objects returned in an array of
 * @example
 * collect an array of objects that match search: 
 * myres = myres.concat(get([uid, '0', 'used-directly', '0', 'objects'], usedobj))
 * myres = myres.concat(get([uid, '0', 'used-directly', '0', 'access-conrtol-rules'], usedobj))
 * Or get a specific value, like the total count from the API:
 * myval = get([uid, '0', 'used-directly', '0', 'total'], usedobj)
 */ 
const get = (p, o) =>
  p.reduce((xs, x) => (xs && xs[x]) ? xs[x] : null, o)


/**
 * Variable required from auth/mycpapi.json file
 * @param {Object[]} myapisite - Setup API hostname
 * @param {Object} myapisite.apihost - mycpapi.json
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
 *	}
 * }
 */
const myapisite = require('./auth/mycpapi')

/**
 * Variable required from auth/mycpauth.json
 * @params {Object} credentials - auth/mycpauth.json
 * @example 
 * create auth/mycpauth.json file
 * {
 *		"user": "apiuser",
 *		"password": "PASSWORD"
 * }
 */
const mycred = require('./auth/mycpauth')

/**
 * Class Method for API callout builder
 * @class
 *
 */
const CpApiClass = require('./cpclass')
const toApi = new CpApiClass(myapisite.chkp)

var details = 'uid'

//var objarr = []
//var objdata = {}

var usedobj = {}
var cleanobj = {}
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
		//.then(myout => writeJson(myout))
		//.then(() => parseObjectUse(allobj[myuids]))
		//.then(tagit => tagObjects(tagit))
		//.then(() => parseRuleUse(cleanobj))
		//.then(() => parseNatUse(cleanobj))
		//.then(() => parseThreatUse(cleanobj))
		.then(() => writeJson(allobjs))
		.then(() => endSession())
		.then(exitstat => console.log(exitstat))
		//.then(() => console.dir(cleanobj))
		//.then(thindat => console.log(thindat))
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
 * Object use for an IP
 * @function showObjects
 * @param {String} ip - IP address to search for
 * @returns {uid[]} Direct and indirect object usage
 */

async function showObjects(mydata, mycmd) {
        try {
		var objdata = {}
		var objarr = []
		var cleanarr = []
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
 * @function checkObject
 * @param {String[]} uid - UID to verify IP address filter
 * @returns {uid[]} -  array of safe UID's to verify usage against
 */


async function checkObject(objarr) {
	try {
		var mydata = {}
		var mytagged = []
		mycmd = 'show-object'
                //mydata['details-level'] = details
		for (var x in objarr) {
			let myobj = objarr[x]
			mydata.uid = myobj
                	var setit = toApi.doPost(mydata, mycmd)
                	let indat = await callOut(setit.options, setit.postData)
			if (indat.object['ipv4-address'] === ip) {
				console.log(indat.object.uid)
				mytagged = mytagged.concat(indat.object)
				allobjs[myuids] = allobjs[myuids].concat(indat.object.uid)
				allobjs[backup] = allobjs[backup].concat(indat.object.name)
				let myback = {}
				myback.name = indat.object.name
				myback['ipv4-address'] = indat.object['ipv4-address']
				myback.cmd = 'add-host'
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
 * where-used returned data format
 * @typedef {Object[]} uid - Array of Host objects by UID
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
  * @function whereUsed
  * @param {Object[]} objarr Any array of objects containing filter values by UID
  * @return {Object[]} An array of objects where the parameter values were found in policy
  */ 
async function whereUsed(objarr) {
	try {
		var mydata = {}
		mycmd = 'where-used'
                mydata['details-level'] = details
                mydata.indirect = true
		for (var x in objarr) {
			let myreturn = {}
			mydata.uid = objarr[x]
                	var setit = toApi.doPost(mydata, mycmd)
                	myreturn[objarr[x]] = await callOut(setit.options, setit.postData)
                	usedobj[ip] = usedobj[ip].concat(myreturn)
		}
                //usedobj[ip] = usedobj[ip].concat(myreturn)
		return usedobj
	} catch (err) {
		console.log('error in whereUsed : ' + err)
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

 /**
  * Determine where a set of objects is used in Check Point policies
  * @function getObjectUse 
  * @param {Object[]} isused An Check Point host object array prepared by doParse
  * @return {Object[]} An array of objects where the parameter values were found in policy
  */
async function getObjectUse(isused) {
	try {
		var myres = []
		const myid = {}
		var myuse = []
		Object.keys(isused).forEach(uid => {
			myres = myres.concat(get([uid, '0', 'used-directly', '0', 'objects'], isused))
		});
		let unique = [...new Set(myres)]
		myuse = myuse.concat(await getUsedObject(unique))
		let tagdata = await tagObject(myuse)
		return myuse
	} catch (err) {
		console.log('error in getObjectUse : ' + err)
	}
}

 /**
  * Recursively discover the use of a host object against Check Point policy
  * @function getUsedObject 
  * @param {Object[]} objarr An Check Point object 
  * @return {Object[]} An array of objects where the parameter values were found in policy
  */
async function getUsedObject(objarr) {
	try {
		var mydata = {}
		var myreturn = []
		mycmd = 'show-object'
                //mydata['details-level'] = details
		for (var x in objarr) {
			let myobj = objarr[x]
			mydata.uid = myobj
                	var setit = toApi.doPost(mydata, mycmd)
                	let indat = await callOut(setit.options, setit.postData)
			//console.log(indat.object.type)
			myreturn = myreturn.concat(indat.object)
		}
		return myreturn
	} catch (err) {
		console.log('error in getUsedObject : ' + err)
	}
}

async function getType(myobj) {
	try {
		var mydata = {}
		mycmd = 'show-object'
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
		mycmd = 'show-access-rule'
        myobj['details-level'] = details
        var setit = toApi.doPost(myobj, mycmd)
        let indat = await callOut(setit.options, setit.postData)
			//console.log(indat.object.type)
		return await indat
	} catch (err) {
		console.log('error in getRule : ' + err)
	}
}

/** 
 * @function tagObjects 
 * @param {Object[]} myobj An array of tags to be added to a Check Point host object
 * @return {Object} Returns the session handler after tagging operations are concluded
 */
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
			mycmd = 'set-' + myobj[x].type
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

/**
 * Given a set of objects returns by the Check Point API, 
 * @function doParse 
 * @param {*} objdat An array of objects where the parameter values were already found in policy
 * @return {Object[]} The parsed and prepared Check Point host object array
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

// pretty show json data to console
/**
 * @function showJson
 * @param {json} obj 
 * @return {json} A prettifed version of the json object using prettyjson library
 */
async function showJson(obj) {
    return (showpretty.render(obj, {
              keysColor: 'blue',
              dashColor: 'white',
              stringColor: 'green'
    }));
}

/**
 * Create an authenticated session with the Check Point API
 * @function startSession 
 * @param {json} myauth Credentials used for API access
 * @return {Object} The prepared session handler
 */
async function startSession(myauth) {
        try {
                console.log('starting session')
                var setit = toApi.doPost(myauth, 'login')
		//toApi.showOpt()
                sessionid = await callOut(setit.options, setit.postData)
                return sessionid
        } catch (err) {
                console.log('error in startSession')
                console.log(err)
        }
}

// set session token to header
/**
 * Set the session handler for a Check Point API connection
 * @function setSession 
 * @param {Object} mysession A Check Point API session handler
 */
async function setSession(mysession) {
        try {
                console.log('setting session')
                toApi.setToken(mysession)
                //toApi.showOpt()
                return
        } catch (err) {
                console.log('error in setSession')
                console.log(err)
        }
}

/**
 * Publish data to the Check Point API via a callout to HTTP POST
 * @function pubSession 
 * @return {Object} mysession A Check Point API session handler
 */
async function pubSession() {
        try {
                console.log('publishing session')
		var mycmd = 'publish'
		var nodata = {}
                var mysession = await callOut(toApi.doPost(nodata, mycmd).options, toApi.doPost(nodata, mycmd).postData)
               	//toApi.showOpt()
		await sleep(3000)
                return mysession
        } catch (err) {
                console.log('error in pubSession : ' + err)
        }
}


// end session and expire token from header
/**
 * Safely logout from the Check Point API
 * @function endSession 
 * @return {Object} The completed Check Point API session handler
 */
async function endSession() {
        try {
                console.log('ending session')
		var nodata = {}
                var nosession = await callOut(toApi.doPost(nodata, 'logout').options, toApi.doPost(nodata, 'logout').postData)
               	//toApi.showOpt()
                return nosession
        } catch (err) {
                console.log('error in endSession : ' + err)
        }
}

// go get the rest api data
/**
 * 
 * @param {json} options 
 * @param {*} postData 
 */
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
/**
 * @function writeJson
 * @param {json} content 
 */
async function writeJson (content) {
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
/**
 * Promise'd sleep function to account for API round trip delays
 * @function sleep 
 * @param {int} ms Number of milliseconds to sleep  by
 * @return {Object} The completed promise after x time has passed
 */
function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * the number of keys in use for a given object
 * @function Count 
 * @param {Object} obj The object to be checked
 * @return {int} The number of keys in use
 */
function countOf(obj) {
	return Object.keys(obj).length
}
