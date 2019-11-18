/** cprest client access for API
 */
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;
'use strict'
const https = require('https')
const fs = require('fs');

//const showpretty = require('prettyjson')

/**
 * Traverse object collected in object
 * @param {String[]} getProps - Get object proerties and values with arry of filters
 * @param {Object[]} usedobj - Used objects returned in an array of
 * @example
 * collect an array of objects that match search: 
 * myres = myres.concat(get([uid, '0', 'used-directly', '0', 'objects'], usedobj))
 * myres = myres.concat(get([uid, '0', 'used-directly', '0', 'access-conrol-rules'], usedobj))
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
const toApi = new CpApiClass(myapisite.stage)

var details = 'uid'

//var objarr = []
//var objdata = {}

var usedarr = []
var usedobj = {}

var resultsobj = {}

//var myres = {}
//const objdata = {}

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
	startSession(mycred.stage)
		.then(sessiontoken => setSession(sessiontoken))
		.then(() => showObjects(nodata, runcmd))
		.then(objid => checkObject(objid))
		.then(clean => whereUsed(clean))
		//.then(myout => writeJson(myout))
		.then(() => doParse(usedobj))
		.then(chkuse => getObjectUse(chkuse))
		.then(() => awobjectpre(usedobj[ip]))
		.then(() => awaccessrules(usedobj[ip]))
		//.then(tagit => tagObject(tagit))
		.then(myout => writeJson(myout))
		.then(() => endSession())
		.then(exitstat => console.log(exitstat))
		//.then(thindat => console.log(thindat))
		.then(() => awtestop())
		.catch(endSession)
}

async function awtestop(){
	console.log("RESULTS OBJECT")
	console.log(JSON.stringify(resultsobj))
	console.log("END RESULTS OBJECT")
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
		var myreturn = []
		mycmd = 'show-object'
		//mydata['details-level'] = details
		for (var x in objarr) {
			let myobj = objarr[x]
			mydata.uid = myobj
			var setit = toApi.doPost(mydata, mycmd)
			let indat = await callOut(setit.options, setit.postData)
			if (indat.object['ipv4-address'] === ip) {
				console.log(indat.object)
				mytagged = mytagged.concat(indat.object)
				myreturn = myreturn.concat(indat.object.uid)
			} else {
				throw new Error(indat.object.uid + ' object IP ' + indat.object['ipv4-address'] + ' does not match filter : ' + ip)
			}
		}
		let tagdata = await tagObject(mytagged)
		return myreturn
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


async function awwhereUsed(UID) {
	try {
		var mydata = {}
		mycmd = 'where-used'
		mydata['details-level'] = details.std
		mydata.indirect = true
		let myreturn = {}
		mydata.uid = UID
		var setit = toApi.doPost(mydata, mycmd)
		myreturn = await callOut(setit.options, setit.postData)
		return myreturn
	} catch (err) {
		console.log('error in whereUsed : ' + err)
	}
}

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

async function tagObject(myobj) {
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

async function doParse(objdat) {
	try {
		//const myres = {}
		const myret = {}
		console.log('Doing Search of IP : ' + ip)
		console.log('Number of host objects: ' + Object.values(objdat[ip]).length)
		Object.keys(objdat[ip]).forEach(uid => {
			Object.keys(objdat[ip][uid]).forEach(usetype => {
				console.log(usetype)
				myret[usetype] = []
				Object.keys(objdat[ip][uid][usetype]).forEach(used => {
					var myres = {}
					myres[used] = []
					//console.log(used + ' : ')
					if (objdat[ip][uid][usetype][used]['total'] > 0) {
						mytotal = objdat[ip][uid][usetype][used]['total']
						console.log(used + ' : ' + objdat[ip][uid][usetype][used]['total'])
						Object.keys(objdat[ip][uid][usetype][used]).forEach(arrs => {
							//console.log(arrs + ' ' + Object.keys(objdat[ip][uid][usetype][used][arrs]).length)
							if (Object.keys(objdat[ip][uid][usetype][used][arrs]).length > 0) {
								let myarrs = {}
								myarrs[arrs] = []
								let mycnt = Object.keys(objdat[ip][uid][usetype][used][arrs]).length
								//console.log(Object.keys(objdat[ip][uid][usetype][used][arrs]))
								//console.log(objdat[ip][uid][usetype][used][arrs])
								console.log(mycnt + ' ' + arrs)
								myarrs[arrs] = myarrs[arrs].concat(objdat[ip][uid][usetype][used][arrs])
								myres[used] = myres[used].concat(myarrs)
							}
						});
						myret[usetype] = myret[usetype].concat(myres)
					}
					//console.log(objdat[ip][uid][usetype][used])
					//console.log(Object.entries(objdat[ip][uid][usetype][used]))
					//console.log(Object.values(objdat[ip][uid][usetype]))
					//console.log(Object.entries(objdat[ip][uid][usetype][used]))
				});
				//myret[usetype] = myres
			});
			console.log('---')
		});
		console.log('returning object data')
		return myret
	} catch (err) {
		console.log('error in doParse : ' + err)
	}
}


/** 
 * Cleans  up input for @awacr
 * @function awaccessrules
 * @param  usedobj[ip] - UID and information of elements
 * @returns List of UIDs safe to delete, and UIDs not safe  
 */
async function awaccessrules(STUFF) {
	let UID = ""
	let ACRarray = []
	console.log("XXXXXXX STARTING ACR CLEANUP XXXXXXXXXXX")
	//console.log(STUFF)
	for (x in STUFF) {
		//console.log(Object.keys(STUFF[x]))
		UID = (Object.keys(STUFF[x]))
		//console.log(Object.keys(STUFF[x][UID]["used-directly"]["access-control-rules"]))
		ACRarray = STUFF[x][UID]["used-directly"]["access-control-rules"]
		if (ACRarray.length > 0) {
			ACR = await awacr(ACRarray)
			console.log("RULE ANALYSIS COMPLETE")
			if (ACR[0]) {
				console.log(UID + " is safe to remove from Access Control Rules");
				console.log(ACR)
				console.log("")
			} else {
				console.log(UID + " is NOT safe to remove from Access Control Rules");
				console.log("")
			}
			resultsobj[UID]={["access-control-rules"]:[ACR]}
		}
	}
	//console.log(ACR)

	console.log("XXXXXXX ENDING ACR CLEANUP XXXXXXXXXXX")
}


/** 
 * Cleans  up input for @awobject
 * @function awobjectpre
 * @param  usedobj[ip] - UID and information of elements
 * @returns List of UIDs safe to delete, and UIDs not safe  
 */
async function awobjectpre(STUFF) {
	let UID = ""
	let GroupUID = ""
	let OBJarray = []
	console.log("XXXXXXX START OBJECT-PRE CLEANUP XXXXXXXXXXX")
	console.log(STUFF)
	for (x in STUFF) {
		UID = (Object.keys(STUFF[x]))
		OBJarray = STUFF[x][UID]["used-directly"]["objects"]
		//console.log(OBJarray)
		//console.log(OBJarray[0])
		for (y in OBJarray) {
			GroupUID = OBJarray[y]
			//console.log(GroupUID)
			OBJ = await awobject(GroupUID)
			console.log("GROUP ANALYSIS COMPLETE")
			if (OBJ > 1) {
				console.log(UID + " is safe to remove from GROUP " + GroupUID);
				resultsobj[UID]={[GroupUID]:{["Group"]:true}}
				console.log("")
			} else {
				console.log(UID + " MAY safe to remove from GROUP " + GroupUID);
				//needs further analysis
				let BOB = {}
				let awtmp = {}
				BOB = await awwhereUsed(GroupUID)
				//console.log(BOB)
				//console.log(BOB["used-directly"]["access-control-rules"])
				LARRY = await awobjacr(BOB["used-directly"]["access-control-rules"])
				console.log("RESULTS OF LARRY")
				console.log(LARRY)
				//resultsobj[UID]={["access-control-rules"]:[LARRY]}
				//resultsobj[UID]={[GroupID]:{["Group"]:LARRY[0]}}
				console.log("")
			}
			//resultsobj[UID]["groups"]=OBJ
		}
	}
	//console.log(ACR)

	console.log("XXXXXXX END OBJECT-PRE CLEANUP XXXXXXXXXXX")
}

/** 
 * Checks each UID for groups
 * @function awobject
 * @param  GroupUID the a single UID for a group 
 * @returns The length of the group members.
 */
async function awobject(GroupUID) {
	//console.log("XXXXXXXXXXXXXX OBJECT FUNCTION START XXXXXXXXXXXXX")
	let awdata = {}
	//console.log(GroupUID)
	awdata.uid = GroupUID
	mycmd = "show-group"
	let setit = toApi.doPost(awdata, mycmd)
	// //console.log(setit)
	objdata = await callOut(setit.options, setit.postData)
	let group_member_length = objdata.members.length
	//console.log(group_member_length)
	// //console.log(objdata)
	// console.log("XXXXXXXXXXXXXX OBJECT FUNCTION END XXXXXXXXXXXXX")
	return (group_member_length)
}


/** 
 * Checks each object for access-control-rules to see if the UID is the only object in the source/destination
 * @function awacr
 * @param  ARCarray - Array of rules
 * @returns if UID is safe to delete or not as far as access-control-rules go. 
 */
async function awacr(mykey) {
	let CONTINUE = true;
	let ACRresults = []
	//console.log("IN THE FUNCTION")
	//console.log(mykey)
		for (x in mykey) {
			//console.log("XXXXXXXXXXXXXX START XXXXXXXXXXXXX")
			//console.log(mykey[x]["rule"])
			//console.log(mykey[x]["layer"])
			let columns = (mykey[x]["rule-columns"])
			//console.log(columns)

			let awdata = {}
			awdata.uid = (mykey[x]["rule"])
			//console.log("AAAAA")
			awdata.layer = (mykey[x]["layer"])
			mycmd = "show-access-rule"
			let setit = toApi.doPost(awdata, mycmd)
			//console.log("**")
			//console.log(setit)
			objdata = await callOut(setit.options, setit.postData)
			//console.log(objdata)
			//console.log("--")

			for (DDD of columns) {
				//console.log(objdata[DDD].length)
				//console.log(objdata[DDD])
				if (objdata[DDD].length > 1) {
					//console.log("SAFE TO DELETE")
					//console.log("ADD TAG TO QUEUE")
					temp = ("Rule " + awdata.uid + "at layer " + awdata.layer + " Has " + objdata[DDD].length + " object in the " + DDD + " column")
					ACRresults.push(temp)
					console.log(temp)


				} else {
					//console.log("EJECT EJECT EJECT")
					temp = ("Rule " + awdata.uid + "at layer " + awdata.layer + " Has " + objdata[DDD].length + " object in the " + DDD + " column")
					CONTINUE = flase
					ACRresults.push(temp)
					console.log(temp)
				}
			}
			//console.log("XXXXXXXXXXXXXX END XXXXXXXXXXXXX")	
		}

	ACRresults.unshift(CONTINUE)
	return (ACRresults)
}


/** 
 * Checks each object for access-control-rules to see if the UID is the only object in the source/destination
 * @function awobjacr
 * @param  ARCarray - Array of rules
 * @returns if UID is safe to delete or not as far as access-control-rules go. 
 */
async function awobjacr(mykey) {
	let AWFLAG = true;
	let OBJACRresults = []
	//console.log("IN THE FUNCTION")
	//console.log(mykey)
	//if (CONTINUE) {
	for (zz in mykey) {
		//console.log("XXXXXXXXXXXXXX START XXXXXXXXXXXXX")
		//console.log(mykey[x]["rule"])
		//console.log(mykey[x]["layer"])
		let columns = (mykey[zz]["rule-columns"])
		//console.log(columns)

		let awdata = {}
		awdata.uid = (mykey[zz]["rule"]["uid"])
		//console.log("AAAAA")
		awdata.layer = (mykey[zz]["layer"]["uid"])
		mycmd = "show-access-rule"
		let setit = toApi.doPost(awdata, mycmd)
		//console.log("**")
		//console.log(setit)
		objdata = await callOut(setit.options, setit.postData)
		//console.log(objdata)
		//console.log("--")

		for (DDD of columns) {
			//console.log(objdata[DDD].length)
			//console.log(objdata[DDD])
			if (objdata[DDD].length > 1) {
				//console.log("SAFE TO DELETE")
				//console.log("ADD TAG TO QUEUE")
				temp = ("Rule " + awdata.uid + "at layer " + awdata.layer + " Has " + objdata[DDD].length + " object in the " + DDD + " column")
				ACRresults.push(temp)
				console.log(temp)
			} else {
				//console.log("OBJECT EJECT EJECT EJECT")
				temp = ("Rule " + awdata.uid + "at layer " + awdata.layer + " Has " + objdata[DDD].length + " object in the " + DDD + " column")
				console.log(temp)
				OBJACRresults.push(temp)
				AWFLAG = false
			}
		}
		//console.log("XXXXXXXXXXXXXX END XXXXXXXXXXXXX")	
	}
	//}
	OBJACRresults.unshift(AWFLAG)
	return (OBJACRresults)
}

// pretty show json data to console
async function showJson(obj) {
	return (showpretty.render(obj, {
		keysColor: 'blue',
		dashColor: 'white',
		stringColor: 'green'
	}));
}

// start a check point api session
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
		console.log('writing file . . . ' + newfile)
		console.log(typeof content)
		const data = await fs.writeFileSync(newfile, JSON.stringify(content, undefined, 2))
		//file written successfully
		console.log(content)
		console.log('Json data written to ' + newfile)
		console.log('  --  ')
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