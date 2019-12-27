// collection of common functions used across the scripts
// consolidate here for central point to edit and manage 
// reusable functions
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;
'use strict'
const https = require('https')
const fs = require('fs');
//const CpApiClass = require('./cpclass')
const CpApiClass = require('./cpclass')
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
const toApi = new CpApiClass(myapisite.chkp)
// Check Point API session auth and token management
/**
 * Create an authenticated session with the Check Point API
 * @param {mycred} credentials Credentials used for API access
 * @param {sessionid} sessionid A Check Point API session ID handler
 * @param {Api} options.headers x-chkp-sid Session ID token applied to header
 * @returns {myapicall} Header token set for session 

 */
async function startSession(myauth) {
	try {
		console.log('starting session')
		var setit = toApi.doPost(myauth, 'login')
		let sessionid = await callOut(setit.options, setit.postData)
        toApi.setToken(sessionid)
		return sessionid
	} catch (err) {
			console.log('error in startSession :' + err)
	}
}

/** 
 * accept post data and command and send API call
 * return post data
 * 
 * */
async function apicall(mydata, mycmd) {
    try {
        let setit = toApi.doPost(mydata, mycmd)
        return await callOut(setit.options, setit.postData)
    } catch (err) {
            console.log('error in cpapi : ' + err)
    }
}

/** 
 * publish changes to Check Point API
*/
async function pubSession() {
    try {
        console.log('publishing session')
        let mycmd = 'publish'
        var nodata = {}
        var mysession = await callOut(toApi.doPost(nodata, mycmd).options, toApi.doPost(nodata, mycmd).postData)
        await sleep(3000)
        return mysession
    } catch (err) {
            console.log('error in pubSession : ' + err)
    }
}


/**
 * end session and expire token from header
 * @function endSession expire token and end API session
 * 
*/
async function endSession() {
    try {
        console.log('ending api session')
        var nodata = {}
        var nosession = await callOut(toApi.doPost(nodata, 'logout').options, toApi.doPost(nodata, 'logout').postData)
        return nosession
    } catch (err) {
        console.log('error in endSession : ' + err)
    }
}

// make the callout to the rest api for data
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
    });
}

// save api output as json data to file
async function writeJson (content, file) {
    try {
        let newfile = file + '.json'
        await fs.writeFileSync(newfile, JSON.stringify(content, undefined, 2))
        console.log('Json data written to ' + newfile)
        return content
    } catch (err) {
            console.error('Error writing object to file in writeJson: ' + err)
    }
}

/**
* the number of keys in use for a given object
* @function Count 
* @param {Object} obj The object to be checked
* @return {Number} The number of keys in use
*/
function countOf(obj) {
    return Object.keys(obj).length
}

// Accepts the array and key
const groupBy = (array, key) => {
    // Return the end result
    return array.reduce((result, currentValue) => {
      // If an array already present for key, push it to the array. Else create an array and push the object
      (result[currentValue[key]] = result[currentValue[key]] || []).push(
        currentValue
      );
      // Return the current iteration `result` value, this will be taken as next iteration `result` value and accumulate
      return result;
    }, {}); // empty object is the initial value for result object
};

// easy way to wait
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = {
    startSession,
    apicall,
    pubSession,
    endSession,
    writeJson,
    countOf,
    groupBy
}