/** cprest client access for API
 */
'use strict'
const cp = require('./cp')

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
 * Properties for accessing specific check point rules
 * @typedef {Object} access-rule
 * @property {String} layer Layer that the rule belongs to identified by the name or UID.
 * @property {String} uid Object unique identifier.
 * @property {String} name Object unique name.
 * @property {Number} rule-number Rule number in policy layer. 
 * @property {Boolean} show-hits set to true for rule activity counter
 */

const limit = 500

main()

async function main() {
        cp.startSession(mycred)
                .then(() => getObjects())
                //                .then(layers => awrule(layers))
                //              .then(awruleobj => cp.writeJson(awruleobj, 'aw-rules'))
                .then(() => cp.endSession())
                .catch(cp.endSession)
}

async function getObjects() {
        let awobjects = {}
        let objecttype = ["hosts", "network", "service-tcp"]

        for (let element of objecttype) {
                try {
                        var mydata = {}
                        var mycmd = 'show-objects'
                        var objdata = {}
                        var objarr = []
                        mydata.offset = 0
                        mydata['details-level'] = 'full'
                        mydata.type = element
                        mydata.limit = limit
                        console.log('getting objects')
                        objdata = await cp.apicall(mydata, mycmd)
                        if (!objdata['objects']) {
                                throw new Error(objdata)
                        }
                        objarr = objarr.concat(objdata['objects'])
                        if (objdata.total > objdata.to) {
                                while (objdata.total > mydata.offset) {
                                        console.log('Indexed from ' + objdata.from + ' to ' + objdata.to + ' of ' + objdata.total + ' total objects')
                                        mydata.offset = Number(objdata.to)
                                        objdata = await cp.apicall(mydata, mycmd)
                                        objarr = objarr.concat(objdata['objects'])
                                }
                        }

                        //console.log(layerarr)
                        awobjects[element] = objarr
                        console.log(awobjects)
                        return awobjects
                } catch (err) {
                        console.log('error in getObjects : ' + err)
                }
        }

}