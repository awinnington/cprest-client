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
                .then(() => getLayerNames())
                .then(layers => awrule(layers))
                .then(awruleobj => cp.writeJson(awruleobj, 'aw-rules'))
                .then(() => cp.endSession())
                .catch(cp.endSession)
}

async function getLayerNames() {
        try {
                var mydata = {}
                var mycmd = 'show-access-layers'
                var objdata = {}
                var objarr = []
                mydata.offset = 0
                mydata['details-level'] = 'standard'
                mydata.limit = limit
                console.log('getting layers')
                objdata = await cp.apicall(mydata, mycmd)
                if (!objdata['access-layers']) {
                        throw new Error(objdata)
                }
                objarr = objarr.concat(objdata['access-layers'])
                if (objdata.total > objdata.to) {
                        while (objdata.total > mydata.offset) {
                                console.log('Indexed from ' + objdata.from + ' to ' + objdata.to + ' of ' + objdata.total + ' total objects')
                                mydata.offset = Number(objdata.to)
                                objdata = await cp.apicall(mydata, mycmd)
                                objarr = objarr.concat(objdata['access-layers'])
                        }
                }

                // Just need layer names
                let layerarr = []
                objarr.forEach(x => layerarr.push(x.name))
                //console.log(layerarr)


                return layerarr
        } catch (err) {
                console.log('error in getLayers : ' + err)
        }
}

async function awrule(layers) {

        //console.log(layers)
        let awruleobj = {}
        for (let element of layers) {
                let mycmd = "show-access-rulebase"
                let awdata = {}
                let objarr = []
                awdata['name'] = element
                awdata['use-object-dictionary'] = false
                awdata['offset'] = 0
                awdata['show-hits'] = true
                awdata['details-level'] = 'standard'
                awdata.limit = 50

                let awrulebase = await cp.apicall(awdata, mycmd)
                //console.log(awrulebase['rulebase'])
                //console.log(awrulebase.to)
                objarr = objarr.concat(awrulebase['rulebase'])
                //console.log(awrulebase)

                if (awrulebase.total > awrulebase.to) {
                        while (awrulebase.total > awdata.offset) {
                                console.log('Indexed from ' + awrulebase.from + ' to ' + awrulebase.to + ' of ' + awrulebase.total + ' total objects')
                                awdata.offset = Number(awrulebase.to)
                                awrulebase = await cp.apicall(awdata, mycmd)
                                objarr = objarr.concat(awrulebase['rulebase'])
                        }
                }
                awruleobj[element] = objarr
        }
        return (awruleobj)
}