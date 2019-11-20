/**
 * @namespace typedefs
 */

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
 * { group: 
    *      [ { type: 'group',
    *          uid: '12345678-1234-1234-1234-1234567890ab' 
    *          members: [uid] },
    *        { type: 'group',
    *          uid: '87654321-4321-4321-4321-ba0987654321' 
    *          members: [uid] } ]
    *   object: [ 'ba123456-abcd-abcd-abcd-abcd0000dcba' ],
    *             'access-rule': [],
    *   garbage:
    *     [ {   "type": 'RadiusServer',
    *           "uid": '88889999-00aa-00aa-00aa-8888abab9999',
    *           "name": "RadiusServer_01" },
    *       {   "rule": "ffff1111-9988-9988-99880-ffff0101ffff",
    *           "rule-columns": ["original-source"], 
    *           "position": "69",
    *           "package": "4141abab-7777-7777-7777-717199991717",
    *           "type": "nat-rule" },
    *        {  "rule": "dddd123d-d0d0-d0d0-d0d0-6666dddd0000",
    *           "rule-columns": ["translated-destination"], 
    *           "position": "68",
    *           "package": "4141abab-7777-7777-7777-717199991717",
    *           "type": "nat-rule" },
    *      ]
    *  }
    */

/**
 * Check Point Management API standard-details host object format 
 * @typedef {json} host_standard
 * @property {string} name Object name. Should be unique in the domain.
 * @property {string} uid Object unique identifier.
 * @property {string} type Type of the object.
 * @memberof typedefs
 */

 /**
 * Check Point Management API full-details host object format 
 * @typedef {Object} host_standard
 * @property {string} name Object name. Should be unique in the domain.
 * @property {string} uid Object unique identifier.
 * @property {string} type Type of the object.
 * @property {domain} domain Information about the domain the object belongs to.
 * @property {Object[]} groups How much details are returned depends on the details-level field of the request.
 * @property {string} icon Object icon.
 * @property {interfaces[]} interfaces Host interfaces.
 * @property {string} ipv4-address IPv4 host address.
 * @property {string} ipv6-address IPv6 host address.
 * @property {meta_info} meta-info Object metadata.
 * @property {Object} nat-settings NAT settings.
 * @property {boolean} read-only Indicates  whether the object is read-only.
 * @property {tags_standard[]} tags Collection of tag objects identified by the name or UID
 * @property {Object} host-servers Servers Configuration.
 * @property {string} color Color of the object. Should be one of existing colors.
 * @property {string} comments Comments string.
 * @memberof typedefs
 */

/**
 * Check Point Management API domain object format 
 * @typedef {json} domain
 * @property {string} name Object name. Should be unique in the domain.
 * @property {string} uid Object unique identifier.
 * @property {string} domain-type Includes options arguments of mds, data domain, domain, global domain
 * @memberof typedefs
 */

 /**
 * Check Point Management API standard-details groups object format 
 * @typedef {Object} groups_standard
 * @property {string} name Object name. Should be unique in the domain.
 * @property {string} uid Object unique identifier.
 * @property {string} type Type of the object.
 * @property {domain} domain Information about the domain the object belongs to.
 * @property {group[]} groups How much details are returned depends on the details-level field of the request.
 * @property {string} icon Object icon.
 * @property {standard_obj[]} members Collection of network objects identified by the name or UID
 * @property {meta_info} meta-info Object metadata.
 * @property {Object} ranges Displays the group's matched content as ranges of IP addresses, in case 'show-as-ranges' is set to true. In this case, the 'members' parameter is omitted.
 * @property {boolean} read-only Indicates whether the object is read-only.
 * @property {tags_standard[]} tags Collection of tag objects identified by the name or UID.
 * @property {string} color Color of the object. Should be one of existing colors.
 * @property {string} comments Comments string.
 * @memberof typedefs
 */

 /**
 * Check Point Management API standard-details ranges object format from 'show address-ranges'
 * @typedef {Object} ranges_standard
 * @property {int} from From which element number the query was done.
 * @property {range_standard[]} objects List of objects in the range
 * @property {int} to To which element number the query was done.
 * @property {int} total Total number of elements returned by the query.
 * @memberof typedefs
 */

/**
 * Check Point Management API full-details ranges object format from 'show address-ranges'
 * @typedef {Object} ranges_full
 * @property {int} from From which element number the query was done.
 * @property {range_full[]} objects List of objects in the range
 * @property {int} to To which element number the query was done.
 * @property {int} total Total number of elements returned by the query.
 * @memberof typedefs
 */

/**
 * Check Point Management API standard-details range object format from 'show address-ranges' 
 * @typedef {Object} range_standard
 * @property {string} name Object name. Should be unique in the domain.
 * @property {string} uid Object unique identifier.
 * @property {string} type Type of the object.
 * @property {domain} domain Information about the domain the object belongs to.
 * @property {string} ipv4-address-first First IPv4 address in the range.
 * @property {string} ipv4-address-last Last IPv4 address in the range.
 * @property {string} ipv6-address-first First IPv6 address in the range.
 * @property {string} ipv6-address-last Last IPv9 address in the range.
 * @memberof typedefs
 */

/**
 * Check Point Management API full-details range object format from 'show address-range'
 * @typedef {Object} range_full
 * @property {string} name Object name. Should be unique in the domain.
 * @property {string} uid Object unique identifier.
 * @property {string} type Type of the object.
 * @property {domain} domain Information about the domain the object belongs to.
 * @property {group[]} groups How much details are returned depends on the details-level field of the request.
 * @property {string} icon Object icon.
 * @property {string} ipv4-address-first First IPv4 address in the range.
 * @property {string} ipv4-address-last Last IPv4 address in the range.
 * @property {string} ipv6-address-first First IPv6 address in the range.
 * @property {string} ipv6-address-last Last IPv9 address in the range.
 * @property {meta_info} meta-info Object metadata.
 * @property {nat_settings} nat-settings NAT Settings
 * @property {boolean} read-only Indicates whether the object is read-only.
 * @property {tags_standard[]} tags Collection of tag objects identified by the name or UID.
 * @property {string} color Color of the object. Should be one of existing colors.
 * @property {string} comments Comments string.
 * @memberof typedefs
 */

 /**
 * Check Point Management API nat-settings object format 
 * @typedef {Object} nat_settings 
 * @property {boolean} auto-rule Whether to add automatic address translation rules.
 * @property {string} hide-behind Hide behind method. This parameter is not required in case "method" parameter is "static". Optional values: gateway, ip-address
 * @property {string} install-on Which gateway should apply the NAT translation.
 * @property {string} ipv4-address IPv4 host address.
 * @property {string} ipv6-address IPv6 host address.
 * @property {string} method NAT translation method. Optional values: hide, static
 * @memberof typedefs
 */

/**
 * Check Point Management API meta-info object format 
 * @typedef {Object} meta_info 
 * @property {timestamp} creation-time
 * @property {string} creator
 * @property {string} last-modifier N
 * @property {timestamp} last-modify-time 
 * @property {string} lock Object lock state. It's not allowed to edit objects locked by other session.
 * @property {string} validation-state Oprtional arguments of: ok, info, warning, error
 * @memberof typedefs
 */

/**
 * Check Point Management API timestamp object format
 * @typedef {Object} timestamp 
 * @property {string} iso-8601 Date and time represented in international ISO 8601 format.
 * @property {Int} posix Number of milliseconds that have elapsed since 00:00:00, 1 January 1970.
 * @memberof typedefs
 */

 /**
 * Check Point Management API members object format 
 * @typedef {Object} standard_obj
 * @property {string} name Object name. Should be unique in the domain.
 * @property {string} uid Object unique identifier.
 * @property {string} type Type of the object.
 * @property {domain} domain Information about the domain the object belongs to.
 * @memberof typedefs
 */

/**
 * Check Point Management API members object format 
 * @typedef {standard_obj} group
 * @memberof typedefs
 */

 /**
 * Check Point Management API interfaces object format 
 * @typedef {Object} interfaces
 * @property {string} name Object name. Should be unique in the domain.
 * @property {string} subnet4 IPv4 network address.
 * @property {string} subnet6 IPv6 network address.
 * @property {string} uid Object unique identifier.
 * @property {int} mask-length4 IPv4 network mask length.
 * @property {int} mask-length6 IPv6 network mask length.
 * @property {string} type Type of the object.
 * @property {domain} domain Information about the domain the object belongs to.
 * @property {string} icon Object icon.
 * @property {meta_info} meta-info Object metadata.
 * @property {boolean} read-only Indicates whether the object is read-only.
 * @property {tags_standard[]} tags Collection of tag objects identified by the name or UID.
 * @memberof typedefs
 */

/**
 * Check Point Management API standard-details tags object format 
 * @typedef {standard_obj} tags_standard
 * @memberof typedefs
 */

/**
 * Check Point Management API standard-details access-role object format from 'show access-roles'
 * @typedef {Object} access_roles_standard
 * @property {int} from From which element number the query was done.
 * @property {access_role_standard[]} objects List of objects in the range
 * @property {int} to To which element number the query was done.
 * @property {int} total Total number of elements returned by the query.
 * @memberof typedefs
 */

/**
 * Check Point Management API full-details access-role object format from 'show access-roles'
 * @typedef {Object} access_roles_full
 * @property {int} from From which element number the query was done.
 * @property {access_role_full[]} objects List of objects in the range
 * @property {int} to To which element number the query was done.
 * @property {int} total Total number of elements returned by the query.
 * @memberof typedefs
 */


/**
 * Check Point Management API full-details access-role object format from 'show access-role'
 * @typedef {standard_obj} access_role_standard
 * @property {string} name Object name. Should be unique in the domain.
 * @property {string} uid Object unique identifier.
 * @property {string} type Type of the object.
 * @property {domain} domain Information about the domain the object belongs to.
 * @property {string} icon Object icon.
 * @property {Object[]} machines Machines that can access the system.
 * @property {meta_info} meta-info Object metadata.
 * @property {standard_obj[]} networks Collection of Network objects identified by the name or UID that can access the system.
 * @property {boolean} read-only Indicates whether the object is read-only.
 * @property {standard_obj} remote-access-client Remote access clients identified by name or UID.
 * @property {tags_standard[]} tags Collection of tag objects identified by the name or UID.
 * @property {standard_obj[]} users Users that can access the system. 
 * @property {string} color Color of the object. Should be one of existing colors.
 * @property {string} comments Comments string.
 * @memberof typedefs
 */

/** 
 * Check Point Management API full-details access-role object format from 'show security-zone'
 * @typedef {Object} security_zone_standard
 * @property {string} name Object name. Should be unique in the domain.
 * @property {string} uid Object unique identifier.
 * @property {string} type Type of the object.
 * @property {domain} domain Information about the domain the object belongs to.
 * @property {string} icon Object icon.
 * @property {meta_info} meta-info Object metadata.
 * @property {nat_settings} nat-settings NAT settings.
 * @property {boolean} read-only Indicates  whether the object is read-only.
 * @property {tags_standard[]} tags Collection of tag objects identified by the name or UID
 * @property {string} color Color of the object. Should be one of existing colors.
 * @property {string} comments Comments string.
 * @memberof typedefs
 */

 /**
 * Check Point Management API standard-details access-role object format from 'show security-zones'
 * @typedef {Object} security_zones_standard
 * @property {int} from From which element number the query was done.
 * @property {security_zone_standard[]} objects List of objects in the range
 * @property {int} to To which element number the query was done.
 * @property {int} total Total number of elements returned by the query.
 * @memberof typedefs
 */

/**
*  Definition of a json object.
*  @typedef json 
*  @type {Object} Definition of a json object. 
*  @property {string} {*}
*  @property {string} {*}
*  @memberof typedefs
*/ 

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