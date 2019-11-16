## Classes

<dl>
<dt><a href="#CpApiClass">CpApiClass</a></dt>
<dd></dd>
</dl>

## Constants

<dl>
<dt><a href="#myapisite">myapisite</a></dt>
<dd><p>Variable required from auth/mycpapi.json file</p>
</dd>
<dt><a href="#mycred">mycred</a></dt>
<dd><p>Variable required from auth/mycpauth.json</p>
</dd>
</dl>

## Functions

<dl>
<dt><a href="#showObjects">showObjects(ip)</a> ⇒ <code><a href="#uid">Array.&lt;uid&gt;</a></code></dt>
<dd><p>Object use for an IP</p>
</dd>
<dt><a href="#checkObject">checkObject(uid)</a> ⇒ <code><a href="#uid">Array.&lt;uid&gt;</a></code></dt>
<dd><p>Object verify IP matches filter</p>
</dd>
</dl>

## Typedefs

<dl>
<dt><a href="#uid">uid</a> : <code>Array.&lt;Object&gt;</code></dt>
<dd><p>where-used returned data format</p>
</dd>
</dl>

<a name="CpApiClass"></a>

## CpApiClass
**Kind**: global class  
<a name="new_CpApiClass_new"></a>

### new CpApiClass()
Class Method for API callout builder

<a name="myapisite"></a>

## myapisite
Variable required from auth/mycpapi.json file

**Kind**: global constant  

| Param | Type | Description |
| --- | --- | --- |
| myapisite | <code>Array.&lt;Object&gt;</code> | Setup API hostname |
| myapisite.apihost | <code>Object</code> | mycpapi.json |

**Example**  
```js
create auth/mycpapi.json file
{
	"chkp": {
		"host": "SET.YOUR.HOSTNAME",
		"port": "443",
		"path": "/web_api",
		"method": "POST",
		"headers": {
			"Content-Type": "application/json"
		}
	}
}
```
<a name="mycred"></a>

## mycred
Variable required from auth/mycpauth.json

**Kind**: global constant  
**Params**: <code>Object</code> credentials - auth/mycpauth.json  
**Example**  
```js
create auth/mycpauth.json file
{
		"user": "apiuser",
		"password": "PASSWORD"
}
```
<a name="showObjects"></a>

## showObjects(ip) ⇒ [<code>Array.&lt;uid&gt;</code>](#uid)
Object use for an IP

**Kind**: global function  
**Returns**: [<code>Array.&lt;uid&gt;</code>](#uid) - Direct and indirect object usage  

| Param | Type | Description |
| --- | --- | --- |
| ip | <code>String</code> | IP address to search for |

<a name="checkObject"></a>

## checkObject(uid) ⇒ [<code>Array.&lt;uid&gt;</code>](#uid)
Object verify IP matches filter

**Kind**: global function  
**Returns**: [<code>Array.&lt;uid&gt;</code>](#uid) - -  array of safe UID's to verify usage against  

| Param | Type | Description |
| --- | --- | --- |
| uid | <code>Array.&lt;String&gt;</code> | UID to verify IP address filter |

<a name="uid"></a>

## uid : <code>Array.&lt;Object&gt;</code>
where-used returned data format

**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| used-directly | <code>Object</code> | Direct use of object |
| used-directly.total | <code>Number</code> | Total count of usage |
| used-directly.objects | <code>Array.&lt;Object&gt;</code> | Array of object dependencies |
| used-directly.access-control-rules | <code>Array.&lt;Object&gt;</code> | Array of access rule dependencies |
| used-directly.nat-rules | <code>Array.&lt;Object&gt;</code> | Array of nat rule dependencies |
| used-directly.threat-prevention-rules | <code>Array.&lt;Object&gt;</code> | Array of threat inspection rules |
| used-indirectly | <code>Object</code> | Indirect or nested use of object |
| used-indirectly.total | <code>Number</code> | Total count of indirect use |
| used-indirectly.objects | <code>Array.&lt;Object&gt;</code> | Array of object references |
| used-indirectly.access-control-rules | <code>Array.&lt;Object&gt;</code> | Array of nested access rule |
| used-indirectly.nat-rules | <code>Array.&lt;Object&gt;</code> | Array of indirect nat rules |
| used-indirectly.threat-prevention-rules | <code>Array.&lt;Object&gt;</code> | Array of nested threat rules |

**Example**  
```js
{ ip: [
       {
         uid: [
         	  { 
	          used-directly: {
	       			  total: 0,
	        		  access-control-rules[],
	        		  nat-rules[],
	        		  threat-prevention-rules[],
	        		  objects[]
	        		  },
	      	  used-indirectly: {
	       			  total: 0,
	        		  access-control-rules[],
	        		  nat-rules[],
	        		  threat-prevention-rules[],
	        		  objects[]
	        		  }
             }
          ] 
       }
    ]
 }
```
