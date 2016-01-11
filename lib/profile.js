'use strict';
/**
 * Parse profile.
 *
 * @param {Object|String} json
 * @return {Object}
 * @api private
 */

exports.parse = function(json) {
  if ('string' === typeof json) {
    json = JSON.parse(json);
  }

  var profile = {};
  profile.id = json.entry.id;
  profile.displayName = json.entry.displayName;
  profile.userid = profile.id.replace(/urn:lsid:lconn.ibm.com:profiles.person:/i, '');
  profile.emails = [];

  if (json.entry) {
    if (Array.isArray(json.entry.emails)) {
      profile.emails = json.entry.emails;
    }
    if (json.entry.appData && json.entry.appData.connections){
      profile.isExternal = !!json.entry.appData.connections.isExternal;
      profile.organizationId = !!json.entry.appData.connections.organizationId;
    }
  }

  return profile;
};


/*
{
  "entry": {
    "appData": {
      "connections": {
        "isExternal": "false",
        "organizationId": "urn:lsid:lconn.ibm.com:connections.organization:00000000-0000-0000-0000-000000000000"
      }
    },
    "displayName": "Benjamin Kroeger",
    "emails": [{
      "type": "primary",
      "value": "bkroeger@sg.ibm.com",
      "primary": true
    }],
    "id": "urn:lsid:lconn.ibm.com:profiles.person:87f2c6c0-3ae5-1033-85b6-9fda8af4f3da"
  }
}
*/
