# passport-ibm-connections-basic
A passport basic authentication strategy for IBM Connections 

This strategy allows to use IBM Connections as an authentication backend by leveraging the OpenSocial People API with the basic authentication interceptor in WebSphere Application Server.

Available options and defaults:

```
{
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: false,
    skipUserProfile: false,
    authSchema: 'https',
    authHostname: false,
    authPort: 443,
    openSocial: '/connections',
    authMethod: 'GET',
    defaultRequestHeaders: {
      'user-agent': 'Mozilla/5.0'
    }
  }
 ```

 `authHostname` is required!