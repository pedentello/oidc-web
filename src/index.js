/* jslint esversion:9 */
/* global process, Buffer*/
// login-and-consent.js
// ------------------------------------------------------------------
//
// A node app that implements an authentication and consent-granting web
// app. This thing implements what is known in the OAuth docs as the
// Authorization Server. This app uses jade for view rendering, and
// bootstrap CSS in the HTML pages, but those details are irrelevant for
// its main purpose.
//
// Run this with
//     node ./login-and-consent.js
//
// See the package.json for dependencies.
//
// This app is designed to also run on heroku. In fact, since Edge needs
// to redirect to the login app, it works best if this app runs in a
// server that is accessible from the internet.
//
// To pop the login page:
// GET https://ORGNAME-ENVNAME-test.apigee.net/PROXYBASEPATH/oauth2/authorize?client_id=VALID_CLIENT_ID_HERE&redirect_uri=http://dinochiesa.github.io/openid-connect/callback-handler.html&response_type=id_token&scope=openid%20profile&nonce=A12345&state=ABCDEFG
//
// Sunday, 28 February 2016, 13:47
//
// ------------------------------------------------------------------

const express = require("express"),
  bodyParser = require("body-parser"),
  querystring = require("querystring"),
  morgan = require("morgan"), // a logger
  request = require("request"),
  path = require("path"),
  defaultAppLogo = "http://i.imgur.com/6DidtRS.png",
  app = express(),
  config = require("./config/config.json");

require("./lib/dateExtensions.js");

function logError(e) {
  //console.log('unhandled error: ' + e);
  console.log("unhandled error:  " + JSON.stringify(e));
  if (e.stack) {
    console.log(e.stack);
  }
}

function copyHash(obj) {
  var copy = {};
  if (null !== obj && typeof obj === "object") {
    Object.keys(obj).forEach(function (attr) {
      copy[attr] = obj[attr];
    });
  }
  return copy;
}

function formifyHash(obj) {
  // By default, qs serializes an array like roles : [ 'foo', 'bar', 'bam']
  // into roles[0]=foo&roles[1]=bar&roles[2]=bam
  // We want
  // into roles=foo bar bam
  var result = {};
  Object.keys(obj).forEach(function (key) {
    var prop = obj[key];
    result[key] = Array.isArray(prop) ? prop.join(" ") : prop;
  });
  return result;
}

function base64Encode(item) {
  return new Buffer(item).toString("base64");
}

function base64Decode(item) {
  return new Buffer(item, "base64").toString("ascii");
}

function getGrantType(responseType) {
  let parts = responseType.split(" ");
  return parts.indexOf("code") !== -1 ? "authorization_code" : "implicit";
}

function authenticateUser(ctx) {
  console.log("authenticateUser ctx: " + JSON.stringify(ctx, null, 2));

  return new Promise((resolve, reject) => {
    // send a query to Edge to authenticate user

    //let sessionEndpoint = ctx.oidcroot + '/session';
    let usersEndpoint = "https://pedentello-eval-test.apigee.net/v1/users";

    const options = {
      method: "POST",
      uri: usersEndpoint + "/authenticate",
      headers: {
        apikey: config.usersApi.apikey,
        Accept: "application/json"
      },
      json: ctx.credentials
    };

    console.log(
      "authenticateUser request: " + JSON.stringify(options, null, 2)
    );

    request(options, function (error, response, body) {
      console.log("authenticateUser response: " + body);
      console.log("authenticateUser, statusCode = " + response.statusCode);
      console.log("authenticateUser, reference = " + body.reference);

      if (error) {
        return reject(error);
      }
      if (response.statusCode === 200) {
        try {
          ctx.loginStatus = 200;
          ctx.reference = body.reference;
          ctx.userInfo = ctx.credentials;
        } catch (exc1) {
          console.log("authenticateUser exception: " + exc1.message);
          reject(exc1);
        }
        resolve(ctx);
      } else if (response.statusCode === 407) {
        try {
          ctx.loginStatus = 407;
          ctx.reference = body.reference;
          ctx.userInfo = ctx.credentials;
        } catch (exc1) {
          console.log("authenticateUser exception: " + exc1.message);
          reject(exc1);
        }
        resolve(ctx);
      } else if (response.statusCode === 409) {
        try {
          ctx.loginStatus = 409;
          ctx.errorMessageLogin =
            "Senha inválida na autenticação, X tentativas restantes antes do bloqueio.";
          ctx.userInfo = ctx.credentials;
        } catch (exc1) {
          console.log("authenticateUser exception: " + exc1.message);
          reject(exc1);
        }
        resolve(ctx);
      } else {
        ctx.errorMessageLogin = "Sistema indisponível";
        console.log("authenticateUser, statusCode = " + response.statusCode);
        resolve(ctx);
      }
    });
  });
}

function validatePassword2(ctx) {
  console.log("validatePassword2 ctx: " + JSON.stringify(ctx, null, 2));

  return new Promise((resolve, reject) => {
    // send a query to Edge to validate 2FA

    let usersEndpoint = "https://pedentello-eval-test.apigee.net/v1/users";

    const options = {
      method: "POST",
      uri: usersEndpoint + "/authenticate",
      headers: {
        apikey: config.usersApi.apikey,
        Accept: "application/json"
      },
      json: ctx.credentials2
    };

    console.log(
      "validatePassword2 request: " + JSON.stringify(options, null, 2)
    );

    request(options, function (error, response, body) {
      console.log("validatePassword2 response: " + body);
      console.log("validatePassword2 statusCode: " + response.statusCode);

      if (error) {
        return reject(error);
      }

      if (response.statusCode === 200) {
        try {
          ctx.password2Validated = true;
        } catch (exc1) {
          console.log("validatePassword2 exception: " + exc1.message);
          reject(exc1);
        }
        resolve(ctx);
      } else {
        ctx.password2Validated = false;
        console.log("validatePassword2, statusCode = " + response.statusCode);
        resolve(ctx);
      }
    });
  });
}

function postAuthorization(ctx) {
  return new Promise((resolve, reject) => {
    // the path to the auth endpoint needs to be consistent with the API proxy
    var authEndpoint =
        "https://pedentello-eval-test.apigee.net/auth/oauth/v2/auth",
      formParams = copyHash(ctx.userInfo),
      options = {
        method: "POST",
        uri: authEndpoint,
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          Accept: "application/json"
        },
        form: formifyHash({
          ...formParams,
          grant_type: getGrantType(ctx.response_type)
        })
      };

    console.log("postAuthorization, auth endpoint:" + authEndpoint);
    console.log("postAuthorization, context:" + JSON.stringify(ctx, null, 2));
    options.form.sessionid = ctx.txid;
    delete options.form.status;

    request(options, function (error, response) {
      console.log("auth response: " + response.statusCode);
      if (response.statusCode === 302) {
        try {
          ctx.authRedirLoc = response.headers.location;
        } catch (exc1) {
          console.log("auth exception: " + exc1.message);
          console.log(exc1.stack);
          reject(exc1);
        }
      } else {
        console.log("auth, statusCode = " + response.statusCode);
      }
      resolve(ctx);
    });
  });
}

function inquireOidcSessionId(ctx) {
  console.log("inquireOidcSessionId ctx: " + JSON.stringify(ctx, null, 2));

  return new Promise((resolve, reject) => {
    // send a query to Edge to ask about the OIDC session

    if (!ctx.oidcroot) {
      return reject({ message: "no oidc server" });
    }

    //let sessionEndpoint = ctx.oidcroot + '/session';
    let sessionEndpoint = ctx.oidcroot;

    const options = {
      method: "GET",
      uri:
        sessionEndpoint + "/info?" + querystring.stringify({ txid: ctx.txid }),
      headers: {
        apikey: config.sessionApi.apikey,
        Accept: "application/json"
      }
    };

    console.log(
      "inquireOidcSessionId request: " + JSON.stringify(options, null, 2)
    );

    request(options, function (error, response, body) {
      console.log("inquireOidcSessionId response: " + body);
      if (error) {
        return reject(error);
      }
      if (response.statusCode === 200) {
        try {
          body = JSON.parse(body);
          // Edge knows about the session and has returned information about it.
          ctx.sessionInfo = body;
        } catch (exc1) {
          console.log("inquireOidcSessionId exception: " + exc1.message);
          reject(exc1);
        }
        resolve(ctx);
      } else {
        console.log(
          "inquireOidcSessionId, statusCode = " + response.statusCode
        );
        resolve(ctx);
      }
    });
  });
}

app.use(morgan("combined")); // logger
app.use("/css", express.static(path.join(__dirname, "css")));
app.use("/img", express.static(path.join(__dirname, "img")));
app.use("/js", express.static(path.join(__dirname, "js")));
app.engine("html", require("ejs").renderFile);
app.set("view engine", "html");
app.set("views", path.join(__dirname, "/views"));

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));

// parse application/json
app.use(bodyParser.json());

app.get("/logout", function (request, response) {
  request.session = null; // logout
  response.redirect("manage");
});

// display the cancel page
app.get("/cancel", function (request, response) {
  response.status(200);
  response.render("cancel", {
    title: "Declined",
    mainMessage: "Você recusou."
  });
});

// display the Info form
app.get("/loginInfo", function (request, response) {
  function renderLoginInfo(ctx) {
    // sessionInfo:
    //   client_id
    //   response_type
    //   response_type_token
    //   response_type_id_token
    //   response_type_code
    //   scope
    //   redirect_uri
    //   req_state
    //   appName
    //   appLogoUrl
    //   nonce
    //   display
    //   login_hint
    if (ctx.sessionInfo && ctx.sessionInfo.open_id) {
      ctx.viewData = copyHash(ctx.sessionInfo);
      ctx.viewData.action = "Continuar";
      ctx.viewData.txid = ctx.txid;
      ctx.viewData.oidcroot = ctx.oidcroot;
      ctx.viewData.appLogoUrl = ctx.sessionInfo.appLogoUrl || defaultAppLogo;
      ctx.viewData.errorMessage = null; // must be present and null
      response.render("loginInfo", ctx.viewData);
    }

    return ctx;
  }

  var context = { txid: request.query.sessionid };
  if (request.query.oidcroot) {
    context.oidcroot = decodeURIComponent(request.query.oidcroot);
  } else {
    context.oidcroot = " https://pedentello-eval-test.apigee.net/oidc-session";
  }
  Promise.resolve(context)
    .then(inquireOidcSessionId)
    .then(renderLoginInfo)
    .catch((e) => {
      logError(e);
      response.status(404).render("error400", e);
    });
});

// display the login form
app.get("/login", function (request, response) {
  function renderLogin(ctx) {
    // sessionInfo:
    //   client_id
    //   response_type
    //   response_type_token
    //   response_type_id_token
    //   response_type_code
    //   scope
    //   redirect_uri
    //   req_state
    //   appName
    //   appLogoUrl
    //   nonce
    //   display
    //   login_hint
    if (ctx.sessionInfo && ctx.sessionInfo.open_id) {
      ctx.viewData = copyHash(ctx.sessionInfo);
      ctx.viewData.action = "Entrar";
      ctx.viewData.txid = ctx.txid;
      ctx.viewData.oidcroot = ctx.oidcroot;
      ctx.viewData.errorMessage = null; // must be present and null
      response.render("login", ctx.viewData);
    }

    return ctx;
  }

  var context = { txid: request.query.sessionid };
  if (request.query.oidcroot) {
    context.oidcroot = decodeURIComponent(request.query.oidcroot);
  } else {
    context.oidcroot = " https://pedentello-eval-test.apigee.net/oidc-session";
  }
  Promise.resolve(context)
    .then(inquireOidcSessionId)
    .then(renderLogin)
    .catch((e) => {
      logError(e);
      response.status(404).render("error400", e);
    });
});

app.post("/validateLoginInfo", function (request, response) {
  console.log("BODY: " + JSON.stringify(request.body));
  if (!request.body.redirect_uri) {
    response.status(400);
    response.render("error", {
      errorMessage: "Bad request"
    });
    return;
  }

  if (request.body.submit !== "yes") {
    console.log("user has declined to login");
    // ! request.body.redirect_uri.startsWith('oob') &&
    // ! request.body.redirect_uri.startsWith('urn:ietf:wg:oauth:2.0:oob')
    response.status(302);
    response.header(
      "Location",
      request.body.redirect_uri + "?error=access_denied"
    );
    response.end();
    return;
  }

  Promise.resolve({
    txid: request.body.sessionid
  })
    .then(function (ctx) {
      // This app got a 200 ok from the user Authentication service.
      response.status(200);
      response.render("login", {
        action: "Login",
        txid: ctx.txid,
        oidcroot: request.body.oidcroot,
        client_id: request.body.client_id,
        response_type: request.body.response_type,
        req_scope: request.body.requestedScopes,
        redirect_uri: request.body.redirect_uri,
        req_state: request.body.clientState,
        appName: request.body.appName,
        appLogoUrl: request.body.appLogoUrl || defaultAppLogo,
        display: request.body.display,
        login_hint: request.body.login_hint,
        errorMessage: null
      });

      return ctx;
    })
    .catch(logError);
});

// respond to the login form postback
app.post("/validateLoginAndConsent", function (request, response) {
  console.log("BODY: " + JSON.stringify(request.body));
  if (!request.body.redirect_uri) {
    response.status(400);
    response.render("error", {
      errorMessage: "Bad request"
    });
    return;
  }

  if (request.body.submit !== "yes") {
    console.log("user has declined to login");
    // ! request.body.redirect_uri.startsWith('oob') &&
    // ! request.body.redirect_uri.startsWith('urn:ietf:wg:oauth:2.0:oob')
    response.status(302);
    response.header(
      "Location",
      request.body.redirect_uri + "?error=access_denied"
    );
    response.end();
    return;
  }

  // validate form data
  if (!request.body.username || !request.body.password) {
    // missing form fields
    response.status(401);
    response.render("login", {
      action: "Entrar",
      txid: request.body.sessionid,
      oidcroot: request.body.oidcroot,
      client_id: request.body.client_id,
      response_type: request.body.response_type,
      req_scope: request.body.requestedScopes,
      redirect_uri: request.body.redirect_uri,
      req_state: request.body.clientState,
      appName: request.body.appName,
      appLogoUrl: request.body.appLogoUrl || defaultAppLogo,
      display: request.body.display,
      login_hint: request.body.login_hint,
      reference: request.body.referente,
      errorMessage: "You must specify a user and a password."
    });
    return;
  }

  Promise.resolve({
    credentials: {
      username: request.body.username,
      password: request.body.password
    },
    txid: request.body.sessionid
  })
    .then(authenticateUser)
    .then(function (ctx) {
      if (ctx.loginStatus !== 200 && ctx.loginStatus !== 407) {
        response.status(401);
        response.render("login", {
          action: "Entrar",
          txid: ctx.txid,
          oidcroot: request.body.oidcroot,
          client_id: request.body.client_id,
          response_type: request.body.response_type,
          req_scope: request.body.requestedScopes,
          redirect_uri: request.body.redirect_uri,
          req_state: request.body.clientState,
          appName: request.body.appName,
          appLogoUrl: request.body.appLogoUrl || defaultAppLogo,
          display: request.body.display,
          login_hint: request.body.login_hint,
          reference: request.body.referente,
          errorMessage: ctx.errorMessageLogin
        });
        return ctx;
      }

      // else, a-ok.
      // This app got a 200 ok from the user Authentication service.
      response.status(200);
      response.render("consent", {
        action: "Autorizar",
        txid: ctx.txid,
        oidcroot: request.body.oidcroot,
        client_id: request.body.client_id,
        response_type: request.body.response_type,
        req_scope: request.body.requestedScopes,
        redirect_uri: request.body.redirect_uri,
        req_state: request.body.clientState,
        appName: request.body.appName,
        appLogoUrl: request.body.appLogoUrl || defaultAppLogo,
        display: request.body.display,
        login_hint: request.body.login_hint,
        reference: ctx.reference,
        errorMessage: null,
        userProfile: base64Encode(JSON.stringify(ctx.userInfo))
      });

      return ctx;
    })
    .catch(logError);
});

// respond to the consent form postback
app.post("/grantConsent", function (request, response) {
  console.log("/grantConsent BODY: " + JSON.stringify(request.body));
  if (!request.body.redirect_uri) {
    response.status(400);
    response.render("error", { errorMessage: "Bad request" });
    return;
  }

  if (request.body.submit !== "yes") {
    console.log("user has declined to consent");
    // ! request.body.redirect_uri.startsWith('oob') &&
    // ! request.body.redirect_uri.startsWith('urn:ietf:wg:oauth:2.0:oob')

    response.status(302);
    response.header(
      "Location",
      request.body.redirect_uri + "?error=access_denied"
    );
    response.end();
    return;
  }

  Promise.resolve({
    userInfo: JSON.parse(base64Decode(request.body.userProfile)),
    txid: request.body.sessionid,
    credentials2: {
      token: request.body.password2,
      reference: request.body.reference
    },
    response_type: request.body.response_type,
    oidcroot: request.body.oidcroot
  })
    .then(validatePassword2)
    .then(postAuthorization)
    .then(function (ctx) {
      if (ctx.password2Validated !== true) {
        response.status(401);
        response.render("consent", {
          action: "Autorizar",
          txid: ctx.txid,
          oidcroot: request.body.oidcroot,
          client_id: request.body.client_id,
          response_type: request.body.response_type,
          req_scope: request.body.requestedScopes,
          redirect_uri: request.body.redirect_uri,
          req_state: request.body.clientState,
          appName: request.body.appName,
          appLogoUrl: request.body.appLogoUrl || defaultAppLogo,
          display: request.body.display,
          login_hint: request.body.login_hint,
          reference: request.body.referente,
          userProfile: base64Encode(JSON.stringify(ctx.userInfo)),
          errorMessage: "Código de verificação incorreto."
        });
        return ctx;
      }

      response.status(302);
      if (!ctx.authRedirLoc) {
        // the post did not succeed
        response.header(
          "Location",
          request.body.redirect_uri + "?error=server_error"
        );
      } else {
        response.header("Location", ctx.authRedirLoc);
      }
      response.end();
      return ctx;
    })
    .catch(logError);
});

app.get("/*", function (request, response) {
  response.status(404);
  response.render("error404", {
    mainMessage: "Nada aqui!",
    title: "That's 404 dude!"
  });
});

process.on("exit", function (code) {
  console.log("Script terminating with code %s", code);
});

process.on("uncaughtException", function (err) {
  console.log(err.stack);
});

var httpPort = process.env.PORT || 8080;
app.listen(httpPort, function () {
  console.log("Listening on port " + httpPort);
});
