const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
    randomString,
    containsAll,
    decodeAuthCredentials,
    timeout,
} = require("./utils")

const config = {
    port: 9001,
    privateKey: fs.readFileSync("assets/private_key.pem"),

    clientId: "my-client",
    clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
    redirectUri: "http://localhost:9000/callback",

    authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
    "my-client": {
        name: "Sample Client",
        clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
        scopes: ["permission:name", "permission:date_of_birth"],
    },
    "test-client": {
        name: "Test Client",
        clientSecret: "TestSecret",
        scopes: ["permission:name"],
    },
}

const users = {
    user1: "password1",
    john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))

/*
Your code here
*/
app.get('/authorize', (req, res) => {
    let clientID = req.query.client_id;
    const client = clients[clientID];
    if (!client) {
        res.status(401).send("Error: client not authorized");
        return;
    }
    let clientScope = req.query.scope.split(" ");
    if (typeof req.query.scope !== "string" || !containsAll(client.scopes, clientScope)) {
        res.status(401).send("Error: invalid scope requested");
        return;
    }
    // else {
    //     res.status(200).send("Error: invalid scope requested");
    //     return;
    // }
    const requestId = randomString();
    requests[requestId] = req.query;
    res.render("login", {client: clients[clientID], scope: req.query.scope, requestId});

    app.post('/approve', (reqP, resP) => {
        // here I can handle incoming post request from the login page.

        const {userName, password, requestId} = reqP.body;
        if (!userName || users[userName !== password]) {
            res.status[401].send("Error: users not authorized");
            return;
        }
        const clientReq = requests[requestId];
        if (!clientReq) {
            res.status(401).send("Error: invalid user request");
            return;
        }
        const code = randomString();
        authorizationCodes[code] = {clientReq, userName};
        let redirectUri = url.parse(clientReq.redirect_uri);
        redirectUri.query = {
            code,
            state: clientReq.state
        }
        resP.redirect(url.format(redirectUri));

    })

    app.post('/token', (reqT, resT) => {
        let authCredentials = reqT.headers.authorization;
        if (authCredentials) {
            resT.status(401).send("Error: not authorized");
            return;
        }
        const {client_id, clientSecret} = decodeAuthCredentials(authCredentials);
        const clientAuth = clients[client_id];
        if (!clientAuth || clientAuth.clientSecret !== clientSecret) {
            resT.status(401).send("Error: client not authorized");
            return;
        }
        let code1 = req.body.code;
        if (code1 || !authorizationCodes[code1]) {
            res.status(401).send("Error: invalid code");
            return;
        }
        const {clientReq, userName} = authorizationCodes[code1];
        delete authCredentials[code1];
        const token = jwt.sign({
                userName,
                scope: clientReq.scope
            }, config.privateKey,
            {
                algorithm: "RS256",
                expiresIn: 300,
                issuer: "http://localhost:" + config.port
            }, () => {
            });
        resT.json({access_token: token, token_type: "Bearer", scope: clientReq.scope});
    })
});

const server = app.listen(config.port, "localhost", function () {
    var host = server.address().address
    var port = server.address().port
})

// for testing purposes

module.exports = {app, requests, authorizationCodes, server}
