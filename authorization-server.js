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
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get('/authorize', (req, res) => {
	let clientID = req.query.client[config.clientId];
	if (clientID){
		let clientScope = req.query.scope.split(" ");
		if (containsAll(clientScope, clients[clientID])) {
			const requestId = requests.setHeader(req.query.randomString());
			res.render("login", {client: clients[clientID], scope: req.query.scope, requestId: requestId});
			app.post('/approve', (reqP, resP) => {
				// here I can handle incoming post request from the login page.
				if (reqP.body.userName in users) {
					if (users[reqP.body.userName] !== reqP.body.password) {
						res.status(401).end();
					}
				} else {
					res.status(401).end();
				}
				if (requests[requestId]) {
					const request = requests[requestId];
					const authKey = randomString();
					authorizationCodes[authKey] = request;
					let redirectUrl = new URL("http://www.example.com/go-here");
					redirectUrl.searchParams.append("code", "rof5ijf");
					redirectUrl.searchParams.append("state", "pc03ns9S");
					resP.redirect("http://www.example.com/go-here");

					app.post('/token', (reqT, resT) =>{
						if (reqT.headers.authorization){
							let clientSecret = decodeAuthCredentials(reqT.headers.authorization);
							if (clientSecret.clientId === clientID && clientSecret.clientSecret === clients[clientID]) {
								if (req.body.code in authorizationCodes) {
									const secretMatch = req.body.code in authorizationCodes;
									const jwtString = jwt.sign({
										userName: secretMatch.userName,
										scope: secretMatch.scope
									}, 'assets/private_key.pem', {"alg": "RS256"}, () => {
									});
									res.setResponseBody({"access_token": jwtString, "token_type": "Bearer"});
									res.send();
									res.status(200).end();
								} else {
									res.status(401).end();
								}
							}
						} else {
							res.status(401).end();
						}
					})
				} else {
					res.status(401).end();
				}
			})
		} else {
			res.status(401).end();
		}
	} else {
		res.status(401).end();
	}
});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
