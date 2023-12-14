#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include "mock_server.h"

// Declare and initialize the mutex
std::mutex mockServerMutex;

MockServer::MockServer(const string & responseJson):started(false),
	responseJson(responseJson)
{
	listener = http_listener("http://localhost:8080");
	listener.support(methods::GET,
			[this, responseJson] (http_request request) {
			handleGetRequest(request, responseJson);
			});

	listener.support(methods::POST,
			[this, responseJson] (http_request request) {
			handlePostRequest(request, responseJson);
			});
}

void MockServer::start()
{
	std::lock_guard < std::mutex > lock(mockServerMutex);
	if (!started) {
		thread serverThread([this] () {
				listener.open().wait();
				started = true; cv.notify_all();
				}
				);
		serverThread.detach();

		// Wait until the server is running
		std::unique_lock < std::mutex > lock(mutex_);
		cv.wait(lock,[this] () {
				return started;
				}
		       );
	}
}

void MockServer::stop()
{
	std::lock_guard < std::mutex > lock(mockServerMutex);
	if (started) {
		listener.close().wait();
		started = false;
	}
}

void MockServer::handleGetRequest(http_request request,
		const string & responseJson)
{
	string response = generateResponse(request, "GET", responseJson);
	request.reply(status_codes::OK, response, "text/plain");
}

void MockServer::handlePostRequest(http_request request,
		const string & responseJson)
{
	string response = generateResponse(request, "POST", responseJson);
	request.reply(status_codes::OK, response, "text/plain");
}

char *MockServer::validTokenResponse()
{
	const char *validToken1 =
		"{\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEyMyIsImprdSI6Imh0dHBzOlxcbG9jYWxob3N0OjgwODAifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.cCOaUSoglcRlEiqoKIxV0bC8PptNuedV_EaXD2BDCng\"}";
	char *validToken = (char *) calloc(1, 235 * sizeof(char));
	memcpy(validToken, validToken1, 234);
	return validToken;
}

string MockServer::generateResponse(const http_request & request,
		const string & httpMethod,
		const string & responseJson)
{
	string path = request.relative_uri().path();
	string method = request.method();

	string httpResponse;
	if (httpMethod == methods::GET) {
		if (path == "/appraisal/v1/version") {
			httpResponse = responseJson;
		} else if (path == "/appraisal/v1/nonce") {
			httpResponse = responseJson;
		} else if (path == "/token_signing_cert") {
			httpResponse = responseJson;
		} else if (path == "/invalid-cert/certs") {
			httpResponse = responseJson;
		} else if (path == "/invalid-x5c/certs") {
			httpResponse = responseJson;
		} else if (path == "/kid-mismatch/certs") {
			httpResponse = responseJson;
		} else if (path == "/invalid-x5c-count/certs") {
			httpResponse = responseJson;
		} else if (path == "/unknown-x5c/certs") {
			httpResponse = responseJson;
		} else if (path == "/invalid-e-and-n/certs") {
			httpResponse = responseJson;
		} else if (path == "/wrong-signature/certs") {
			httpResponse = responseJson;
		} else if (path == "/valid-jwks/certs") {
			httpResponse = responseJson;
		} else {
			httpResponse = "Invalid GET request";
		}
	} else if (httpMethod == methods::POST
			&& path == "/appraisal/v1/attest") {
		httpResponse = validTokenResponse();
	} else {
		httpResponse = "Invalid POST request";
	}

	http_response response(status_codes::OK);
	response.set_body(httpResponse, "text/plain");

	return response.extract_string().get();
}
