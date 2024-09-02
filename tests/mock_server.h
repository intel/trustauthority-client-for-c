#ifndef mock_server_H
#define mock_server_H

#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <cpprest/http_listener.h>
#include <cpprest/json.h>

using namespace std;
using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;

class MockServer
{
public:
    MockServer(const string &responseJson);
    void start();
    void stop();

private:
    void handleGetRequest(http_request request, const string &responseJson);
    void handlePostRequest(http_request request, const string &responseJson);
    char *validTokenResponse();
    string generateResponse(const http_request &request, const string &httpMethod, const string &responseJson);
    string generateResponseCRL(const http_request & request, const string & httpMethod, const string & responseJson);
    bool started;
    string responseJson;
    http_listener listener;
    std::condition_variable cv;
    std::mutex mutex_;
};

#endif