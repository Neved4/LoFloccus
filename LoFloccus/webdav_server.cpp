#include "webdav_server.h"

#include "civetweb.h"
#include "request.h"
#include "response.h"
#include "server.h"

#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {
class RequestCivet final : public WebDav::Request {
public:
	RequestCivet(mg_connection *conn, const std::string &path)
		: Request(path), conn(conn),
		requestInfo(mg_get_request_info(conn))
	{
	}

	std::string getHeader(std::string name) override
	{
		const char *value = mg_get_header(conn, name.c_str());
		if (value == nullptr) {
			return "";
		}
		return std::string(value);
	}

	size_t getContentLength() override
	{
		if (requestInfo == nullptr) {
			return 0;
		}
		if (requestInfo->content_length < 0) {
			return 0;
		}
		return static_cast<size_t>(requestInfo->content_length);
	}

	int readBody(char *buf, int len) override
	{
		return mg_read(conn, buf, static_cast<size_t>(len));
	}

private:
	mg_connection *conn;
	const mg_request_info *requestInfo;
};

class ResponseCivet final : public WebDav::Response {
public:
	explicit ResponseCivet(mg_connection *conn)
		: conn(conn), statusCode(200), statusMessageText("OK"),
		contentType("text/plain"), headersSent(false),
		headersPrepared(false)
	{
		setDavHeaders();
	}

	void setStatus(int code, std::string message) override
	{
		statusCode = code;
		statusMessageText = std::move(message);
	}

	void setContentType(const char *ct) override
	{
		if (ct == nullptr) {
			contentType.clear();
			return;
		}
		contentType = ct;
	}

	bool sendChunk(const char *buf, ssize_t len = -1) override
	{
		sendHeadersIfNeeded();
		if (len < 0) {
			len = static_cast<ssize_t>(strlen(buf));
		}
		if (len == 0) {
			return true;
		}
		return mg_write(conn, buf, static_cast<size_t>(len)) == len;
	}

	void closeChunk() override
	{
		sendHeadersIfNeeded();
	}

	void closeBody() override
	{
		sendHeadersIfNeeded();
	}

	void finalize()
	{
		sendHeadersIfNeeded();
	}

	bool hasSentHeaders() const
	{
		return headersSent;
	}

protected:
	void writeHeader(const char *header, const char *value) override
	{
		headerLines += header;
		headerLines += ": ";
		headerLines += value;
		headerLines += "\r\n";
		headersPrepared = true;
	}

private:
	void sendHeadersIfNeeded()
	{
		if (headersSent) {
			return;
		}
		if (!headersPrepared) {
			flushHeaders();
			headersPrepared = true;
		}

		std::string statusLine = "HTTP/1.1 " +
			std::to_string(statusCode) + " " +
			statusMessageText + "\r\n";
		mg_write(conn, statusLine.c_str(), statusLine.size());

		if (!contentType.empty()) {
			std::string typeLine = "Content-Type: " +
				contentType + "\r\n";
			mg_write(conn, typeLine.c_str(), typeLine.size());
		}

		mg_write(conn, headerLines.c_str(), headerLines.size());
		mg_write(conn, "\r\n", 2);
		headersSent = true;
	}

	mg_connection *conn;
	int statusCode;
	std::string statusMessageText;
	std::string contentType;
	std::string headerLines;
	bool headersSent;
	bool headersPrepared;
};

struct WebDavState {
	WebDavState(std::string rootPath, std::string user,
		std::string password)
		: rootPath(std::move(rootPath)), user(std::move(user)),
		password(std::move(password)), rootUri("/"),
		webDavServer(this->rootPath, rootUri)
	{
	}

	std::string rootPath;
	std::string user;
	std::string password;
	std::string rootUri;
	WebDav::Server webDavServer;
};

mg_context *ctx = nullptr;
std::unique_ptr<WebDavState> webDavState;

const char *cstr(const std::string &value)
{
	return value.empty() ? nullptr : value.c_str();
}

bool hasSuffix(const std::string &value, const std::string &suffix)
{
	if (value.size() < suffix.size()) {
		return false;
	}
	return value.compare(value.size() - suffix.size(), suffix.size(),
		suffix) == 0;
}

bool isAllowedRequest(const std::string &uri, const std::string &method)
{
	if (uri == "/" || uri.empty()) {
		return method == "HEAD" || method == "PROPFIND";
	}
	if (hasSuffix(uri, ".xbel") || hasSuffix(uri, ".xbel.lock")) {
		return true;
	}
	return hasSuffix(uri, ".html") || hasSuffix(uri, ".htm");
}

bool decodeBasicAuth(const std::string &token, std::string &user,
	std::string &password)
{
	std::string prefix = "Basic ";
	if (token.size() <= prefix.size()) {
		return false;
	}
	if (token.compare(0, prefix.size(), prefix) != 0) {
		return false;
	}

	std::string encoded = token.substr(prefix.size());
	std::string decoded(encoded.size(), '\0');
	size_t decodedSize = decoded.size();
	int result = mg_base64_decode(encoded.c_str(), encoded.size(),
		reinterpret_cast<unsigned char *>(&decoded[0]),
		&decodedSize);
	if (result != -1) {
		return false;
	}
	decoded.resize(decodedSize > 0 ? decodedSize - 1 : 0);

	size_t split = decoded.find(':');
	if (split == std::string::npos) {
		return false;
	}
	user = decoded.substr(0, split);
	password = decoded.substr(split + 1);
	return true;
}

bool checkAuth(mg_connection *conn, const WebDavState &state)
{
	if (state.user.empty() && state.password.empty()) {
		return true;
	}

	const char *authHeader = mg_get_header(conn, "Authorization");
	if (authHeader == nullptr) {
		return false;
	}

	std::string user;
	std::string password;
	if (!decodeBasicAuth(authHeader, user, password)) {
		return false;
	}

	return user == state.user && password == state.password;
}

std::string statusMessage(int code)
{
	switch (code) {
	case 200:
		return "OK";
	case 201:
		return "Created";
	case 204:
		return "No Content";
	case 207:
		return "Multi-Status";
	case 400:
		return "Bad Request";
	case 401:
		return "Unauthorized";
	case 403:
		return "Forbidden";
	case 404:
		return "Not Found";
	case 405:
		return "Method Not Allowed";
	case 409:
		return "Conflict";
	case 412:
		return "Precondition Failed";
	case 415:
		return "Unsupported Media Type";
	case 500:
		return "Internal Server Error";
	case 501:
		return "Not Implemented";
	case 507:
		return "Insufficient Storage";
	default:
		return "Error";
	}
}

int sendSimpleResponse(mg_connection *conn, int code,
	const std::string &message, const std::string &extraHeader)
{
	std::string body = message + "\n";
	std::string statusLine = "HTTP/1.1 " + std::to_string(code) +
		" " + message + "\r\n";
	mg_write(conn, statusLine.c_str(), statusLine.size());

	if (!extraHeader.empty()) {
		std::string headerLine = extraHeader + "\r\n";
		mg_write(conn, headerLine.c_str(), headerLine.size());
	}

	std::string headers = "Content-Type: text/plain\r\n"
		"Content-Length: " + std::to_string(body.size()) +
		"\r\n\r\n";
	mg_write(conn, headers.c_str(), headers.size());
	mg_write(conn, body.c_str(), body.size());

	return code;
}

int sendAuthRequired(mg_connection *conn)
{
	return sendSimpleResponse(conn, 401, "Unauthorized",
		"WWW-Authenticate: Basic realm=\"Restricted\"");
}

int handleWebDavRequest(mg_connection *conn, void *cbdata)
{
	auto *state = static_cast<WebDavState *>(cbdata);
	if (state == nullptr) {
		return 0;
	}

	const mg_request_info *requestInfo = mg_get_request_info(conn);
	if (requestInfo == nullptr || requestInfo->request_method == nullptr) {
		return 0;
	}

	std::string method = requestInfo->request_method;
	const char *localUri = requestInfo->local_uri;
	const char *requestUri = requestInfo->request_uri;
	std::string uri = localUri != nullptr ? localUri :
		(requestUri != nullptr ? requestUri : "/");

	if (!checkAuth(conn, *state)) {
		return sendAuthRequired(conn);
	}

	if (!isAllowedRequest(uri, method)) {
		return sendSimpleResponse(conn, 401, "Unauthorized",
			"");
	}

	std::string path = state->webDavServer.uriToPath(uri);
	RequestCivet request(conn, path);
	if (!request.parseRequest()) {
		return sendSimpleResponse(conn, 400, "Bad Request", "");
	}

	ResponseCivet response(conn);

	int status = 500;
	if (method == "COPY") {
		status = state->webDavServer.doCopy(request, response);
	} else if (method == "DELETE") {
		status = state->webDavServer.doDelete(request, response);
	} else if (method == "GET") {
		status = state->webDavServer.doGet(request, response);
	} else if (method == "HEAD") {
		status = state->webDavServer.doHead(request, response);
	} else if (method == "LOCK") {
		status = state->webDavServer.doLock(request, response);
	} else if (method == "MKCOL") {
		status = state->webDavServer.doMkcol(request, response);
	} else if (method == "MOVE") {
		status = state->webDavServer.doMove(request, response);
	} else if (method == "OPTIONS") {
		status = state->webDavServer.doOptions(request, response);
	} else if (method == "PROPFIND") {
		status = state->webDavServer.doPropfind(request, response);
	} else if (method == "PROPPATCH") {
		status = state->webDavServer.doProppatch(request, response);
	} else if (method == "PUT") {
		status = state->webDavServer.doPut(request, response);
	} else if (method == "UNLOCK") {
		status = state->webDavServer.doUnlock(request, response);
	} else {
		status = 405;
	}

	if (!response.hasSentHeaders()) {
		response.setStatus(status, statusMessage(status));
	}
	response.finalize();
	return status;
}
}

bool serverStart(const std::string &address, const std::string &port,
	const std::string &root, const std::string &user,
	const std::string &password)
{
	if (ctx != nullptr) {
		serverStop();
	}

	webDavState = std::make_unique<WebDavState>(root, user, password);

	std::string listen = address + ":" + port;
	std::vector<const char *> opts = {
		"document_root",
		cstr(root),
		"listening_ports",
		cstr(listen),
		nullptr
	};

	ctx = mg_start(nullptr, nullptr, opts.data());
	if (ctx == nullptr) {
		webDavState.reset();
		return false;
	}

	mg_set_request_handler(ctx, "**", handleWebDavRequest,
		webDavState.get());
	return true;
}

void serverStop()
{
	if (ctx == nullptr) {
		return;
	}
	mg_stop(ctx);
	ctx = nullptr;
	webDavState.reset();
}
