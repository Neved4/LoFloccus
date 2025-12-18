#include "webdav_server.h"

#include "civetweb.h"

#include <memory>
#include <string>
#include <vector>

namespace {
mg_context *ctx = nullptr;
std::unique_ptr<struct ServerState> serverState;

struct ServerState {
	std::string user;
	std::string password;
};

const char *cstr(const std::string &value)
{
	return value.empty() ? nullptr : value.c_str();
}

bool decodeBasicAuth(const char *header, std::string &user,
	std::string &password)
{
	if (header == nullptr) {
		return false;
	}

	std::string token(header);
	const std::string prefix = "Basic ";
	if (token.compare(0, prefix.size(), prefix) != 0) {
		return false;
	}

	std::string encoded = token.substr(prefix.size());
	if (encoded.empty()) {
		return false;
	}

	std::string decoded(encoded.size(), '\0');
	size_t decodedSize = decoded.size();
	int result = mg_base64_decode(encoded.c_str(), encoded.size(),
		reinterpret_cast<unsigned char *>(&decoded[0]),
		&decodedSize);
	if (result != -1 || decodedSize == 0) {
		return false;
	}
	decoded.resize(decodedSize - 1);

	size_t sep = decoded.find(':');
	if (sep == std::string::npos) {
		return false;
	}

	user = decoded.substr(0, sep);
	password = decoded.substr(sep + 1);
	return true;
}

int sendAuthRequired(mg_connection *conn)
{
	const char *headers =
		"WWW-Authenticate: Basic realm=\"Restricted\"\r\n";
	mg_printf(conn,
		"HTTP/1.1 401 Unauthorized\r\n"
		"%s"
		"Content-Length: 0\r\n\r\n",
		headers);
	return 0;
}

int authHandler(mg_connection *conn, void *cbdata)
{
	auto *state = static_cast<ServerState *>(cbdata);
	if (state == nullptr) {
		return 0;
	}
	if (state->user.empty() && state->password.empty()) {
		return 1;
	}

	std::string user;
	std::string password;
	if (!decodeBasicAuth(mg_get_header(conn, "Authorization"),
		user, password)) {
		return sendAuthRequired(conn);
	}
	if (user != state->user || password != state->password) {
		return sendAuthRequired(conn);
	}
	return 1;
}
}

bool serverStart(const std::string &address, const std::string &port,
	const std::string &root, const std::string &user,
	const std::string &password)
{
	if (ctx != nullptr) {
		serverStop();
	}

	serverState = std::make_unique<ServerState>();
	serverState->user = user;
	serverState->password = password;

	std::string listen = address + ":" + port;
	std::vector<const char *> opts = {
		"document_root",
		cstr(root),
		"listening_ports",
		cstr(listen),
		"enable_directory_listing",
		"yes",
		"enable_webdav",
		"yes",
		nullptr
	};

	ctx = mg_start(nullptr, nullptr, opts.data());
	if (ctx == nullptr) {
		serverState.reset();
		return false;
	}

	mg_set_auth_handler(ctx, "**", authHandler, serverState.get());
	return true;
}

void serverStop()
{
	if (ctx == nullptr) {
		return;
	}
	mg_stop(ctx);
	ctx = nullptr;
	serverState.reset();
}
