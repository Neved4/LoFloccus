#include "webdav_server.h"

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QHostAddress>
#include <QRandomGenerator>
#include <QSaveFile>
#include <QUrl>

#include <microhttpd.h>

#include <atomic>
#include <arpa/inet.h>
#include <cstring>
#include <mutex>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <thread>
#include <utility>

namespace {

struct ServerConfig {
	std::string address;
	std::string port;
	std::string root;
	std::string user;
	std::string password;
};

struct ConnectionState {
	std::string method;
	std::string body;
};

struct ServerState {
	ServerConfig cfg;
	MHD_Daemon *daemon;
	std::thread loop;
	std::atomic<bool> running;
	sockaddr_storage bindAddr;
	socklen_t bindLen;
};

ServerState *state = nullptr;
QHash<QString, QString> pathToToken;
QHash<QString, QString> tokenToPath;
std::mutex locksMutex;

bool allowedExtension(const QString &path) {
	return path.endsWith(".xbel", Qt::CaseInsensitive) ||
		path.endsWith(".xbel.lock", Qt::CaseInsensitive) ||
		path.endsWith(".html", Qt::CaseInsensitive) ||
		path.endsWith(".htm", Qt::CaseInsensitive);
}

bool normalizePath(const std::string &path, const QString &root,
	QString &relOut, QString &fullOut) {
	QString decoded = QUrl::fromPercentEncoding(
		QByteArray::fromStdString(path));
	if (decoded.startsWith('/')) {
		decoded.remove(0, 1);
	}
	if (decoded.contains("..")) {
		return false;
	}
	relOut = QDir::cleanPath(decoded);
	fullOut = QDir(root).filePath(relOut);
	return true;
}

MHD_Response *makeResponse(const QByteArray &data, int status,
	const char *ctype = "application/octet-stream") {
	Q_UNUSED(status);
	MHD_Response *resp = MHD_create_response_from_buffer(
		data.size(), const_cast<char *>(data.constData()),
		MHD_RESPMEM_MUST_COPY);
	if (resp == nullptr) {
		return nullptr;
	}
	MHD_add_response_header(resp, "Content-Type", ctype);
	MHD_add_response_header(resp, "Cache-Control", "no-cache");
	return resp;
}

MHD_Result queueSimple(struct MHD_Connection *connection, int status,
	const char *ctype = "text/plain") {
	QByteArray empty;
	auto *resp = makeResponse(empty, status, ctype);
	if (resp == nullptr) {
		return MHD_NO;
	}
	MHD_queue_response(connection, status, resp);
	MHD_destroy_response(resp);
	return MHD_YES;
}

bool checkAuth(struct MHD_Connection *connection,
	const ServerConfig &cfg) {
	char *user = nullptr;
	char *pass = nullptr;
	bool ok = false;
	user = MHD_basic_auth_get_username_password(connection, &pass);
	ok = user != nullptr &&
		cfg.user == std::string(user ? user : "") &&
		cfg.password == std::string(pass ? pass : "");
	if (user) {
		MHD_free(user);
	}
	if (pass) {
		MHD_free(pass);
	}
	return ok;
}

QString httpDate(const QDateTime &t) {
	return t.toUTC().toString("ddd, dd MMM yyyy HH:mm:ss 'GMT'");
}

QString escapeXml(const QString &value) {
	QString escaped = value;
	escaped.replace("&", "&amp;");
	escaped.replace("<", "&lt;");
	escaped.replace(">", "&gt;");
	escaped.replace("\"", "&quot;");
	escaped.replace("'", "&apos;");
	return escaped;
}

QString hrefFor(const QString &rel, bool isDir) {
	QString path = rel;
	if (!path.startsWith('/')) {
		path.prepend('/');
	}
	if (isDir && !path.endsWith('/')) {
		path.append('/');
	}
	return path;
}

QString buildPropXml(const QFileInfo &info, const QString &href) {
	QString xml;
	xml.append("<D:response>");
	xml.append("<D:href>");
	xml.append(escapeXml(href));
	xml.append("</D:href>");
	xml.append("<D:propstat><D:prop>");
	xml.append("<D:displayname>");
	xml.append(escapeXml(info.fileName()));
	xml.append("</D:displayname>");
	if (info.isFile()) {
		xml.append("<D:getcontentlength>");
		xml.append(QString::number(info.size()));
		xml.append("</D:getcontentlength>");
		xml.append("<D:resourcetype/>");
	} else {
		xml.append("<D:resourcetype><D:collection/></D:resourcetype>");
	}
	xml.append("<D:creationdate>");
	xml.append(info.birthTime().toUTC().toString(Qt::ISODate));
	xml.append("</D:creationdate>");
	xml.append("<D:getlastmodified>");
	xml.append(httpDate(info.lastModified()));
	xml.append("</D:getlastmodified>");
	xml.append("</D:prop><D:status>");
	xml.append("HTTP/1.1 200 OK");
	xml.append("</D:status></D:propstat>");
	xml.append("</D:response>");
	return xml;
}

QString lockTokenFromHeader(const char *value) {
	if (value == nullptr) {
		return "";
	}
	QString header = QString::fromUtf8(value);
	int idx = header.indexOf("opaquelocktoken:");
	if (idx < 0) {
		return "";
	}
	int end = header.indexOf('>', idx);
	QString token = header.mid(idx, end > idx ? end - idx :
		header.length() - idx);
	return token;
}

QString ensureLockToken(const QString &path) {
	QString token = "opaquelocktoken:" +
		QString::number(QRandomGenerator::global()->generate64(), 16);
	std::lock_guard<std::mutex> guard(locksMutex);
	pathToToken.insert(path, token);
	tokenToPath.insert(token, path);
	return token;
}

bool isLocked(const QString &path, const QString &token) {
	std::lock_guard<std::mutex> guard(locksMutex);
	if (!pathToToken.contains(path)) {
		return false;
	}
	if (token.isEmpty()) {
		return true;
	}
	return pathToToken.value(path) != token;
}

bool unlockPath(const QString &path, const QString &token) {
	std::lock_guard<std::mutex> guard(locksMutex);
	if (!pathToToken.contains(path)) {
		return false;
	}
	if (pathToToken.value(path) != token) {
		return false;
	}
	pathToToken.remove(path);
	tokenToPath.remove(token);
	return true;
}

bool ensureDirFor(const QString &path) {
	QFileInfo info(path);
	QDir dir = info.dir();
	if (dir.exists()) {
		return true;
	}
	return dir.mkpath(".");
}

MHD_Result handlePropfind(struct MHD_Connection *connection,
	const QString &relPath, const QString &fullPath,
	const char *depthHeader) {
	QFileInfo target(fullPath);
	if (!target.exists()) {
		return queueSimple(connection, MHD_HTTP_NOT_FOUND);
	}
	int depth = 0;
	if (depthHeader != nullptr && std::strcmp(depthHeader, "1") == 0) {
		depth = 1;
	}
	QString xml = "<D:multistatus xmlns:D=\"DAV:\">";
	xml.append(buildPropXml(target, hrefFor(relPath, target.isDir())));
	if (target.isDir() && depth == 1) {
		QDir dir(fullPath);
		QFileInfoList entries = dir.entryInfoList(
			QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot,
			QDir::Name | QDir::DirsFirst);
		for (const QFileInfo &entry : entries) {
			if (entry.isFile() &&
				!allowedExtension(entry.fileName())) {
				continue;
			}
			QString childRel = relPath;
			if (!childRel.isEmpty() && !childRel.endsWith('/')) {
				childRel.append('/');
			}
			childRel.append(entry.fileName());
			xml.append(buildPropXml(entry,
				hrefFor(childRel, entry.isDir())));
		}
	}
	xml.append("</D:multistatus>");
	QByteArray body = xml.toUtf8();
	auto *resp = makeResponse(body, MHD_HTTP_MULTI_STATUS,
		"application/xml");
	if (resp == nullptr) {
		return MHD_NO;
	}
	MHD_queue_response(connection, MHD_HTTP_MULTI_STATUS, resp);
	MHD_destroy_response(resp);
	return MHD_YES;
}

MHD_Result handlePut(struct MHD_Connection *connection,
	const QString &fullPath,
	const ConnectionState *state) {
	QString token = lockTokenFromHeader(MHD_lookup_connection_value(
		connection, MHD_HEADER_KIND, "If"));
	if (isLocked(fullPath, token)) {
		return queueSimple(connection, MHD_HTTP_LOCKED);
	}
	if (!ensureDirFor(fullPath)) {
		return queueSimple(connection,
			MHD_HTTP_INSUFFICIENT_STORAGE);
	}
	QSaveFile file(fullPath);
	if (!file.open(QIODevice::WriteOnly)) {
		return queueSimple(connection,
			MHD_HTTP_INSUFFICIENT_STORAGE);
	}
	file.write(state->body.data(),
		static_cast<qint64>(state->body.size()));
	if (!file.commit()) {
		return queueSimple(connection,
			MHD_HTTP_INSUFFICIENT_STORAGE);
	}
	return queueSimple(connection, MHD_HTTP_CREATED);
}

MHD_Result handleDelete(struct MHD_Connection *connection,
	const QString &fullPath) {
	QString token = lockTokenFromHeader(MHD_lookup_connection_value(
		connection, MHD_HEADER_KIND, "If"));
	if (isLocked(fullPath, token)) {
		return queueSimple(connection, MHD_HTTP_LOCKED);
	}
	if (!QFile::exists(fullPath)) {
		return queueSimple(connection, MHD_HTTP_NOT_FOUND);
	}
	if (!QFile::remove(fullPath)) {
		return queueSimple(connection,
			MHD_HTTP_INSUFFICIENT_STORAGE);
	}
	return queueSimple(connection, MHD_HTTP_NO_CONTENT);
}

MHD_Result handleGetHead(struct MHD_Connection *connection,
	const QString &fullPath, bool headOnly) {
	QFile file(fullPath);
	if (!file.exists()) {
		return queueSimple(connection, MHD_HTTP_NOT_FOUND);
	}
	if (!file.open(QIODevice::ReadOnly)) {
		return queueSimple(connection,
			MHD_HTTP_INSUFFICIENT_STORAGE);
	}
	QByteArray data = file.readAll();
	auto *resp = makeResponse(
		headOnly ? QByteArray() : data,
		MHD_HTTP_OK);
	if (resp == nullptr) {
		return MHD_NO;
	}
	if (headOnly) {
		MHD_add_response_header(resp, "Content-Length",
			QString::number(data.size()).toUtf8().constData());
	}
	MHD_queue_response(connection, MHD_HTTP_OK, resp);
	MHD_destroy_response(resp);
	return MHD_YES;
}

MHD_Result handleMkcol(struct MHD_Connection *connection,
	const QString &fullPath) {
	QDir dir(fullPath);
	if (dir.exists()) {
		return queueSimple(connection, MHD_HTTP_OK);
	}
	if (dir.mkpath(".")) {
		return queueSimple(connection, MHD_HTTP_CREATED);
	}
	return queueSimple(connection, MHD_HTTP_INSUFFICIENT_STORAGE);
}

MHD_Result handleLock(struct MHD_Connection *connection,
	const QString &relPath,
	const QString &fullPath) {
	if (!relPath.isEmpty() && !allowedExtension(relPath)) {
		return queueSimple(connection, MHD_HTTP_FORBIDDEN);
	}
	if (!QFile::exists(fullPath)) {
		if (!ensureDirFor(fullPath)) {
			return queueSimple(connection,
				MHD_HTTP_INSUFFICIENT_STORAGE);
		}
		QSaveFile f(fullPath);
		f.open(QIODevice::WriteOnly);
		f.commit();
	}
	QString token = ensureLockToken(fullPath);
	QString body = "<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery>"
		"<D:activelock><D:locktype><D:write/></D:locktype>"
		"<D:lockscope><D:exclusive/></D:lockscope>"
		"<D:depth>infinity</D:depth><D:locktoken><D:href>";
	body.append(token);
	body.append("</D:href></D:locktoken></D:activelock>"
		"</D:lockdiscovery></D:prop>");
	QByteArray data = body.toUtf8();
	auto *resp = makeResponse(data, MHD_HTTP_OK, "application/xml");
	if (resp == nullptr) {
		return MHD_NO;
	}
	MHD_add_response_header(resp, "Lock-Token",
		QString("<%1>").arg(token).toUtf8().constData());
	MHD_queue_response(connection, MHD_HTTP_OK, resp);
	MHD_destroy_response(resp);
	return MHD_YES;
}

MHD_Result handleUnlock(struct MHD_Connection *connection,
	const QString &fullPath) {
	QString token = lockTokenFromHeader(MHD_lookup_connection_value(
		connection, MHD_HEADER_KIND, "Lock-Token"));
	if (token.isEmpty()) {
		return queueSimple(connection, MHD_HTTP_BAD_REQUEST);
	}
	if (!unlockPath(fullPath, token)) {
		return queueSimple(connection, MHD_HTTP_CONFLICT);
	}
	return queueSimple(connection, MHD_HTTP_NO_CONTENT);
}

MHD_Result handler(void *cls, struct MHD_Connection *connection,
	const char *url, const char *method, const char *version,
	const char *uploadData, size_t *uploadDataSize, void **conCls) {
	Q_UNUSED(version);
	ServerConfig *cfg = static_cast<ServerConfig *>(cls);
	if (*conCls == nullptr) {
		auto *state = new ConnectionState();
		state->method = method;
		*conCls = state;
		return MHD_YES;
	}
	auto *connState = static_cast<ConnectionState *>(*conCls);
	if (*uploadDataSize != 0) {
		connState->body.append(uploadData, *uploadDataSize);
		*uploadDataSize = 0;
		return MHD_YES;
	}
	std::unique_ptr<ConnectionState> guard(connState);
	if (!checkAuth(connection, *cfg)) {
		auto *resp = MHD_create_response_from_buffer(
			0, nullptr, MHD_RESPMEM_PERSISTENT);
		if (resp != nullptr) {
			MHD_add_response_header(resp, "WWW-Authenticate",
				"Basic realm=\"Restricted\"");
			MHD_queue_response(connection, MHD_HTTP_UNAUTHORIZED,
				resp);
			MHD_destroy_response(resp);
		}
		return MHD_YES;
	}
	QString rel;
	QString full;
	if (!normalizePath(url, QString::fromStdString(cfg->root),
		rel, full)) {
		queueSimple(connection, MHD_HTTP_FORBIDDEN);
		return MHD_YES;
	}
	bool fileMethod = std::strcmp(method, "GET") == 0 ||
		std::strcmp(method, "HEAD") == 0 ||
		std::strcmp(method, "PUT") == 0 ||
		std::strcmp(method, "DELETE") == 0;
	if (fileMethod && !rel.isEmpty() && !allowedExtension(rel)) {
		queueSimple(connection, MHD_HTTP_FORBIDDEN);
		return MHD_YES;
	}
	if (std::strcmp(method, "PROPFIND") == 0) {
		if (!rel.isEmpty()) {
			QFileInfo info(full);
			if (info.isFile() && !allowedExtension(rel)) {
				queueSimple(connection, MHD_HTTP_FORBIDDEN);
				return MHD_YES;
			}
		}
		return handlePropfind(connection, rel, full,
			MHD_lookup_connection_value(connection,
				MHD_HEADER_KIND, "Depth"));
	}
	if (std::strcmp(method, "MKCOL") == 0) {
		return handleMkcol(connection, full);
	}
	if (std::strcmp(method, "LOCK") == 0) {
		return handleLock(connection, rel, full);
	}
	if (std::strcmp(method, "UNLOCK") == 0) {
		return handleUnlock(connection, full);
	}
	if (std::strcmp(method, "PUT") == 0) {
		return handlePut(connection, full, connState);
	}
	if (std::strcmp(method, "DELETE") == 0) {
		return handleDelete(connection, full);
	}
	if (std::strcmp(method, "GET") == 0 ||
		std::strcmp(method, "HEAD") == 0) {
		return handleGetHead(connection, full,
			std::strcmp(method, "HEAD") == 0);
	}
	queueSimple(connection, MHD_HTTP_METHOD_NOT_ALLOWED);
	return MHD_YES;
}

} // namespace

bool serverStart(const std::string &address, const std::string &port,
	const std::string &root, const std::string &user,
	const std::string &password) {
	serverStop();
	state = new ServerState();
	state->cfg.address = address;
	state->cfg.port = port;
	state->cfg.root = root;
	state->cfg.user = user;
	state->cfg.password = password;
	state->running = true;
	state->bindLen = 0;
	QHostAddress addr(QString::fromStdString(address));
	int portNum = std::stoi(port);
	if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
		auto *a = reinterpret_cast<sockaddr_in *>(
			&state->bindAddr);
		state->bindLen = sizeof(sockaddr_in);
		std::memset(a, 0, sizeof(sockaddr_in));
		a->sin_family = AF_INET;
		a->sin_port = htons(static_cast<uint16_t>(portNum));
		a->sin_addr.s_addr = htonl(addr.toIPv4Address());
	} else if (addr.protocol() == QAbstractSocket::IPv6Protocol) {
		auto *a6 = reinterpret_cast<sockaddr_in6 *>(
			&state->bindAddr);
		state->bindLen = sizeof(sockaddr_in6);
		std::memset(a6, 0, sizeof(sockaddr_in6));
		a6->sin6_family = AF_INET6;
		a6->sin6_port = htons(static_cast<uint16_t>(portNum));
		auto raw = addr.toIPv6Address();
		std::memcpy(&a6->sin6_addr.s6_addr, raw.c,
			sizeof(raw.c));
	}
	state->daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
		0, nullptr, nullptr, &handler, &state->cfg,
		MHD_OPTION_SOCK_ADDR, &state->bindAddr,
		MHD_OPTION_END);
	if (state->daemon == nullptr) {
		delete state;
		state = nullptr;
		return false;
	}
	return true;
}

void serverStop() {
	if (state == nullptr) {
		return;
	}
	if (state->daemon != nullptr) {
		MHD_stop_daemon(state->daemon);
	}
	delete state;
	state = nullptr;
}
