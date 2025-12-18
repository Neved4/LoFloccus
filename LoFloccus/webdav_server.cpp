#include "webdav_server.h"

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QRandomGenerator>
#include <QSaveFile>

#include "mongoose.h"

#include <atomic>
#include <cstring>
#include <mutex>
#include <sstream>
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

struct ServerState {
	ServerConfig cfg;
	mg_mgr mgr;
	mg_connection *listener;
	std::thread loop;
	std::atomic<bool> running;
};

ServerState *state = nullptr;
QHash<QString, QString> pathToToken;
QHash<QString, QString> tokenToPath;
std::mutex locksMutex;

mg_str strLiteral(const char *value) {
	return mg_str_n(value, strlen(value));
}

bool allowedExtension(const QString &path) {
	return path.endsWith(".xbel", Qt::CaseInsensitive) ||
		path.endsWith(".xbel.lock", Qt::CaseInsensitive) ||
		path.endsWith(".html", Qt::CaseInsensitive) ||
		path.endsWith(".htm", Qt::CaseInsensitive);
}

bool normalizePath(const mg_http_message *hm, const QString &root,
	QString &relOut, QString &fullOut) {
	char buf[512];
	size_t len = mg_url_decode(hm->uri.buf, hm->uri.len, buf,
		sizeof(buf), 0);
	if (len == 0 || len >= sizeof(buf)) {
		return false;
	}
	QString rel = QString::fromUtf8(buf, static_cast<int>(len));
	if (rel.startsWith('/')) {
		rel.remove(0, 1);
	}
	if (rel.contains("..", Qt::CaseInsensitive)) {
		return false;
	}
	relOut = QDir::cleanPath(rel);
	fullOut = QDir(root).filePath(relOut);
	return true;
}

void replyAuth(mg_connection *c) {
	const char *headers = "WWW-Authenticate: Basic realm=\"Restricted\"\r\n";
	mg_http_reply(c, 401, headers, "");
}

void replyStatus(mg_connection *c, int code) {
	mg_http_reply(c, code, "", "");
}

bool checkAuth(mg_http_message *hm, const ServerConfig &cfg,
	mg_connection *c) {
	char user[64];
	char pass[64];
	mg_http_creds(hm, user, sizeof(user), pass, sizeof(pass));
	if (cfg.user != user || cfg.password != pass) {
		replyAuth(c);
		return false;
	}
	return true;
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

QString lockTokenFromHeader(struct mg_http_message *hm,
	const char *name) {
	struct mg_str *h = mg_http_get_header(hm, name);
	if (h == nullptr) {
		return "";
	}
	QString header = QString::fromUtf8(h->buf,
		static_cast<int>(h->len));
	int idx = header.indexOf("opaquelocktoken:");
	if (idx < 0) {
		return "";
	}
	int end = header.indexOf('>', idx);
	return header.mid(idx, end > idx ? end - idx :
		header.length() - idx);
}

QString ensureLockToken(const QString &path) {
	QString token = "opaquelocktoken:" +
		QString::number(QRandomGenerator::global()->generate64(),
			16);
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

void handlePropfind(mg_connection *c, mg_http_message *hm,
	const QString &relPath, const QString &fullPath) {
	QFileInfo target(fullPath);
	if (!target.exists()) {
		replyStatus(c, 404);
		return;
	}
	struct mg_str *depthHeader = mg_http_get_header(hm, "Depth");
	int depth = 0;
	if (depthHeader != nullptr) {
		if (mg_strcmp(*depthHeader, strLiteral("1")) == 0) {
			depth = 1;
		}
	}
	QString xml = "<D:multistatus xmlns:D=\"DAV:\">";
	xml.append(buildPropXml(target, hrefFor(relPath, target.isDir())));
	if (target.isDir() && depth == 1) {
		QDir dir(fullPath);
		QFileInfoList entries = dir.entryInfoList(
			QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot,
			QDir::Name | QDir::DirsFirst);
		for (const QFileInfo &entry : entries) {
			if (entry.isFile() && !allowedExtension(entry.fileName())) {
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
	std::string body = xml.toUtf8().toStdString();
	const char *headers = "Content-Type: application/xml\r\n";
	mg_http_reply(c, 207, headers, "%.*s",
		static_cast<int>(body.size()), body.c_str());
}

void handlePut(const QString &fullPath, mg_http_message *hm,
	mg_connection *c) {
	QString token = lockTokenFromHeader(hm, "If");
	if (isLocked(fullPath, token)) {
		replyStatus(c, 423);
		return;
	}
	if (!ensureDirFor(fullPath)) {
		replyStatus(c, 507);
		return;
	}
	QSaveFile file(fullPath);
	if (!file.open(QIODevice::WriteOnly)) {
		replyStatus(c, 507);
		return;
	}
	file.write(hm->body.buf, static_cast<qint64>(hm->body.len));
	if (!file.commit()) {
		replyStatus(c, 507);
		return;
	}
	replyStatus(c, 201);
}

void handleDelete(const QString &fullPath, mg_http_message *hm,
	mg_connection *c) {
	QString token = lockTokenFromHeader(hm, "If");
	if (isLocked(fullPath, token)) {
		replyStatus(c, 423);
		return;
	}
	if (!QFile::exists(fullPath)) {
		replyStatus(c, 404);
		return;
	}
	if (!QFile::remove(fullPath)) {
		replyStatus(c, 507);
		return;
	}
	replyStatus(c, 204);
}

void handleGetHead(const QString &fullPath, mg_http_message *hm,
	mg_connection *c) {
	if (!QFile::exists(fullPath)) {
		replyStatus(c, 404);
		return;
	}
	struct mg_http_serve_opts opts = {};
	mg_http_serve_file(c, hm, fullPath.toUtf8().constData(), &opts);
}

void handleLock(mg_connection *c, mg_http_message *hm,
	const QString &relPath, const QString &fullPath) {
	Q_UNUSED(hm);
	if (!relPath.isEmpty() && !allowedExtension(relPath)) {
		replyStatus(c, 403);
		return;
	}
	if (!QFile::exists(fullPath)) {
		if (!ensureDirFor(fullPath)) {
			replyStatus(c, 507);
			return;
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
	std::string text = body.toUtf8().toStdString();
	std::string headers = "Content-Type: application/xml\r\n"
		"Lock-Token: <" + token.toStdString() + ">\r\n";
	mg_http_reply(c, 200, headers.c_str(), "%.*s",
		static_cast<int>(text.size()), text.c_str());
}

void handleUnlock(mg_connection *c, mg_http_message *hm,
	const QString &fullPath) {
	QString token = lockTokenFromHeader(hm, "Lock-Token");
	if (token.isEmpty()) {
		replyStatus(c, 400);
		return;
	}
	if (!unlockPath(fullPath, token)) {
		replyStatus(c, 409);
		return;
	}
	replyStatus(c, 204);
}

void eventHandler(mg_connection *c, int ev, void *evData) {
	auto *server = static_cast<ServerState *>(c->fn_data);
	if (ev != MG_EV_HTTP_MSG || server == nullptr) {
		return;
	}
	auto *hm = static_cast<mg_http_message *>(evData);
	if (!checkAuth(hm, server->cfg, c)) {
		return;
	}
	QString rel;
	QString full;
	if (!normalizePath(hm, QString::fromStdString(server->cfg.root),
		rel, full)) {
		replyStatus(c, 403);
		return;
	}
	bool isGet = mg_strcmp(hm->method, strLiteral("GET")) == 0;
	bool isHead = mg_strcmp(hm->method, strLiteral("HEAD")) == 0;
	bool isPut = mg_strcmp(hm->method, strLiteral("PUT")) == 0;
	bool isDelete = mg_strcmp(hm->method, strLiteral("DELETE")) == 0;
	bool isProp = mg_strcmp(hm->method, strLiteral("PROPFIND")) == 0;
	bool isLock = mg_strcmp(hm->method, strLiteral("LOCK")) == 0;
	bool isUnlock = mg_strcmp(hm->method, strLiteral("UNLOCK")) == 0;
	if ((isGet || isHead || isPut || isDelete) && !rel.isEmpty() &&
		!allowedExtension(rel)) {
		replyStatus(c, 403);
		return;
	}
	if (isProp) {
		if (!rel.isEmpty()) {
			QFileInfo info(full);
			if (info.isFile() && !allowedExtension(rel)) {
				replyStatus(c, 403);
				return;
			}
		}
		handlePropfind(c, hm, rel, full);
		return;
	}
	if (isLock) {
		handleLock(c, hm, rel, full);
		return;
	}
	if (isUnlock) {
		handleUnlock(c, hm, full);
		return;
	}
	if (isPut) {
		handlePut(full, hm, c);
		return;
	}
	if (isDelete) {
		handleDelete(full, hm, c);
		return;
	}
	if (isGet || isHead) {
		handleGetHead(full, hm, c);
		return;
	}
	replyStatus(c, 405);
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
	state->listener = nullptr;
	state->running = true;
	mg_mgr_init(&state->mgr);
	std::string url = "http://" + address + ":" + port;
	state->listener = mg_http_listen(&state->mgr, url.c_str(),
		eventHandler, state);
	if (state->listener == nullptr) {
		state->running = false;
		mg_mgr_free(&state->mgr);
		delete state;
		state = nullptr;
		return false;
	}
	state->loop = std::thread([]() {
		while (state != nullptr && state->running) {
			mg_mgr_poll(&state->mgr, 100);
		}
		if (state != nullptr) {
			mg_mgr_free(&state->mgr);
		}
	});
	return true;
}

void serverStop() {
	if (state == nullptr) {
		return;
	}
	state->running = false;
	if (state->loop.joinable()) {
		state->loop.join();
	}
	delete state;
	state = nullptr;
}
