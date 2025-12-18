#include "webdav_server.h"

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
pid_t serverPid = -1;
std::string prefixDir;
std::string configPath;
std::string authPath;

bool ensureDir(const std::string &path)
{
	if (mkdir(path.c_str(), 0755) == 0) {
		return true;
	}
	return errno == EEXIST;
}

std::string tempBase()
{
	const char *env = std::getenv("TMPDIR");
	if (env && env[0] != '\0') {
		return std::string(env) + "/lofloccus-nginx";
	}
	return "/tmp/lofloccus-nginx";
}

std::string hashPassword(const std::string &password)
{
	const char *salt = "lf";
	char *hashed = crypt(password.c_str(), salt);
	if (hashed == nullptr) {
		return "";
	}
	return std::string(hashed);
}

bool writeAuthFile(const std::string &user, const std::string &password)
{
	if (user.empty() || password.empty()) {
		return false;
	}

	authPath = prefixDir + "/conf/htpasswd";
	std::ofstream auth(authPath.c_str(), std::ios::trunc);
	if (!auth.is_open()) {
		return false;
	}

	std::string hashed = hashPassword(password);
	if (hashed.empty()) {
		return false;
	}

	auth << user << ":" << hashed << "\n";
	return true;
}

bool writeConfig(const std::string &address, const std::string &port,
	const std::string &root, const std::string &user,
	const std::string &password)
{
	prefixDir = tempBase();
	if (!ensureDir(prefixDir)
		|| !ensureDir(prefixDir + "/logs")
		|| !ensureDir(prefixDir + "/conf")
		|| !ensureDir(prefixDir + "/client_body")) {
		return false;
	}

	if (!writeAuthFile(user, password)) {
		return false;
	}

	configPath = prefixDir + "/conf/lofloccus.conf";
	std::ofstream cfg(configPath.c_str(), std::ios::trunc);
	if (!cfg.is_open()) {
		return false;
	}

	cfg << "worker_processes 1;\n";
	cfg << "pid " << prefixDir << "/nginx.pid;\n";
	cfg << "error_log " << prefixDir << "/logs/error.log notice;\n";
	cfg << "events { worker_connections 16; }\n";
	cfg << "http {\n";
	cfg << "  client_body_temp_path " << prefixDir
		<< "/client_body;\n";
	cfg << "  server {\n";
	cfg << "    listen " << address << ":" << port << ";\n";
	cfg << "    access_log " << prefixDir << "/logs/access.log;\n";
	cfg << "    location / {\n";
	cfg << "      root " << root << ";\n";
	cfg << "      dav_methods PUT DELETE MKCOL COPY MOVE;\n";
	cfg << "      create_full_put_path on;\n";
	cfg << "      autoindex on;\n";
	cfg << "      auth_basic \"Restricted\";\n";
	cfg << "      auth_basic_user_file " << authPath << ";\n";
	cfg << "    }\n";
	cfg << "  }\n";
	cfg << "}\n";

	return true;
}
}

bool serverStart(const std::string &address, const std::string &port,
	const std::string &root, const std::string &user,
	const std::string &password)
{
	if (serverPid > 0) {
		serverStop();
	}
	if (!writeConfig(address, port, root, user, password)) {
		return false;
	}

	pid_t pid = fork();
	if (pid < 0) {
		return false;
	}
	if (pid == 0) {
		std::string prefix = "-p";
		std::string conf = "-c";
		execlp("nginx",
			"nginx",
			prefix.c_str(),
			prefixDir.c_str(),
			conf.c_str(),
			configPath.c_str(),
			"-g",
			"daemon off;",
			static_cast<char *>(0));
		_exit(1);
	}

	serverPid = pid;
	return true;
}

void serverStop()
{
	if (serverPid <= 0) {
		return;
	}
	kill(serverPid, SIGTERM);
	waitpid(serverPid, 0, 0);
	serverPid = -1;
}
