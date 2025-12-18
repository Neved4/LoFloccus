#ifndef WEBDAV_SERVER_H
#define WEBDAV_SERVER_H

#include <string>

bool serverStart(const std::string &address, const std::string &port,
	const std::string &root, const std::string &user,
	const std::string &password);

void serverStop();

#endif
