#pragma once

#include "comic.h"

#include <string>

namespace comicsdb
{

namespace v1
{

std::string toJson(const Comic &comic);
Comic fromJson(const std::string &json);

} // namespace v1

namespace v2
{

std::string toJson(const Comic &comic);
Comic fromJson(const std::string &json);

} // namespace v2

} // namespace comicsdb
