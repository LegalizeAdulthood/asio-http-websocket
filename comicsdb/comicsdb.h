#pragma once

#include "comic.h"

#include <cstddef>
#include <vector>

namespace comicsdb
{

namespace v1
{

using ComicDb = std::vector<Comic>;

ComicDb load();
Comic readComic(const ComicDb &db, std::size_t id);
void deleteComic(ComicDb &db, std::size_t id);
void updateComic(ComicDb &db, std::size_t id, const Comic &comic);
std::size_t createComic(ComicDb &db, Comic &&comic);

} // namespace v1

namespace v2
{

using ComicDb = std::vector<Comic>;

ComicDb load();
Comic readComic(const ComicDb &db, std::size_t id);
void deleteComic(ComicDb &db, std::size_t id);
void updateComic(ComicDb &db, std::size_t id, const Comic &comic);
std::size_t createComic(ComicDb &db, Comic &&comic);

}

} // namespace comicsdb
