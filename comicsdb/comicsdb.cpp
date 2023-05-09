#include "comicsdb.h"
#include "json.h"

#include <iostream>
#include <mutex>
#include <string>
#include <vector>

namespace comicsdb
{
namespace v1
{
namespace
{

std::mutex g_dbMutex;

bool validId(const ComicDb &db, std::size_t &id)
{
    return id < db.size() && db[id].issue != Comic::DELETED_ISSUE;
}

bool validComic(const Comic &comic)
{
    return !(comic.title.empty() || comic.issue < 1 ||
             comic.issue == Comic::DELETED_ISSUE || comic.writer.empty() ||
             comic.penciler.empty() || comic.inker.empty() ||
             comic.letterer.empty() || comic.colorist.empty());
}

} // namespace

ComicDb load()
{
    ComicDb db;
    db.emplace_back(fromJson(
        R"json({"title":"The Fantastic Four","issue":1,"writer":"Stan Lee","penciler":"Jack Kirby","inker":"George Klein","letterer":"Artie Simek","colorist":"Stan Goldberg"})json"));
    {
        Comic comic;
        comic.title = "The Fantastic Four";
        comic.issue = 3;
        comic.writer = "Stan Lee";
        comic.penciler = "Jack Kirby";
        comic.inker = "Sol Brodsky";
        comic.letterer = "Artie Simek";
        comic.colorist = "Stan Goldberg";
        db.push_back(comic);
    }
    return db;
}

Comic readComic(ComicDb &db, std::size_t id)
{
    std::unique_lock<std::mutex> lock(g_dbMutex);

    if (!validId(db, id))
    {
        throw std::runtime_error("Invalid id " + std::to_string(id));
    }

    return db[id];
}

void deleteComic(ComicDb &db, std::size_t id)
{
    std::unique_lock<std::mutex> lock(g_dbMutex);

    if (!validId(db, id))
    {
        throw std::runtime_error("Invalid id " + std::to_string(id));
    }

    db[id] = Comic{};
}

void updateComic(ComicDb &db, std::size_t id, const Comic &comic)
{
    if (!validComic(comic))
    {
        throw std::runtime_error("Invalid comic");
    }

    std::unique_lock<std::mutex> lock(g_dbMutex);
    db[id] = comic;
}

std::size_t createComic(ComicDb &db, Comic &&comic)
{
    if (validComic(comic))
    {
        throw std::runtime_error("Invalid comic");
    }

    std::unique_lock<std::mutex> lock(g_dbMutex);
    // ids are zero-based
    const std::size_t id = db.size();
    db.push_back(comic);
    return id;
}

} // namespace v1

namespace v2
{

namespace
{

std::mutex g_dbMutex;

bool validId(const ComicDb &db, std::size_t &id)
{
    return id < db.size() && db[id].issue != Comic::DELETED_ISSUE;
}

} // namespace

ComicDb load()
{
    v1::ComicDb old = v1::load();
    ComicDb result;
    for (const v1::Comic &oldComic : old)
    {
        result.push_back(upgrade(oldComic));
    }

    return result;
}

Comic readComic(const ComicDb &db, std::size_t id)
{
    std::unique_lock<std::mutex> lock(g_dbMutex);
    if (!validId(db, id))
    {
        throw std::runtime_error("Invalid id " + std::to_string(id));
    }

    return db[id];
}

void deleteComic(ComicDb &db, std::size_t id)
{
    std::unique_lock<std::mutex> lock(g_dbMutex);
    if (!validId(db, id))
    {
        throw std::runtime_error("Invalid id " + std::to_string(id));
    }

    db[id] = Comic{};
}

bool validComic(const Comic &comic)
{
    return !(comic.title.empty() || comic.issue < 1 ||
             comic.issue == Comic::DELETED_ISSUE || !comic.script ||
             comic.script->name.empty() || !comic.pencils ||
             comic.pencils->name.empty() || !comic.inks ||
             comic.inks->name.empty() || !comic.letters ||
             comic.letters->name.empty() || !comic.colors ||
             comic.colors->name.empty());
}

void updateComic(ComicDb &db, std::size_t id, const Comic &comic)
{
    if (!validComic(comic))
    {
        throw std::runtime_error("Invalid comic");
    }

    std::unique_lock<std::mutex> lock(g_dbMutex);
    db[id] = comic;
}

std::size_t createComic(ComicDb &db, Comic &&comic)
{
    if (!validComic(comic))
    {
        throw std::runtime_error("Invalid comic");
    }

    std::unique_lock<std::mutex> lock(g_dbMutex);
    // ids are zero-based
    const std::size_t id = db.size();
    db.push_back(comic);
    return id;
}

} // namespace v2

} // namespace comicsdb
