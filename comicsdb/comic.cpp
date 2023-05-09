#include "comic.h"

#include <map>

namespace comicsdb
{
namespace v2
{
namespace
{

std::map<std::string, PersonPtr> s_persons;

}
PersonPtr findPerson(const std::string &name)
{
    auto it = s_persons.find(name);
    if (it == s_persons.end())
    {
        it = s_persons.emplace(name, std::make_shared<Person>(name)).first;
    }
    return it->second;
}

void forgetAllPersons()
{
    s_persons.clear();
}

Comic upgrade(const v1::Comic &comic)
{
    Comic upgraded;
    upgraded.title = comic.title;
    upgraded.issue = comic.issue == v1::Comic::DELETED_ISSUE ? Comic::DELETED_ISSUE : comic.issue;
    upgraded.script = findPerson(comic.writer);
    upgraded.pencils = findPerson(comic.penciler);
    upgraded.inks = findPerson(comic.inker);
    upgraded.letters = findPerson(comic.letterer);
    upgraded.colors = findPerson(comic.colorist);
    return upgraded;
}

} // namespace v2
} // namespace comicsdb
