#pragma once

#include <memory>
#include <string>

namespace comicsdb
{

namespace v1
{

struct Comic
{
    enum
    {
        DELETED_ISSUE = -1
    };
    std::string title;
    int issue{DELETED_ISSUE};
    std::string writer;
    std::string penciler;
    std::string inker;
    std::string letterer;
    std::string colorist;
};

}

namespace v2
{

struct Person
{
    Person() = default;
    Person(const std::string &name_) : name(name_) {}

    std::string name;
};

using PersonPtr = std::shared_ptr<Person>;

PersonPtr findPerson(const std::string &name);
void forgetAllPersons();

struct Comic
{
    enum
    {
        DELETED_ISSUE = -2
    };
    std::string title;
    int issue{DELETED_ISSUE};
    PersonPtr script;
    PersonPtr pencils;
    PersonPtr inks;
    PersonPtr letters;
    PersonPtr colors;
};

Comic upgrade(const v1::Comic &comic);

}

} // namespace comicsdb
