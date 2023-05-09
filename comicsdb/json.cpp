#include "comic.h"

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

namespace comicsdb
{
namespace v1
{

std::string toJson(const Comic &comic)
{
    rapidjson::Document doc;
    rapidjson::Value &obj = doc.SetObject();
    auto addMember = [&obj, &doc](const char *key, const std::string &value)
    {
        using String = rapidjson::GenericStringRef<char>;
        obj.AddMember(String{key}, String{value.c_str()}, doc.GetAllocator());
    };
    addMember("title", comic.title);
    obj.AddMember("issue", comic.issue, doc.GetAllocator());
    addMember("writer", comic.writer);
    addMember("penciler", comic.penciler);
    addMember("inker", comic.inker);
    addMember("letterer", comic.letterer);
    addMember("colorist", comic.colorist);
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);
    return buffer.GetString();
}

Comic fromJson(const std::string &json)
{
    rapidjson::Document doc;
    doc.Parse(json.c_str());
    Comic comic{};
    auto getString = [&doc](const char *key) { return doc[key].GetString(); };
    comic.title = getString("title");
    comic.issue = doc["issue"].GetInt();
    comic.writer = getString("writer");
    comic.penciler = getString("penciler");
    comic.inker = getString("inker");
    comic.letterer = getString("letterer");
    comic.colorist = getString("colorist");
    return comic;
}

} // namespace v1

namespace v2
{

std::string toJson(const Comic &comic)
{
    rapidjson::Document doc;
    rapidjson::Value &obj = doc.SetObject();
    auto addMember = [&obj, &doc](const char *key, const std::string &value)
    {
        using String = rapidjson::GenericStringRef<char>;
        obj.AddMember(String{key}, String{value.c_str()}, doc.GetAllocator());
    };
    addMember("title", comic.title);
    obj.AddMember("issue", comic.issue, doc.GetAllocator());
    addMember("script", comic.script->name);
    addMember("pencils", comic.pencils->name);
    addMember("inks", comic.inks->name);
    addMember("letters", comic.letters->name);
    addMember("colors", comic.colors->name);
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);
    return buffer.GetString();
}

Comic fromJson(const std::string &json)
{
    rapidjson::Document doc;
    doc.Parse(json.c_str());
    Comic comic{};
    auto getString = [&doc](const char *key) { return doc[key].GetString(); };
    comic.title = getString("title");
    comic.issue = doc["issue"].GetInt();
    const std::string writer = getString("script");
    comic.script = findPerson(writer);
    const std::string penciler = getString("pencils");
    comic.pencils = findPerson(penciler);
    const std::string inker = getString("inks");
    comic.inks = findPerson(inker);
    const std::string letterer = getString("letters");
    comic.letters = findPerson(letterer);
    const std::string colorist = getString("colors");
    comic.colors = findPerson(colorist);
    return comic;
}

} // namespace v2

} // namespace comicsdb
