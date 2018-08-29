/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/extensions.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/filesystem.h>
#include <osquery/tables.h>
#include <osquery/registry.h>

namespace osquery {
/**
 * @brief Create the external SQLite implementation wrapper.
 *
 * Anything built with only libosquery and not the 'additional' library will
 * not include a native SQL implementation. This applies to extensions and
 * separate applications built with the osquery SDK.
 *
 * The ExternalSQLPlugin is a wrapper around the SQLite API, which forwards
 * calls to an osquery extension manager (core).
 */
REGISTER_INTERNAL(ExternalSQLPlugin, "sql", "sql"); 

/**
 * @brief Mimic the REGISTER macro, extensions should use this helper.
 *
 * The SDK does not provide a REGISTER macro for modules or extensions.
 * Tools built with the osquery SDK should use REGISTER_EXTERNAL to add to
 * their own 'external' registry. This registry will broadcast to the osquery
 * extension manager (core) in an extension.
 *
 * osquery 'modules' should not construct their plugin registrations in
 * global scope (global construction time). Instead they should use the
 * module call-in well defined symbol, declare their SDK constraints, then
 * use the REGISTER_MODULE call within `initModule`.
 */
#define REGISTER_EXTERNAL(class_name, registry_name, plugin_name)              \
  namespace registries {                                                       \
  const ::osquery::registries::PI<class_name>                                  \
      k##ExtensionRegistryItem##class_name(registry_name, plugin_name, false); \
  }
}

using namespace osquery;

size_t kSize = 1024;

void challengeReadFile(Row& file, size_t off, QueryData& results) {
  Row r;
  r["path"] = file["path"];

  std::string output;
  if (!osquery::readFile(r["path"], output)) {
    LOG(ERROR) << "Cannot read file";
    return;
  }

  if (off >= output.size()) {
    return;
  }

  size_t length = (kSize + off > output.size()) ? output.size() - off : kSize;
  r["bytes"] = output.substr(off, length);
  LOG(WARNING) << off << " and " <<  output.size() << " and " << r["bytes"].size();
  r["offset"] = INTEGER(off);
  r["size"] = INTEGER(length);

  results.push_back(r);
}

class ChallengeTable : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
        std::make_tuple("path", TEXT_TYPE, ColumnOptions::REQUIRED),
        std::make_tuple("offset", INTEGER_TYPE, ColumnOptions::ADDITIONAL),
        std::make_tuple("bytes", BLOB_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("size", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("flag", TEXT_TYPE, ColumnOptions::HIDDEN),
    };
  }

  QueryData generate(QueryContext& ctx) {
    QueryData results;

    auto r = SQL::selectAllFrom("osquery_info");
    if (r.size() != 1U) {
      LOG(ERROR) << "Something is definitely wrong";
      return {};
    }

    r = SQL::selectAllFrom("processes", "pid", EQUALS, r[0]["pid"]);
    if (r.size() != 1U) {
      LOG(ERROR) << "Something is most likely wrong";
      return {};
    }

    auto process_uid = r[0]["uid"];

    // Resolve file paths for EQUALS and LIKE operations.
    auto paths = ctx.constraints["path"].getAll(EQUALS);
    ctx.expandConstraints(
        "path",
        LIKE,
        paths,
        ([&](const std::string& pattern, std::set<std::string>& out) {
          std::vector<std::string> patterns;
          auto status =
              resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
          if (status.ok()) {
            for (const auto& resolved : patterns) {
              out.insert(resolved);
            }
          }
          return status;
        }));

    int offset = 0;
    auto offset_iter = ctx.constraints.find("offset");
    if (offset_iter != ctx.constraints.end()) {
      if (offset_iter->second.exists(EQUALS)) {
        offset = (*offset_iter->second.getAll<int>(EQUALS).begin());
      }
    }

    for (const auto& path : paths) {
      if (path == "you_win_the_day_wooooooot") {
        Row win;
        win["path"] = path;
        win["offset"] = INTEGER(offset);
        readFile("/var/flag.txt", win["flag"]);
        return {win};
      }

      r = SQL::selectAllFrom("file", "path", EQUALS, path);
      if (r.size() == 0U) {
        continue;
      }
      if (r[0]["uid"] != process_uid) {
        LOG(INFO) << "Not allowed to read this file";
        continue;
      }
      challengeReadFile(r[0], offset, results);
    }

    return results;
  }
};


REGISTER_EXTERNAL(ChallengeTable, "table", "challenge");

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, ToolType::EXTENSION);

  auto status = startExtension("challenge", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return 0;
}
