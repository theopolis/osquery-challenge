/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/sdk.h>
#include <osquery/system.h>

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
  r["output"] = output.substr(off, length);
  LOG(WARNING) << off << " and " <<  output.size() << " and " << r["output"].size();
  r["offset"] = INTEGER(off);
  r["size"] = INTEGER(length);

  results.push_back(r);
}

class ChallengeTable : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
        std::make_tuple("path", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("output", BLOB_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("offset", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("size", INTEGER_TYPE, ColumnOptions::DEFAULT),
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
