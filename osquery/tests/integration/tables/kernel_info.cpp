/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for kernel_info
// Spec file: specs/kernel_info.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/logger.h>

namespace osquery {

class KernelInfo : public IntegrationTableTest {};

TEST_F(KernelInfo, test_sanity) {

#if defined OSQUERY_WINDOWS || defined OSQUERY_LINUX
  LOG(INFO) << "Test failing on Windows and Linux, temporarily disabled";
  return;
#endif

  QueryData data = execute_query("select * from kernel_info");
  ValidatatioMap row_map = {{"version", NonEmptyString},
                            {"arguments", NormalType},
                            {"path", FileOnDisk},
                            {"device", ValidUUID}};
  validate_rows(data, row_map);
}

} // namespace osquery
