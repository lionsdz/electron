// Copyright (c) 2026 Electron authors.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include "shell/common/asar/archive.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "base/base64.h"
#include "base/check.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/pickle.h"
#include "base/strings/string_number_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "shell/common/asar/asar_util.h"
#include "shell/common/asar/scoped_temporary_file.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace asar {
namespace {

// These fixtures were signed offline with a deterministic Ed25519 test key.
// Tests contain only its public key and therefore cannot mint accepted input.
constexpr char kCanonicalArchive[] =
    "RUFTUgIAAADIAAEBAAAAALkAAAAAAAAATAEAAAAAAAAHAAAAAAAAAGHNifcSi+4TfnrW"
    "C7UccLIvGGOr0spvDz+ZRbxKK3Q6gGy6bYIxxsB7Z5tQ3is1D/xpc61Mi7DG7e/kfDzE"
    "R1jvoJ748Hz9sQ98Zce8P1JgIBExg2/KI36DOtdqeaae34ZColTHazw8Ilx/BpkvuCpB0"
    "JtxIlusukJ8Tz8VVu+q9pA/lH9a/aXBVRhfHhbR0yaAzcm982r/o66fZDkJSQFFSURYAQ"
    "AADAYDAANkaXIAAw0vYm91bmRhcnkuYmluAYgntQILAAllbXB0eS50eHQBAAAIbGluay5"
    "iaW4CEGRpci9ib3VuZGFyeS5iaW4AC25hdGl2ZS5ub2RlDQ1B9Y7+XR1hTC/9ya34XLL3"
    "Xbw2q6rjp61PfX1y2nfL0gAHcmF3LmJpbgEMACkmGKzj6pBQpUGpQ4xra33Arz0DV2YL"
    "uvXJA9ly+i5ws0CEzKwUtbYi0Z1E+yxIWepvVI+UbBvtHZ9Dc11N4J3/EPiNTcnmchqw"
    "DXsP1VQtMOmWNEmyYPATBFkNk9s7FGl8evXTZSlqYlUYYm8uizpYoWwuSX1KCEpoZ4V0"
    "z6y8/08N2WGaVxIX1XS7xzfSwffP6C/W4Cksah8/+yX6dPrcv/Bqf5dRhRJndej3iiVK"
    "1nuE+OtFQ0A0xpp9TpirSqD9hIJpQ6K0kmR673qtfi3tzSHgAEhZ/WjOrY6NKxieZWcMd"
    "IOzSox8FfHJV1YZP0i/5g50YBxEX2vkysC71hniAVpRZ/rIGuGbY/GiGv3AuEyQnal2r"
    "KIqyHGB1PbA1X1lwyJlIR67Ik9ITHfKyCtf8QqwtsW0D7LpAWFCJz/ejrylga4L5zyRIL"
    "JfLimYSWd1FxlVy0v5V13MVUo1AEvdirqN56rIll7eOm+TESmv8rznp6Oo1xPsdmrf";

constexpr char kNonCanonicalVarintArchive[] =
    "RUFTUgIAAADIAAEBAAAAALoAAAAAAAAATAEAAAAAAAAHAAAAAAAAAGHNifcSi+4TfnrW"
    "C7UccLIvGGOr0spvDz+ZRbxKK3Q6gGy6bYIxxsB7Z5tQ3is1D/xpc61Mi7DG7e/kfDzE"
    "R1jc8pXtBlasQLsXv1JAQ5oL3nsh2bmHgXinVMvkjd3bk5hcGcA4iycmD9T9HlyEqnWtB"
    "IhiKYlCHRdQF5g8hRWssKQKGdwt7LVws83tBK8QvFSednIEIpRIe0Aj5PjjcwRFSURYAQ"
    "AADIYAAwADZGlyAAMNL2JvdW5kYXJ5LmJpbgGIJ7UCCwAJZW1wdHkudHh0AQAACGxpbms"
    "uYmluAhBkaXIvYm91bmRhcnkuYmluAAtuYXRpdmUubm9kZQ0NQfWO/l0dYUwv/cmt+Fyy"
    "9128Nquq46etT319ctp3y9IAB3Jhdy5iaW4BDAApJhis4+qQUKVBqUOMa2t9wK89A1dmC"
    "7r1yQPZcvoucLNAhMysFLW2ItGdRPssSFnqb1SPlGwb7R2fQ3NdTeCd/xD4jU3J5nIasA"
    "17D9VULTDpljRJsmDwEwRZDZPbOxRpfHr102UpamJVGGJvLos6WKFsLkl9SghKaGeFdM+"
    "svP9PDdlhmlcSF9V0u8c30sH3z+gv1uApLGofP/sl+nT63L/wan+XUYUSZ3Xo94olStZ7"
    "hPjrRUNANMaafU6Yq0qg/YSCaUOitJJkeu96rX4t7c0h4ABIWf1ozq2OjSsYnmVnDHSDs"
    "0qMfBXxyVdWGT9Iv+YOdGAcRF9r5MrAu9YZ4gFaUWf6yBrhm2Pxohr9wLhMkJ2pdqyiKs"
    "hxgdT2wNV9ZcMiZSEeuyJPSEx3ysgrX/EKsLbFtA+y6QFhQic/3o68pYGuC+c8kSCyXy4"
    "pmElndRcZVctL+VddzFVKNQBL3Yq6jeeqyJZe3jpvkxEpr/K856ejqNcT7HZq3w==";

constexpr char kBadPathArchive[] =
    "RUFTUgIAAADIAAEBAAAAALkAAAAAAAAATAEAAAAAAAAHAAAAAAAAAGHNifcSi+4TfnrW"
    "C7UccLIvGGOr0spvDz+ZRbxKK3Q6gGy6bYIxxsB7Z5tQ3is1D/xpc61Mi7DG7e/kfDzE"
    "R1gEe+wmlFAm9ZsY4TLZqh4/RWiAcag+R4TwI8x4kYM0pZzpN64U8q2pYLKg1WDpUOkCU"
    "vg28+s4n5MhYbPbiFw6EA1fADMa1ogCrEA96ET1USDsdYuCBQZE5TOlBAbe9AVFSURYAQ"
    "AADAYDAAMuLi8AAw0vYm91bmRhcnkuYmluAYgntQILAAllbXB0eS50eHQBAAAIbGluay5"
    "iaW4CEGRpci9ib3VuZGFyeS5iaW4AC25hdGl2ZS5ub2RlDQ1B9Y7+XR1hTC/9ya34XLL3"
    "Xbw2q6rjp61PfX1y2nfL0gAHcmF3LmJpbgEMACkmGKzj6pBQpUGpQ4xra33Arz0DV2YL"
    "uvXJA9ly+i5ws0CEzKwUtbYi0Z1E+yxIWepvVI+UbBvtHZ9Dc11N4J3/EPiNTcnmchqw"
    "DXsP1VQtMOmWNEmyYPATBFkNk9s7FGl8evXTZSlqYlUYYm8uizpYoWwuSX1KCEpoZ4V0"
    "z6y8/08N2WGaVxIX1XS7xzfSwffP6C/W4Cksah8/+yX6dPrcv/Bqf5dRhRJndej3iiVK"
    "1nuE+OtFQ0A0xpp9TpirSqD9hIJpQ6K0kmR673qtfi3tzSHgAEhZ/WjOrY6NKxieZWcMd"
    "IOzSox8FfHJV1YZP0i/5g50YBxEX2vkysC71hniAVpRZ/rIGuGbY/GiGv3AuEyQnal2r"
    "KIqyHGB1PbA1X1lwyJlIR67Ik9ITHfKyCtf8QqwtsW0D7LpAWFCJz/ejrylga4L5zyRIL"
    "JfLimYSWd1FxlVy0v5V13MVUo1AEvdirqN56rIll7eOm+TESmv8rznp6Oo1xPsdmrf";

constexpr char kBadFlagsArchive[] =
    "RUFTUgIAAADIAAEBAAAAALkAAAAAAAAATAEAAAAAAAAHAAAAAAAAAGHNifcSi+4TfnrW"
    "C7UccLIvGGOr0spvDz+ZRbxKK3Q6gGy6bYIxxsB7Z5tQ3is1D/xpc61Mi7DG7e/kfDzE"
    "R1hk+bq+LZBein5exP8ncsqWPYAtDotTAfQ6V2QTTFmkqwrtCvuZYX29h5ebs6lfyqEu5"
    "jxkXdG9iifCgjp2Q1k2Px9xkrSL53XB6G8naYEr1UBPBG3Woc8vH+zexYWPdwdFSURYAQ"
    "AADAYDAANkaXIDAw0vYm91bmRhcnkuYmluAYgntQILAAllbXB0eS50eHQBAAAIbGluay5"
    "iaW4CEGRpci9ib3VuZGFyeS5iaW4AC25hdGl2ZS5ub2RlDQ1B9Y7+XR1hTC/9ya34XLL3"
    "Xbw2q6rjp61PfX1y2nfL0gAHcmF3LmJpbgEMACkmGKzj6pBQpUGpQ4xra33Arz0DV2YL"
    "uvXJA9ly+i5ws0CEzKwUtbYi0Z1E+yxIWepvVI+UbBvtHZ9Dc11N4J3/EPiNTcnmchqw"
    "DXsP1VQtMOmWNEmyYPATBFkNk9s7FGl8evXTZSlqYlUYYm8uizpYoWwuSX1KCEpoZ4V0"
    "z6y8/08N2WGaVxIX1XS7xzfSwffP6C/W4Cksah8/+yX6dPrcv/Bqf5dRhRJndej3iiVK"
    "1nuE+OtFQ0A0xpp9TpirSqD9hIJpQ6K0kmR673qtfi3tzSHgAEhZ/WjOrY6NKxieZWcMd"
    "IOzSox8FfHJV1YZP0i/5g50YBxEX2vkysC71hniAVpRZ/rIGuGbY/GiGv3AuEyQnal2r"
    "KIqyHGB1PbA1X1lwyJlIR67Ik9ITHfKyCtf8QqwtsW0D7LpAWFCJz/ejrylga4L5zyRIL"
    "JfLimYSWd1FxlVy0v5V13MVUo1AEvdirqN56rIll7eOm+TESmv8rznp6Oo1xPsdmrf";

constexpr char kTrailingIndexArchive[] =
    "RUFTUgIAAADIAAEBAAAAALoAAAAAAAAATAEAAAAAAAAHAAAAAAAAAGHNifcSi+4TfnrW"
    "C7UccLIvGGOr0spvDz+ZRbxKK3Q6gGy6bYIxxsB7Z5tQ3is1D/xpc61Mi7DG7e/kfDzE"
    "R1iJ+P5sxBKK9V1WFdY/qWomHhkcH6c9hDN+bVg8c3NuORsBxzeheQ73C9BLhSqKViOXX"
    "0g24IdQLQD4V1Bnt+W6bF3DfdLwCHn3Ac1Y/JMzTyhLq9NzvlkIdtyL4De2ZQJFSURYAQ"
    "AADAYDAANkaXIAAw0vYm91bmRhcnkuYmluAYgntQILAAllbXB0eS50eHQBAAAIbGluay5"
    "iaW4CEGRpci9ib3VuZGFyeS5iaW4AC25hdGl2ZS5ub2RlDQ1B9Y7+XR1hTC/9ya34XLL3"
    "Xbw2q6rjp61PfX1y2nfL0gAHcmF3LmJpbgEMACkmGKzj6pBQpUGpQ4xra33Arz0DV2YL"
    "uvXJA9ly+i5ws0CEzKwUtbYi0Z1E+yxIWQDqb1SPlGwb7R2fQ3NdTeCd/xD4jU3J5nIa"
    "sA17D9VULTDpljRJsmDwEwRZDZPbOxRpfHr102UpamJVGGJvLos6WKFsLkl9SghKaGeFd"
    "M+svP9PDdlhmlcSF9V0u8c30sH3z+gv1uApLGofP/sl+nT63L/wan+XUYUSZ3Xo94olSt"
    "Z7hPjrRUNANMaafU6Yq0qg/YSCaUOitJJkeu96rX4t7c0h4ABIWf1ozq2OjSsYnmVnDHS"
    "Ds0qMfBXxyVdWGT9Iv+YOdGAcRF9r5MrAu9YZ4gFaUWf6yBrhm2Pxohr9wLhMkJ2pdqyi"
    "KshxgdT2wNV9ZcMiZSEeuyJPSEx3ysgrX/EKsLbFtA+y6QFhQic/3o68pYGuC+c8kSCyX"
    "y4pmElndRcZVctL+VddzFVKNQBL3Yq6jeeqyJZe3jpvkxEpr/K856ejqNcT7HZq3w==";

constexpr char kDataKeyHex[] =
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
constexpr char kPublicKeyHex[] =
    "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
constexpr char kDataKeyIdHex[] = "61cd89f7128bee137e7ad60bb51c70b2";
constexpr char kSigningKeyIdHex[] = "2f1863abd2ca6f0f3f9945bc4a2b743a";

template <size_t N>
std::array<uint8_t, N> HexArray(const char* value) {
  std::vector<uint8_t> bytes;
  CHECK(base::HexStringToBytes(value, &bytes));
  CHECK_EQ(bytes.size(), N);
  std::array<uint8_t, N> result{};
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

uint32_t ReadUInt32LE(const std::string& bytes, size_t offset) {
  return static_cast<uint8_t>(bytes[offset]) |
         (static_cast<uint32_t>(static_cast<uint8_t>(bytes[offset + 1])) << 8) |
         (static_cast<uint32_t>(static_cast<uint8_t>(bytes[offset + 2]))
          << 16) |
         (static_cast<uint32_t>(static_cast<uint8_t>(bytes[offset + 3])) << 24);
}

std::string BuildOrdinaryArchive(size_t file_count,
                                 std::string_view payload = "ok") {
  std::string header_json = R"({"files":{)";
  for (size_t index = 0; index < file_count; ++index) {
    if (index != 0)
      header_json.push_back(',');
    header_json.append("\"file")
        .append(base::NumberToString(index))
        .append("\":{\"size\":")
        .append(base::NumberToString(payload.size()))
        .append(",\"offset\":\"0\"}");
  }
  header_json.append("}}");
  base::Pickle header;
  header.WriteString(header_json);
  base::Pickle size;
  size.WriteUInt32(static_cast<uint32_t>(header.size()));
  std::string bytes(reinterpret_cast<const char*>(size.data()), size.size());
  bytes.append(reinterpret_cast<const char*>(header.data()), header.size());
  bytes.append(payload);
  return bytes;
}

class TestKeyProvider final : public EasrKeyProvider {
 public:
  bool GetDataKey(const EasrKeyId& id,
                  std::array<uint8_t, 32>* key) const override {
    if (!provide_data_key || id != data_key_id_)
      return false;
    *key = wrong_data_key ? std::array<uint8_t, 32>{} : data_key_;
    if (wrong_data_key)
      (*key)[0] = 1;
    return true;
  }

  bool GetSigningPublicKey(const EasrKeyId& id,
                           std::array<uint8_t, 32>* public_key) const override {
    if (!provide_signing_key || id != signing_key_id_)
      return false;
    *public_key = public_key_;
    if (wrong_signing_key)
      (*public_key)[0] ^= 1;
    return true;
  }

  uint64_t GetMinimumEpoch(const EasrKeyId&, const EasrKeyId&) const override {
    return minimum_epoch;
  }

  bool provide_data_key = true;
  bool provide_signing_key = true;
  bool wrong_data_key = false;
  bool wrong_signing_key = false;
  uint64_t minimum_epoch = 0;

 private:
  const EasrKeyId data_key_id_ = HexArray<16>(kDataKeyIdHex);
  const EasrKeyId signing_key_id_ = HexArray<16>(kSigningKeyIdHex);
  const std::array<uint8_t, 32> data_key_ = HexArray<32>(kDataKeyHex);
  const std::array<uint8_t, 32> public_key_ = HexArray<32>(kPublicKeyHex);
};

class EasrV2ArchiveTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    ClearArchives();
    ResetEasrSingleFileMaterializationLimitForTesting();
    SetEasrExternalFileDeleteFailureForTesting(false);
    ClearRetainedExternalFilesForTesting();
    SetRequireEncryptedAsarForProcess(false);
    SetEasrKeyProviderForProcess(&provider_);
  }

  void TearDown() override {
    SetEasrKeyProviderForProcess(nullptr);
    SetRequireEncryptedAsarForProcess(false);
    ClearArchives();
    ClearRetainedExternalFilesForTesting();
    ResetEasrSingleFileMaterializationLimitForTesting();
    SetEasrExternalFileDeleteFailureForTesting(false);
    ResetEasrGlobalChunkCacheByteLimitForTesting();
  }

  std::string Decode(const char* encoded) {
    std::string decoded;
    EXPECT_TRUE(base::Base64Decode(encoded, &decoded));
    return decoded;
  }

  base::FilePath WriteArchive(const std::string& bytes,
                              const std::string& name = "fixture.asar") {
    const base::FilePath path = temp_dir_.GetPath().AppendASCII(name);
    EXPECT_EQ(
        static_cast<int>(bytes.size()),
        base::WriteFile(path, bytes.data(), static_cast<int>(bytes.size())));
    return path;
  }

  std::unique_ptr<Archive> Open(const base::FilePath& path) {
    auto archive = std::make_unique<Archive>(path);
    if (!archive->Init())
      return nullptr;
    return archive;
  }

  std::string BoundaryPlaintext() {
    std::string value(5000, '\0');
    for (size_t index = 0; index < 4096; ++index)
      value[index] = static_cast<char>((index * 131 + 17) & 0xff);
    std::fill(value.begin() + 4096, value.end(), 'Z');
    return value;
  }

  base::ScopedTempDir temp_dir_;
  TestKeyProvider provider_;
};

TEST_F(EasrV2ArchiveTest, ReadsGoldenRawCompressedRangeEmptyAndSymlink) {
  const base::FilePath path = WriteArchive(Decode(kCanonicalArchive));
  std::unique_ptr<Archive> archive = Open(path);
  ASSERT_TRUE(archive);
  EXPECT_TRUE(archive->is_encrypted());

  Archive::FileInfo info;
  ASSERT_TRUE(archive->GetFileInfo(
      base::FilePath::FromUTF8Unsafe("dir/boundary.bin"), &info));
  EXPECT_EQ(info.size, 5000u);

  std::string range;
  Archive::Error error = Archive::Error::kIo;
  ASSERT_TRUE(archive->ReadRange(info, 4090, 20, &range, &error));
  EXPECT_EQ(error, Archive::Error::kNone);
  EXPECT_EQ(range, BoundaryPlaintext().substr(4090, 20));

  std::array<char, 20> direct_range{};
  ASSERT_TRUE(
      archive->ReadRange(info, 4090, base::make_span(direct_range), &error));
  EXPECT_EQ(std::string(direct_range.data(), direct_range.size()), range);

  std::string raw;
  EXPECT_TRUE(archive->ReadFile(base::FilePath::FromUTF8Unsafe("raw.bin"), &raw,
                                &error));
  EXPECT_EQ(raw, "raw-easr-v2\n");
  base::FilePath copied_raw;
  ASSERT_TRUE(archive->CopyFileOut(base::FilePath::FromUTF8Unsafe("raw.bin"),
                                   &copied_raw));
  ASSERT_TRUE(base::ReadFileToString(copied_raw, &raw));
  EXPECT_EQ(raw, "raw-easr-v2\n");

  std::string empty = "not empty";
  EXPECT_TRUE(archive->ReadFile(base::FilePath::FromUTF8Unsafe("empty.txt"),
                                &empty, &error));
  EXPECT_TRUE(empty.empty());

  std::string linked;
  EXPECT_TRUE(archive->ReadFile(base::FilePath::FromUTF8Unsafe("link.bin"),
                                &linked, &error));
  EXPECT_EQ(linked, BoundaryPlaintext());

  Archive::Stats stats;
  EXPECT_TRUE(
      archive->Stat(base::FilePath::FromUTF8Unsafe("link.bin"), &stats));
  EXPECT_TRUE(stats.is_link);
  base::FilePath realpath;
  EXPECT_TRUE(
      archive->Realpath(base::FilePath::FromUTF8Unsafe("link.bin"), &realpath));
  EXPECT_EQ(realpath.AsUTF8Unsafe(), "dir/boundary.bin");
  std::vector<base::FilePath> children;
  EXPECT_TRUE(archive->Readdir(base::FilePath(), &children));
  EXPECT_EQ(children.size(), 5u);
}

TEST_F(EasrV2ArchiveTest, BoundsAndReusesAuthenticatedChunkCache) {
  std::unique_ptr<Archive> archive =
      Open(WriteArchive(Decode(kCanonicalArchive)));
  ASSERT_TRUE(archive);
  archive->SetEasrChunkCacheLimitsForTesting(5000, 1);

  std::string contents;
  Archive::Error error = Archive::Error::kIo;
  ASSERT_TRUE(archive->ReadFile(base::FilePath::FromUTF8Unsafe("raw.bin"),
                                &contents, &error));
  ASSERT_TRUE(archive->ReadFile(base::FilePath::FromUTF8Unsafe("raw.bin"),
                                &contents, &error));
  auto stats = archive->GetEasrChunkCacheStatsForTesting();
  EXPECT_EQ(stats.misses, 1u);
  EXPECT_EQ(stats.hits, 1u);
  EXPECT_EQ(stats.entries, 1u);
  EXPECT_LE(stats.bytes, 5000u);

  Archive::FileInfo boundary;
  ASSERT_TRUE(archive->GetFileInfo(
      base::FilePath::FromUTF8Unsafe("dir/boundary.bin"), &boundary));
  ASSERT_TRUE(archive->ReadRange(boundary, 0, 1, &contents, &error));
  stats = archive->GetEasrChunkCacheStatsForTesting();
  EXPECT_EQ(stats.misses, 2u);
  EXPECT_EQ(stats.evictions, 1u);
  EXPECT_EQ(stats.entries, 1u);
  EXPECT_LE(stats.bytes, 5000u);
  EXPECT_GE(stats.cleansed_bytes, 12u);

  archive->ClearEasrChunkCacheForTesting();
  stats = archive->GetEasrChunkCacheStatsForTesting();
  EXPECT_EQ(stats.entries, 0u);
  EXPECT_EQ(stats.bytes, 0u);
  EXPECT_EQ(stats.evictions, 2u);
  EXPECT_GE(stats.cleansed_bytes, 4108u);
}

TEST_F(EasrV2ArchiveTest, EnforcesGlobalChunkBudgetAcrossArchives) {
  SetEasrGlobalChunkCacheByteLimitForTesting(4096);
  const std::string bytes = Decode(kCanonicalArchive);
  std::unique_ptr<Archive> first =
      Open(WriteArchive(bytes, "global-cache-first.asar"));
  std::unique_ptr<Archive> second =
      Open(WriteArchive(bytes, "global-cache-second.asar"));
  ASSERT_TRUE(first);
  ASSERT_TRUE(second);

  Archive::FileInfo first_boundary;
  ASSERT_TRUE(first->GetFileInfo(
      base::FilePath::FromUTF8Unsafe("dir/boundary.bin"), &first_boundary));
  std::array<char, 1> output{};
  Archive::Error error = Archive::Error::kIo;
  ASSERT_TRUE(
      first->ReadRange(first_boundary, 0, base::make_span(output), &error));
  EXPECT_EQ(GetEasrGlobalChunkCacheBytesForTesting(), 4096u);

  Archive::FileInfo second_raw;
  ASSERT_TRUE(second->GetFileInfo(base::FilePath::FromUTF8Unsafe("raw.bin"),
                                  &second_raw));
  ASSERT_TRUE(
      second->ReadRange(second_raw, 0, base::make_span(output), &error));
  EXPECT_EQ(second->GetEasrChunkCacheStatsForTesting().entries, 0u);
  EXPECT_EQ(GetEasrGlobalChunkCacheBytesForTesting(), 4096u);

  first->ClearEasrChunkCacheForTesting();
  EXPECT_EQ(GetEasrGlobalChunkCacheBytesForTesting(), 0u);
  ASSERT_TRUE(
      second->ReadRange(second_raw, 0, base::make_span(output), &error));
  EXPECT_EQ(second->GetEasrChunkCacheStatsForTesting().entries, 1u);
  EXPECT_EQ(GetEasrGlobalChunkCacheBytesForTesting(), 12u);
  second->ClearEasrChunkCacheForTesting();
  EXPECT_EQ(GetEasrGlobalChunkCacheBytesForTesting(), 0u);
}

TEST_F(EasrV2ArchiveTest, RetainsLocalCacheWhenGlobalReplacementCannotFit) {
  SetEasrGlobalChunkCacheByteLimitForTesting(4108);
  const std::string bytes = Decode(kCanonicalArchive);
  std::unique_ptr<Archive> first =
      Open(WriteArchive(bytes, "replacement-first.asar"));
  std::unique_ptr<Archive> second =
      Open(WriteArchive(bytes, "replacement-second.asar"));
  ASSERT_TRUE(first);
  ASSERT_TRUE(second);
  first->SetEasrChunkCacheLimitsForTesting(5000, 1);

  std::array<char, 1> output{};
  Archive::Error error = Archive::Error::kIo;
  Archive::FileInfo first_raw;
  ASSERT_TRUE(first->GetFileInfo(base::FilePath::FromUTF8Unsafe("raw.bin"),
                                 &first_raw));
  ASSERT_TRUE(first->ReadRange(first_raw, 0, base::make_span(output), &error));

  Archive::FileInfo second_boundary;
  ASSERT_TRUE(second->GetFileInfo(
      base::FilePath::FromUTF8Unsafe("dir/boundary.bin"), &second_boundary));
  ASSERT_TRUE(
      second->ReadRange(second_boundary, 0, base::make_span(output), &error));
  EXPECT_EQ(GetEasrGlobalChunkCacheBytesForTesting(), 4108u);

  Archive::FileInfo first_boundary;
  ASSERT_TRUE(first->GetFileInfo(
      base::FilePath::FromUTF8Unsafe("dir/boundary.bin"), &first_boundary));
  ASSERT_TRUE(
      first->ReadRange(first_boundary, 0, base::make_span(output), &error));
  auto stats = first->GetEasrChunkCacheStatsForTesting();
  EXPECT_EQ(stats.entries, 1u);
  EXPECT_EQ(stats.evictions, 0u);
  EXPECT_EQ(GetEasrGlobalChunkCacheBytesForTesting(), 4108u);

  ASSERT_TRUE(first->ReadRange(first_raw, 0, base::make_span(output), &error));
  stats = first->GetEasrChunkCacheStatsForTesting();
  EXPECT_EQ(stats.hits, 1u);
  EXPECT_EQ(stats.evictions, 0u);

  first->ClearEasrChunkCacheForTesting();
  second->ClearEasrChunkCacheForTesting();
  EXPECT_EQ(GetEasrGlobalChunkCacheBytesForTesting(), 0u);
}

TEST_F(EasrV2ArchiveTest, TransfersGlobalBudgetToSmallerReplacement) {
  SetEasrGlobalChunkCacheByteLimitForTesting(4096);
  std::unique_ptr<Archive> archive =
      Open(WriteArchive(Decode(kCanonicalArchive)));
  ASSERT_TRUE(archive);
  archive->SetEasrChunkCacheLimitsForTesting(5000, 1);

  Archive::FileInfo boundary;
  ASSERT_TRUE(archive->GetFileInfo(
      base::FilePath::FromUTF8Unsafe("dir/boundary.bin"), &boundary));
  std::array<char, 1> output{};
  Archive::Error error = Archive::Error::kIo;
  ASSERT_TRUE(archive->ReadRange(boundary, 0, base::make_span(output), &error));
  EXPECT_EQ(GetEasrGlobalChunkCacheBytesForTesting(), 4096u);

  ASSERT_TRUE(
      archive->ReadRange(boundary, 4096, base::make_span(output), &error));
  auto stats = archive->GetEasrChunkCacheStatsForTesting();
  EXPECT_EQ(stats.entries, 1u);
  EXPECT_EQ(stats.bytes, 904u);
  EXPECT_EQ(stats.evictions, 1u);
  EXPECT_EQ(GetEasrGlobalChunkCacheBytesForTesting(), 904u);

  ASSERT_TRUE(
      archive->ReadRange(boundary, 4096, base::make_span(output), &error));
  stats = archive->GetEasrChunkCacheStatsForTesting();
  EXPECT_EQ(stats.hits, 1u);
  EXPECT_EQ(stats.misses, 2u);

  archive->ClearEasrChunkCacheForTesting();
  EXPECT_EQ(GetEasrGlobalChunkCacheBytesForTesting(), 0u);
}

TEST_F(EasrV2ArchiveTest, ReportsStableReadErrors) {
  std::unique_ptr<Archive> archive =
      Open(WriteArchive(Decode(kCanonicalArchive)));
  ASSERT_TRUE(archive);
  std::string contents;
  Archive::Error error = Archive::Error::kNone;
  EXPECT_FALSE(archive->ReadFile(base::FilePath::FromUTF8Unsafe("missing.txt"),
                                 &contents, &error));
  EXPECT_EQ(error, Archive::Error::kNotFound);
  EXPECT_STREQ(ArchiveErrorName(error), "ERR_ASAR_NOT_FOUND");
  EXPECT_STREQ(ArchiveErrorName(Archive::Error::kAuthentication),
               "ERR_EASR_AUTHENTICATION");
  EXPECT_STREQ(ArchiveErrorName(Archive::Error::kRollback),
               "ERR_EASR_ROLLBACK");
}

TEST_F(EasrV2ArchiveTest, BoundsNativeArchiveCache) {
  ClearArchives();
  const std::string bytes = Decode(kCanonicalArchive);
  for (size_t index = 0; index < 40; ++index) {
    Archive::Error error = Archive::Error::kIo;
    ASSERT_TRUE(GetOrCreateAsarArchive(
        WriteArchive(bytes, "cache" + base::NumberToString(index) + ".asar"),
        &error));
    EXPECT_EQ(error, Archive::Error::kNone);
    EXPECT_LE(GetArchiveCacheSizeForTesting(), 32u);
  }
  EXPECT_EQ(GetArchiveCacheSizeForTesting(), 32u);
  ClearArchives();

  for (size_t index = 0; index < 300; ++index) {
    const base::FilePath full_path =
        temp_dir_.GetPath()
            .AppendASCII("directory-cache" + base::NumberToString(index) +
                         ".asar")
            .AppendASCII("child");
    base::FilePath asar_path;
    base::FilePath relative_path;
    EXPECT_TRUE(GetAsarArchivePath(full_path, &asar_path, &relative_path));
    EXPECT_LE(GetDirectoryCacheSizeForTesting(), 256u);
  }
  EXPECT_EQ(GetDirectoryCacheSizeForTesting(), 256u);
}

TEST_F(EasrV2ArchiveTest,
       PreservesOrdinaryMaterializationCompatibilityBeyondEasrLimits) {
  constexpr size_t kEntryCount = 40;
  std::unique_ptr<Archive> archive = Open(
      WriteArchive(BuildOrdinaryArchive(kEntryCount), "materialized.asar"));
  ASSERT_TRUE(archive);
  EXPECT_FALSE(archive->is_encrypted());
  for (size_t index = 0; index < kEntryCount; ++index) {
    base::FilePath output;
    Archive::Error error = Archive::Error::kIo;
    ASSERT_TRUE(archive->CopyFileOut(
        base::FilePath::FromUTF8Unsafe("file" + base::NumberToString(index)),
        &output, &error));
    EXPECT_EQ(error, Archive::Error::kNone);
    std::string contents;
    ASSERT_TRUE(base::ReadFileToString(output, &contents));
    EXPECT_EQ(contents, "ok");
  }
  EXPECT_EQ(GetRetainedExternalFileCountForTesting(), 0u);
  EXPECT_EQ(GetRetainedExternalFileBytesForTesting(), 0u);
}

TEST_F(EasrV2ArchiveTest, OrdinaryMaterializationSurvivesArchiveDestruction) {
  base::FilePath output;
  {
    std::unique_ptr<Archive> archive =
        Open(WriteArchive(BuildOrdinaryArchive(1), "ordinary-lifetime.asar"));
    ASSERT_TRUE(archive);
    ASSERT_TRUE(
        archive->CopyFileOut(base::FilePath::FromUTF8Unsafe("file0"), &output));
    ASSERT_TRUE(base::PathExists(output));
  }

  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(output, &contents));
  EXPECT_EQ(contents, "ok");
}

TEST_F(EasrV2ArchiveTest, OrdinaryMaterializationSurvivesArchiveCacheEviction) {
  const base::FilePath first_archive_path =
      WriteArchive(BuildOrdinaryArchive(1), "ordinary-cache-first.asar");
  std::shared_ptr<Archive> first = GetOrCreateAsarArchive(first_archive_path);
  ASSERT_TRUE(first);
  base::FilePath output;
  ASSERT_TRUE(
      first->CopyFileOut(base::FilePath::FromUTF8Unsafe("file0"), &output));
  first.reset();

  // The 32-entry LRU must evict and destroy the first Archive without
  // invalidating the bare path already returned to a native caller.
  for (size_t index = 0; index < 33; ++index) {
    ASSERT_TRUE(GetOrCreateAsarArchive(WriteArchive(
        BuildOrdinaryArchive(1),
        "ordinary-cache-" + base::NumberToString(index) + ".asar")));
  }
  EXPECT_EQ(GetArchiveCacheSizeForTesting(), 32u);

  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(output, &contents));
  EXPECT_EQ(contents, "ok");
}

TEST_F(EasrV2ArchiveTest, ReusesEncryptedMaterializationAcrossArchives) {
  const std::string bytes = Decode(kCanonicalArchive);
  std::unique_ptr<Archive> first =
      Open(WriteArchive(bytes, "reuse-first.asar"));
  std::unique_ptr<Archive> second =
      Open(WriteArchive(bytes, "reuse-second.asar"));
  ASSERT_TRUE(first);
  ASSERT_TRUE(second);

  base::FilePath first_path;
  base::FilePath second_path;
  ASSERT_TRUE(first->CopyFileOut(base::FilePath::FromUTF8Unsafe("raw.bin"),
                                 &first_path));
  ASSERT_TRUE(second->CopyFileOut(base::FilePath::FromUTF8Unsafe("/raw.bin"),
                                  &second_path));
  EXPECT_EQ(second_path, first_path);
  EXPECT_EQ(GetRetainedExternalFileCountForTesting(), 1u);
  EXPECT_EQ(GetRetainedExternalFileBytesForTesting(), 12u);
}

TEST_F(EasrV2ArchiveTest,
       SymlinkAliasesShareOneArchiveLocalMaterializationSlot) {
  std::unique_ptr<Archive> archive =
      Open(WriteArchive(Decode(kCanonicalArchive)));
  ASSERT_TRUE(archive);

  Archive::FileInfo target_info;
  Archive::FileInfo link_info;
  ASSERT_TRUE(archive->GetFileInfo(
      base::FilePath::FromUTF8Unsafe("dir/boundary.bin"), &target_info));
  ASSERT_TRUE(archive->GetFileInfo(base::FilePath::FromUTF8Unsafe("link.bin"),
                                   &link_info));
  ASSERT_EQ(link_info.easr_entry, target_info.easr_entry);

  base::FilePath first_path;
  // More raw spellings than the 32-slot admission cap must still collapse to
  // the one authenticated target when their required extension is identical.
  for (size_t index = 0; index < 40; ++index) {
    const std::string alias =
        std::string(index, '/') +
        (index % 2 == 0 ? "dir/boundary.bin" : "link.bin");
    base::FilePath output;
    Archive::Error error = Archive::Error::kIo;
    ASSERT_TRUE(archive->CopyFileOut(base::FilePath::FromUTF8Unsafe(alias),
                                     &output, &error));
    EXPECT_EQ(error, Archive::Error::kNone);
    if (first_path.empty())
      first_path = output;
    EXPECT_EQ(output, first_path);
    EXPECT_EQ(archive->GetEasrExternalFileSlotCountForTesting(), 1u);
  }
  EXPECT_EQ(GetRetainedExternalFileCountForTesting(), 1u);
  EXPECT_EQ(GetRetainedExternalFileBytesForTesting(), 5000u);
}

TEST_F(EasrV2ArchiveTest, ConcurrentSymlinkAliasSharesArchiveLocalPendingSlot) {
  std::unique_ptr<Archive> archive =
      Open(WriteArchive(Decode(kCanonicalArchive)));
  ASSERT_TRUE(archive);

  struct CopyResult {
    bool success = false;
    base::FilePath path;
    Archive::Error error = Archive::Error::kIo;
  };
  std::array<CopyResult, 2> results;
  const std::array<const char*, 2> aliases = {"dir/boundary.bin", "link.bin"};
  base::WaitableEvent start;
  std::array<std::thread, 2> threads;
  for (size_t index = 0; index < threads.size(); ++index) {
    threads[index] = std::thread([&, index] {
      start.Wait();
      results[index].success =
          archive->CopyFileOut(base::FilePath::FromUTF8Unsafe(aliases[index]),
                               &results[index].path, &results[index].error);
    });
  }
  start.Signal();
  for (std::thread& thread : threads)
    thread.join();

  for (const CopyResult& result : results) {
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.error, Archive::Error::kNone);
    EXPECT_EQ(result.path, results[0].path);
  }
  EXPECT_EQ(archive->GetEasrExternalFileSlotCountForTesting(), 1u);
  EXPECT_EQ(GetRetainedExternalFileCountForTesting(), 1u);
  EXPECT_EQ(GetRetainedExternalFileBytesForTesting(), 5000u);
}

TEST_F(EasrV2ArchiveTest, ConcurrentArchivesShareOneMaterialization) {
  constexpr size_t kArchiveCount = 8;
  const base::FilePath path = WriteArchive(Decode(kCanonicalArchive));
  std::vector<std::unique_ptr<Archive>> archives;
  archives.reserve(kArchiveCount);
  for (size_t index = 0; index < kArchiveCount; ++index) {
    archives.push_back(Open(path));
    ASSERT_TRUE(archives.back());
  }

  struct CopyResult {
    bool success = false;
    base::FilePath path;
    Archive::Error error = Archive::Error::kIo;
  };
  std::array<CopyResult, kArchiveCount> results;
  base::WaitableEvent start;
  std::vector<std::thread> threads;
  threads.reserve(kArchiveCount);
  for (size_t index = 0; index < kArchiveCount; ++index) {
    threads.emplace_back([&, index] {
      start.Wait();
      results[index].success = archives[index]->CopyFileOut(
          base::FilePath::FromUTF8Unsafe("dir/boundary.bin"),
          &results[index].path, &results[index].error);
    });
  }
  start.Signal();
  for (std::thread& thread : threads)
    thread.join();

  for (const CopyResult& result : results) {
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.error, Archive::Error::kNone);
    EXPECT_EQ(result.path, results[0].path);
  }
  EXPECT_EQ(GetRetainedExternalFileCountForTesting(), 1u);
  EXPECT_EQ(GetRetainedExternalFileBytesForTesting(), 5000u);
}

TEST_F(EasrV2ArchiveTest,
       DoesNotReuseOrdinaryMaterializationAfterSamePathReplacement) {
  const base::FilePath archive_path =
      WriteArchive(BuildOrdinaryArchive(1, "aa"), "replace.asar");
  base::File::Info original_info;
  ASSERT_TRUE(base::GetFileInfo(archive_path, &original_info));

  std::unique_ptr<Archive> archive = Open(archive_path);
  ASSERT_TRUE(archive);
  base::FilePath first_output;
  ASSERT_TRUE(archive->CopyFileOut(base::FilePath::FromUTF8Unsafe("file0"),
                                   &first_output));
  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(first_output, &contents));
  EXPECT_EQ(contents, "aa");
  archive.reset();

  const std::string replacement_bytes = BuildOrdinaryArchive(1, "bb");
  ASSERT_EQ(static_cast<uint64_t>(original_info.size),
            replacement_bytes.size());
  base::File replacement_file(archive_path,
                              base::File::FLAG_OPEN | base::File::FLAG_WRITE);
  ASSERT_TRUE(replacement_file.IsValid());
  ASSERT_EQ(static_cast<int>(replacement_bytes.size()),
            replacement_file.Write(0, replacement_bytes.data(),
                                   static_cast<int>(replacement_bytes.size())));
  replacement_file.Close();
  ASSERT_TRUE(base::TouchFile(archive_path, original_info.last_accessed,
                              original_info.last_modified));
  base::File::Info replacement_info;
  ASSERT_TRUE(base::GetFileInfo(archive_path, &replacement_info));
  EXPECT_EQ(replacement_info.size, original_info.size);
  EXPECT_EQ(replacement_info.creation_time, original_info.creation_time);
  EXPECT_EQ(replacement_info.last_modified, original_info.last_modified);

  archive = Open(archive_path);
  ASSERT_TRUE(archive);
  base::FilePath second_output;
  ASSERT_TRUE(archive->CopyFileOut(base::FilePath::FromUTF8Unsafe("file0"),
                                   &second_output));
  contents.clear();
  ASSERT_TRUE(base::ReadFileToString(second_output, &contents));
  EXPECT_EQ(contents, "bb");
  EXPECT_EQ(GetRetainedExternalFileCountForTesting(), 0u);
  EXPECT_EQ(GetRetainedExternalFileBytesForTesting(), 0u);
}

TEST_F(EasrV2ArchiveTest, EasrMaterializationLimitDoesNotApplyToOrdinaryAsar) {
  // Shrink EASR's production 256 MiB single-file ceiling to one byte. The
  // two-byte ordinary entry exercises the same admission boundary without a
  // giant test fixture and must continue through the historical fast path.
  SetEasrSingleFileMaterializationLimitForTesting(1);
  std::unique_ptr<Archive> ordinary =
      Open(WriteArchive(BuildOrdinaryArchive(1), "ordinary-limit-bypass.asar"));
  ASSERT_TRUE(ordinary);
  base::FilePath output;
  Archive::Error error = Archive::Error::kIo;
  ASSERT_TRUE(ordinary->CopyFileOut(base::FilePath::FromUTF8Unsafe("file0"),
                                    &output, &error));
  EXPECT_EQ(error, Archive::Error::kNone);
  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(output, &contents));
  EXPECT_EQ(contents, "ok");
  EXPECT_EQ(GetRetainedExternalFileCountForTesting(), 0u);
  EXPECT_EQ(GetRetainedExternalFileBytesForTesting(), 0u);

  std::unique_ptr<Archive> encrypted =
      Open(WriteArchive(Decode(kCanonicalArchive), "encrypted-limit.asar"));
  ASSERT_TRUE(encrypted);
  output.clear();
  error = Archive::Error::kNone;
  EXPECT_FALSE(encrypted->CopyFileOut(base::FilePath::FromUTF8Unsafe("raw.bin"),
                                      &output, &error));
  EXPECT_EQ(error, Archive::Error::kResourceExhausted);
  EXPECT_TRUE(output.empty());
  EXPECT_EQ(GetRetainedExternalFileCountForTesting(), 0u);
  EXPECT_EQ(GetRetainedExternalFileBytesForTesting(), 0u);
}

TEST_F(EasrV2ArchiveTest, DeleteNowImmediatelyRemovesUnpublishedPlaintext) {
  ScopedTemporaryFile file;
  ASSERT_TRUE(file.Init(FILE_PATH_LITERAL("bin")));
  const base::FilePath path = file.path();
  ASSERT_EQ(9, base::WriteFile(path, "plaintext", 9));
  ASSERT_TRUE(base::PathExists(path));

  file.DeleteNow();
  EXPECT_TRUE(file.path().empty());
  EXPECT_FALSE(base::PathExists(path));
}

TEST_F(EasrV2ArchiveTest,
       QuarantinedMaterializationFailureIsChargedOnlyOncePerEntry) {
  std::string bytes = Decode(kCanonicalArchive);
  const uint32_t index_size = ReadUInt32LE(bytes, 16);
  bytes[200 + index_size] ^= 1;
  std::unique_ptr<Archive> archive =
      Open(WriteArchive(bytes, "quarantined-failure.asar"));
  ASSERT_TRUE(archive);

  const base::FilePath path =
      base::FilePath::FromUTF8Unsafe("dir/boundary.bin");
  Archive::FileInfo info;
  ASSERT_TRUE(archive->GetFileInfo(path, &info));

  SetEasrExternalFileDeleteFailureForTesting(true);
  for (size_t attempt = 0; attempt < 3; ++attempt) {
    base::FilePath output;
    Archive::Error error = Archive::Error::kNone;
    EXPECT_FALSE(archive->CopyFileOut(path, &output, &error));
    EXPECT_EQ(error, Archive::Error::kAuthentication);
    EXPECT_TRUE(output.empty());
    EXPECT_EQ(GetRetainedExternalFileCountForTesting(), 1u);
    EXPECT_EQ(GetRetainedExternalFileBytesForTesting(), info.size);
  }
  SetEasrExternalFileDeleteFailureForTesting(false);

  ClearRetainedExternalFilesForTesting();
  EXPECT_EQ(GetRetainedExternalFileCountForTesting(), 0u);
  EXPECT_EQ(GetRetainedExternalFileBytesForTesting(), 0u);
}

TEST_F(EasrV2ArchiveTest, AuthenticatesUnpackedAndCopiesToPrivateFile) {
  const base::FilePath path = WriteArchive(Decode(kCanonicalArchive));
  const base::FilePath sidecar =
      path.AddExtension(FILE_PATH_LITERAL("unpacked"));
  ASSERT_TRUE(base::CreateDirectory(sidecar));
  const base::FilePath source = sidecar.AppendASCII("native.node");
  ASSERT_EQ(13, base::WriteFile(source, "native-addon\n", 13));

  std::unique_ptr<Archive> archive = Open(path);
  ASSERT_TRUE(archive);
  std::string contents;
  Archive::Error error = Archive::Error::kIo;
  ASSERT_TRUE(archive->ReadFile(base::FilePath::FromUTF8Unsafe("native.node"),
                                &contents, &error));
  EXPECT_EQ(contents, "native-addon\n");

  base::FilePath copied;
  ASSERT_TRUE(archive->CopyFileOut(
      base::FilePath::FromUTF8Unsafe("native.node"), &copied));
  EXPECT_NE(copied, source);
  EXPECT_FALSE(copied.IsParent(source));
  ASSERT_TRUE(base::ReadFileToString(copied, &contents));
  EXPECT_EQ(contents, "native-addon\n");

  ASSERT_EQ(13, base::WriteFile(source, "tampered!!!!\n", 13));
  EXPECT_FALSE(archive->ReadFile(base::FilePath::FromUTF8Unsafe("native.node"),
                                 &contents, &error));
  EXPECT_EQ(error, Archive::Error::kUnpackedAuthentication);
}

TEST_F(EasrV2ArchiveTest, RejectsEnvelopeAndPayloadTampering) {
  const std::string canonical = Decode(kCanonicalArchive);
  struct Case {
    size_t offset;
    Archive::Error error;
  };
  const uint32_t index_size = ReadUInt32LE(canonical, 16);
  const size_t payload_offset = 200 + index_size;
  const std::array<Case, 3> init_cases = {{
      {12, Archive::Error::kInvalidSignature},
      {136, Archive::Error::kInvalidSignature},
      {200, Archive::Error::kIndexHash},
  }};
  for (size_t case_index = 0; case_index < init_cases.size(); ++case_index) {
    std::string bytes = canonical;
    bytes[init_cases[case_index].offset] ^= 1;
    const base::FilePath path = WriteArchive(
        bytes, "tamper" + base::NumberToString(case_index) + ".asar");
    Archive archive(path);
    EXPECT_FALSE(archive.Init());
    EXPECT_EQ(archive.init_error(), init_cases[case_index].error);
  }

  for (bool append : {false, true}) {
    std::string bytes = canonical;
    if (append)
      bytes.push_back('\0');
    else
      bytes.pop_back();
    Archive archive(
        WriteArchive(bytes, append ? "trailing.asar" : "short.asar"));
    EXPECT_FALSE(archive.Init());
    EXPECT_EQ(archive.init_error(), Archive::Error::kArchiveSize);
  }

  std::string tag = canonical;
  tag[payload_offset - 1] ^= 1;
  Archive tag_archive(WriteArchive(tag, "tag.asar"));
  EXPECT_FALSE(tag_archive.Init());
  EXPECT_EQ(tag_archive.init_error(), Archive::Error::kIndexHash);

  std::string ciphertext = canonical;
  ciphertext[payload_offset] ^= 1;
  std::unique_ptr<Archive> archive =
      Open(WriteArchive(ciphertext, "ciphertext.asar"));
  ASSERT_TRUE(archive);
  std::string output;
  Archive::Error error = Archive::Error::kNone;
  EXPECT_FALSE(archive->ReadFile(
      base::FilePath::FromUTF8Unsafe("dir/boundary.bin"), &output, &error));
  EXPECT_EQ(error, Archive::Error::kAuthentication);

  Archive::FileInfo info;
  ASSERT_TRUE(archive->GetFileInfo(
      base::FilePath::FromUTF8Unsafe("dir/boundary.bin"), &info));
  std::array<char, 32> direct_output;
  direct_output.fill('x');
  EXPECT_FALSE(
      archive->ReadRange(info, 0, base::make_span(direct_output), &error));
  EXPECT_EQ(error, Archive::Error::kAuthentication);
  EXPECT_TRUE(std::all_of(direct_output.begin(), direct_output.end(),
                          [](char value) { return value == 0; }));
}

TEST_F(EasrV2ArchiveTest, RejectsWrongKeysAndRollback) {
  const base::FilePath path = WriteArchive(Decode(kCanonicalArchive));

  provider_.provide_signing_key = false;
  Archive unknown_signing(path);
  EXPECT_FALSE(unknown_signing.Init());
  EXPECT_EQ(unknown_signing.init_error(), Archive::Error::kUnknownSigningKey);

  provider_.provide_signing_key = true;
  provider_.wrong_signing_key = true;
  Archive wrong_signing(path);
  EXPECT_FALSE(wrong_signing.Init());
  EXPECT_EQ(wrong_signing.init_error(), Archive::Error::kSigningKeyIdMismatch);

  provider_.wrong_signing_key = false;
  provider_.provide_data_key = false;
  Archive unknown_data(path);
  EXPECT_FALSE(unknown_data.Init());
  EXPECT_EQ(unknown_data.init_error(), Archive::Error::kUnknownDataKey);

  provider_.provide_data_key = true;
  provider_.wrong_data_key = true;
  Archive wrong_data(path);
  EXPECT_FALSE(wrong_data.Init());
  EXPECT_EQ(wrong_data.init_error(), Archive::Error::kDataKeyIdMismatch);

  provider_.wrong_data_key = false;
  provider_.minimum_epoch = 8;
  Archive rollback(path);
  EXPECT_FALSE(rollback.Init());
  EXPECT_EQ(rollback.init_error(), Archive::Error::kRollback);
}

TEST_F(EasrV2ArchiveTest, RejectsSignedNonCanonicalIndexes) {
  const std::array<const char*, 4> malformed = {
      kNonCanonicalVarintArchive, kBadPathArchive, kBadFlagsArchive,
      kTrailingIndexArchive};
  for (size_t index = 0; index < malformed.size(); ++index) {
    Archive archive(
        WriteArchive(Decode(malformed[index]),
                     "malformed" + base::NumberToString(index) + ".asar"));
    EXPECT_FALSE(archive.Init());
    EXPECT_EQ(archive.init_error(), Archive::Error::kMalformedIndex);
  }
}

TEST_F(EasrV2ArchiveTest, FailsClosedForLegacyUnknownTruncatedAndHugeIndex) {
  for (uint32_t version : {1u, 99u}) {
    std::string bytes("EASR", 4);
    bytes.push_back(static_cast<char>(version));
    bytes.append(3, '\0');
    Archive archive(WriteArchive(
        bytes, "version" + base::NumberToString(version) + ".asar"));
    EXPECT_FALSE(archive.Init());
    EXPECT_EQ(archive.init_error(), version == 1
                                        ? Archive::Error::kLegacyVersion
                                        : Archive::Error::kUnsupportedVersion);
  }

  Archive truncated(
      WriteArchive(std::string("EASR\2\0\0\0", 8), "truncated.asar"));
  EXPECT_FALSE(truncated.Init());
  EXPECT_EQ(truncated.init_error(), Archive::Error::kMalformedSuperblock);

  std::string huge = Decode(kCanonicalArchive);
  huge[16] = 1;
  huge[17] = 0;
  huge[18] = 0;
  huge[19] = 1;  // 16 MiB + 1, rejected before allocation.
  Archive oversized(WriteArchive(huge, "oversized.asar"));
  EXPECT_FALSE(oversized.Init());
  EXPECT_EQ(oversized.init_error(), Archive::Error::kMalformedSuperblock);
}

TEST_F(EasrV2ArchiveTest, PreservesOrdinaryAsarUnlessPolicyRequiresV2) {
  const std::string header_json =
      R"({"files":{"hello.txt":{"size":2,"offset":"0"}}})";
  base::Pickle header;
  header.WriteString(header_json);
  base::Pickle size;
  size.WriteUInt32(static_cast<uint32_t>(header.size()));
  std::string bytes(reinterpret_cast<const char*>(size.data()), size.size());
  bytes.append(reinterpret_cast<const char*>(header.data()), header.size());
  bytes.append("ok", 2);
  const base::FilePath path = WriteArchive(bytes, "ordinary.asar");

  std::unique_ptr<Archive> archive = Open(path);
  ASSERT_TRUE(archive);
  EXPECT_FALSE(archive->is_encrypted());
  std::string contents;
  EXPECT_TRUE(archive->ReadFile(base::FilePath::FromUTF8Unsafe("hello.txt"),
                                &contents));
  EXPECT_EQ(contents, "ok");

  SetRequireEncryptedAsarForProcess(true);
  Archive required(path);
  EXPECT_FALSE(required.Init());
  EXPECT_EQ(required.init_error(), Archive::Error::kEncryptedArchiveRequired);
}

}  // namespace
}  // namespace asar
