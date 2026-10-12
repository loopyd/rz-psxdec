#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <time.h>
#include <tuple>
#include <unistd.h>
#include <vector>

#include <openssl/sha.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <retdec/config/config.h>
#include <retdec/retdec/retdec.h>

#include "rz-plugin/console/data_analysis.h"
#include "rz-plugin/rzretdec.h"
#include "rz-plugin/psx_overlays.h"

namespace retdec {
namespace rzplugin {
namespace {

constexpr const char *CONFIG_SHA = "6297157463f15283a86e5ed177bef059e0b7a360724b2741cdd920099334ad3b";
constexpr size_t REQUEST_LIMIT = 64 << 10;
constexpr size_t CONFIG_LIMIT = 16 << 10;
constexpr size_t PAYLOAD_LIMIT = 16 << 20;
constexpr size_t RANGE_LIMIT = 64 << 10;
constexpr size_t TOKENS_LIMIT = 8 << 20;
constexpr size_t INFERRED_LIMIT = 2 << 20;
constexpr size_t STATUS_LIMIT = 256 << 10;
constexpr size_t CATALOG_LIMIT = 64 << 10;
constexpr size_t CATALOG_IMAGE_LIMIT = 128;
constexpr size_t CATALOG_TOTAL_LIMIT = 64 << 20;
constexpr size_t BINDINGS_LIMIT = 2 << 20;
constexpr size_t BINDING_CALL_LIMIT = 4096;
constexpr size_t BINDING_ALTERNATIVE_LIMIT = 4096;
constexpr uint64_t ADDRESS_END = uint64_t(1) << 32;

struct Descriptor {
    int value;
    ~Descriptor() { if (value >= 0) ::close(value); }
};

void require(bool condition, const char *message)
{
    if (!condition) throw std::runtime_error(message);
}

std::string hexBytes(const std::string& bytes)
{
    const char *hex = "0123456789abcdef";
    std::string result;
    for (unsigned char byte : bytes) {
        result += hex[byte >> 4];
        result += hex[byte & 15];
    }
    return result;
}

std::string hash(const char *bytes, size_t size)
{
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest;
    SHA256(reinterpret_cast<const unsigned char *>(bytes), size, digest.data());
    return hexBytes(std::string(reinterpret_cast<const char *>(digest.data()), digest.size()));
}

std::string hash(const std::string& bytes)
{
    return hash(bytes.data(), bytes.size());
}

void checkCutoff(double cutoff);

std::string readFile(const char *path, size_t limit, double cutoff = 0)
{
    if (cutoff > 0) checkCutoff(cutoff);
    Descriptor file{::open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
    require(file.value >= 0, "fixed input cannot be opened");
    struct stat metadata;
    require(fstat(file.value, &metadata) == 0 && S_ISREG(metadata.st_mode), "fixed input is not regular");
    require(metadata.st_size >= 0 && uint64_t(metadata.st_size) <= limit, "fixed input exceeds bound");
    std::string bytes(size_t(metadata.st_size), '\0');
    size_t position = 0;
    while (position < bytes.size()) {
        if (cutoff > 0) checkCutoff(cutoff);
        auto span = cutoff > 0 ? std::min<size_t>(bytes.size() - position, 64 << 10) : bytes.size() - position;
        auto count = ::read(file.value, &bytes[position], span);
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "fixed input read is incomplete");
        position += size_t(count);
    }
    char extra;
    require(::read(file.value, &extra, 1) == 0, "fixed input grew during read");
    if (cutoff > 0) checkCutoff(cutoff);
    return bytes;
}

void writeFile(const char *path, const std::string& bytes, size_t limit)
{
    require(bytes.size() <= limit, "native artifact exceeds bound");
    Descriptor file{::open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)};
    require(file.value >= 0, "native artifact is not fresh");
    size_t position = 0;
    while (position < bytes.size()) {
        auto count = ::write(file.value, bytes.data() + position, bytes.size() - position);
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "native artifact write failed");
        position += size_t(count);
    }
    require(fsync(file.value) == 0, "native artifact sync failed");
    struct stat opened, linked;
    require(fstat(file.value, &opened) == 0 && S_ISREG(opened.st_mode)
        && opened.st_size >= 0 && uint64_t(opened.st_size) == bytes.size(), "native artifact size differs");
    require(lstat(path, &linked) == 0 && S_ISREG(linked.st_mode)
        && linked.st_dev == opened.st_dev && linked.st_ino == opened.st_ino, "native artifact identity differs");
    require(lseek(file.value, 0, SEEK_SET) == 0, "native artifact rewind failed");
    std::string observed(bytes.size(), '\0');
    position = 0;
    while (position < observed.size()) {
        auto count = ::read(file.value, &observed[position], observed.size() - position);
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "native artifact reread incomplete");
        position += size_t(count);
    }
    char extra;
    require(::read(file.value, &extra, 1) == 0 && observed == bytes, "native artifact bytes differ");
    require(lstat(path, &linked) == 0 && S_ISREG(linked.st_mode)
        && linked.st_dev == opened.st_dev && linked.st_ino == opened.st_ino
        && linked.st_size == opened.st_size, "native artifact final identity differs");
    int descriptor = file.value;
    file.value = -1;
    require(::close(descriptor) == 0, "native artifact close failed");
}

struct Artifact {
    std::string bytes;
    bool attempted = false, complete = false;
};

struct Artifacts {
    Artifact tokens, inferred, bindings;
    bool inferredComputed = false, partialRetention = false;
};

void retain(const char *path, Artifact& artifact, size_t limit)
{
    if (artifact.attempted || artifact.bytes.empty()) return;
    artifact.attempted = true;
    writeFile(path, artifact.bytes, limit);
    artifact.complete = true;
}

void fields(const rapidjson::Value& value, std::initializer_list<const char *> names)
{
    require(value.IsObject(), "JSON object required");
    std::set<std::string> expected(names.begin(), names.end()), observed;
    for (auto it = value.MemberBegin(); it != value.MemberEnd(); ++it) {
        require(it->name.IsString(), "JSON key must be text");
        std::string name(it->name.GetString(), it->name.GetStringLength());
        require(expected.count(name) && observed.insert(name).second, "unknown or duplicate JSON key");
    }
    require(observed == expected, "required JSON field missing");
}

const rapidjson::Value& member(const rapidjson::Value& value, const char* name)
{
    require(value.IsObject() && value.HasMember(name), "required observation field missing");
    return value[name];
}

std::string text(const rapidjson::Value& value, size_t limit = 256)
{
    require(value.IsString() && value.GetStringLength() > 0 && value.GetStringLength() <= limit, "bounded text required");
    std::string result(value.GetString(), value.GetStringLength());
    for (unsigned char byte : result) require(byte >= 32 && byte <= 126, "identity text must be printable ASCII");
    return result;
}

std::string digest(const rapidjson::Value& value)
{
    auto result = text(value, 64);
    require(result.size() == 64, "SHA256 length invalid");
    for (char byte : result) require((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'), "SHA256 encoding invalid");
    return result;
}

uint64_t number(const rapidjson::Value& value, uint64_t maximum)
{
    require(value.IsUint64() && value.GetUint64() <= maximum, "bounded unsigned integer required");
    return value.GetUint64();
}

rapidjson::Document parse(const std::string& bytes)
{
    unsigned depth = 0;
    bool quoted = false, escaped = false;
    for (char byte : bytes) {
        require(byte != '\0', "JSON NUL rejected");
        if (quoted) {
            if (escaped) escaped = false;
            else if (byte == '\\') escaped = true;
            else if (byte == '"') quoted = false;
        } else if (byte == '"') quoted = true;
        else if (byte == '{' || byte == '[') require(++depth <= 16, "JSON nesting exceeds bound");
        else if (byte == '}' || byte == ']') { require(depth > 0, "JSON nesting invalid"); --depth; }
    }
    require(!quoted && depth == 0, "JSON nesting incomplete");
    rapidjson::Document value;
    value.Parse<rapidjson::kParseValidateEncodingFlag | rapidjson::kParseFullPrecisionFlag>(bytes.data(), bytes.size());
    require(!value.HasParseError(), "JSON parse failed");
    return value;
}

void checkCutoff(double cutoff)
{
    struct timespec now;
    require(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic clock unavailable");
    require(std::isfinite(cutoff) && cutoff > double(now.tv_sec) + double(now.tv_nsec) / 1e9, "original cutoff expired");
}

struct Request {
    std::string operation;
    double cutoff;
    uint64_t load = 0, payloadBytes = 0, start = 0, end = 0;
    uint64_t invokedStart = 0, invokedEnd = 0;
    uint64_t fileBytes = 0, payloadOffset = 0;
    std::string fileHash, payloadHash, rangeHash, catalogHash;
    std::optional<common::OriginalCallScope> scope;
    std::optional<common::OriginalSourceForm> sourceForm;
    std::vector<std::string> overlayMounts;
    bool overlays = false;
    std::optional<common::OriginalEntryObservation> entryObservation;
};

common::OriginalEntryObservation readEntryObservation(const rapidjson::Value& value,
    const std::string& workspace, double cutoff)
{
    fields(value, {"function", "image_id", "image_sha256", "entry_pc", "state", "files"});
    common::OriginalEntryObservation observation;
    observation.function = text(value["function"]); observation.imageId = text(value["image_id"]);
    observation.imageHash = digest(value["image_sha256"]);
    observation.pc = uint32_t(number(value["entry_pc"], UINT32_MAX));
    fields(value["state"], {"bytes", "sha256"});
    auto stateBytes = number(value["state"]["bytes"], 64 << 20);
    observation.stateHash = digest(value["state"]["sha256"]);
    const auto& captures = value["files"];
    fields(captures, {"entry-receipt.json", "cpu-receipt.json", "registers.json", "ram.bin", "cpu.json"});
    std::map<std::string, std::string> files, hashes;
    for (const auto& name : {"entry-receipt.json", "cpu-receipt.json", "registers.json", "ram.bin", "cpu.json"}) {
        const auto& record = captures[name]; fields(record, {"path", "bytes", "sha256"});
        auto path = text(record["path"]);
        require(path == std::string("input/entry-") + name, "entry observation path rejected");
        auto limit = std::string(name) == "ram.bin" || std::string(name).find("receipt") != std::string::npos ? 2 << 20 : 64 << 10;
        auto bytes = readFile((workspace + "/" + path).c_str(), limit, cutoff);
        hashes[name] = digest(record["sha256"]);
        require(bytes.size() == number(record["bytes"], limit) && hash(bytes) == hashes[name], "entry observation capture identity differs");
        files.emplace(name, std::move(bytes));
    }
    auto entry = parse(files.at("entry-receipt.json")), cpu = parse(files.at("cpu-receipt.json"));
    for (const auto* receipt : {&entry, &cpu}) {
        require(receipt->IsObject() && receipt->HasMember("schema") && receipt->HasMember("status")
            && text((*receipt)["schema"]) == "psx.runtime-session/v2" && text((*receipt)["status"]) == "passed", "entry observation receipt rejected");
        fields(member(*receipt, "mission"), {"kind", "name", "resources"});
        require(text((*receipt)["mission"]["kind"]) == "builtin", "entry observation mission rejected");
        fields(member(*receipt, "completion"), {"schema", "captures"});
        require(member(*receipt, "inputs").IsObject() && member(*receipt, "emulator").IsObject()
            && member(*receipt, "arguments").IsObject(), "entry receipt inputs rejected");
    }
    require(text(entry["mission"]["name"]) == "target" && text(cpu["mission"]["name"]) == "state", "entry observation mission differs");
    require(text(member(cpu["arguments"], "PATH")) == "registers" && text(member(cpu["arguments"], "DEPTH")) == "2", "entry CPU query differs");
    for (auto key : {"revision", "binary_sha256", "sdl_sha256"})
        require(text(member(entry["emulator"], key)) == text(member(cpu["emulator"], key)), "entry emulator identity differs");
    const auto& state = member(cpu["inputs"], "file:STATE");
    fields(state, {"path", "bytes", "sha256"});
    require(!entry["inputs"].HasMember("executable"), "entry observation executable injection rejected");
    for (auto key : {"bytes", "sha256"}) {
        const auto& a = member(member(entry["inputs"], "bios"), key);
        const auto& b = member(member(cpu["inputs"], "bios"), key);
        require((a.IsString() && b.IsString() && text(a) == text(b))
            || (a.IsUint64() && b.IsUint64() && a.GetUint64() == b.GetUint64()), "entry BIOS identity differs");
    }
    require(number(state["bytes"], 64 << 20) == stateBytes && digest(state["sha256"]) == observation.stateHash, "CPU inspected state identity differs");
    auto captureMatches = [&](const rapidjson::Value& receipt, const char* name, size_t bytes, const std::string& sha) {
        require(text(receipt["completion"]["schema"]) == "psx.runtime-completion/v1" && receipt["completion"]["captures"].IsArray()
            && receipt["completion"]["captures"].Size() <= 128, "entry receipt completion rejected");
        size_t matches = 0;
        for (const auto& record : receipt["completion"]["captures"].GetArray()) {
            fields(record, {"path", "bytes", "sha256"});
            if (text(record["path"]) == name) {
                require(number(record["bytes"], 64 << 20) == bytes && digest(record["sha256"]) == sha, "entry receipt capture differs"); ++matches;
            }
        }
        require(matches == 1, "entry receipt capture missing or duplicated");
    };
    captureMatches(entry, "state.pbuf", stateBytes, observation.stateHash);
    captureMatches(entry, "registers.json", files.at("registers.json").size(), hashes.at("registers.json"));
    captureMatches(entry, "ram.bin", files.at("ram.bin").size(), hashes.at("ram.bin"));
    captureMatches(cpu, "query.json", files.at("cpu.json").size(), hashes.at("cpu.json"));
    auto registers = parse(files.at("registers.json")), query = parse(files.at("cpu.json"));
    fields(registers, {"schema", "pc", "cycles", "registers"});
    require(text(registers["schema"]) == "psx.runtime-registers/v1"
        && number(registers["pc"], UINT32_MAX) == observation.pc
        && registers["registers"].IsArray() && registers["registers"].Size() == 32, "entry native registers rejected");
    fields(query, {"schema", "path", "value"});
    require(text(query["schema"]) == "psx.runtime-query/v1" && text(query["path"]) == "registers", "entry CPU query rejected");
    auto queryFields = [&](const rapidjson::Value& node) {
        require(node.IsObject() && node.HasMember("fields") && node["fields"].IsArray() && node["fields"].Size() <= 32, "entry CPU fields rejected");
        std::map<std::string, const rapidjson::Value*> values;
        for (const auto& field : node["fields"].GetArray()) {
            require(field.IsObject() && field.HasMember("name") && field.HasMember("present") && field.HasMember("value")
                && field["present"].IsBool() && field["present"].GetBool(), "entry CPU field absent");
            require(values.emplace(text(field["name"]), &field["value"]).second, "entry CPU field duplicated");
        }
        return values;
    };
    auto values = queryFields(query["value"]);
    require(number(*values.at("pc"), UINT32_MAX) == observation.pc
        && number(*values.at("cycle"), UINT64_MAX) == number(registers["cycles"], UINT64_MAX), "entry CPU position differs");
    const auto& gprs = member(*values.at("gpr"), "items");
    require(gprs.IsArray() && gprs.Size() == 34, "entry CPU GPR census differs");
    for (unsigned reg = 0; reg < 32; ++reg)
        require(number(gprs[reg], UINT32_MAX) == number(registers["registers"][reg], UINT32_MAX), "entry CPU registers differ");
    for (auto name : {"next_is_delay_slot", "in_isr"})
        require(values.at(name)->IsBool() && !values.at(name)->GetBool(), "entry CPU is not settled");
    for (auto name : {"delay_slot_info_1", "delay_slot_info_2"}) {
        auto pending = queryFields(*values.at(name));
        for (auto flag : {"active", "pc_active"}) require(pending.at(flag)->IsBool() && !pending.at(flag)->GetBool(), "entry CPU has pending transfer");
    }
    const auto& cp0 = member(*values.at("cp0"), "items");
    require(cp0.IsArray() && cp0.Size() == 32 && !(number(cp0[12], UINT32_MAX) & 0x10000), "entry RAM stores are cache isolated");
    observation.sp = uint32_t(number(gprs[29], UINT32_MAX));
    require(observation.pc % 4 == 0 && observation.sp % 4 == 0 && common::psxRamAddress(observation.sp)
        && files.at("ram.bin").size() == 0x200000, "entry PC, SP or RAM invalid");
    observation.ram.assign(files.at("ram.bin").begin(), files.at("ram.bin").end());
    rapidjson::StringBuffer buffer; rapidjson::Writer<rapidjson::StringBuffer> writer(buffer); value.Accept(writer);
    observation.identity = hash(buffer.GetString(), buffer.GetSize());
    return observation;
}

Request readRequest(const rapidjson::Document& doc, const std::string& workspace)
{
    require(doc.IsObject() && doc.HasMember("schema"), "request schema missing");
    auto schema = text(doc["schema"]);
    bool observation = schema == "retdec118.native-request/v6";
    bool overlays = observation || schema == "retdec118.native-request/v5";
    bool forms = schema == "retdec118.native-request/v4" || (overlays && doc.HasMember("source_form"));
    bool bindings = overlays || forms || schema == "retdec118.native-request/v3";
    bool graph = bindings || schema == "retdec118.native-request/v2";
    if (observation && forms) fields(doc, {"schema", "operation", "request_id", "config_sha256", "cutoff", "member", "image", "problem_sha256", "callees", "image_catalog_sha256", "source_form", "overlay_mounts", "entry_observation"});
    else if (observation) fields(doc, {"schema", "operation", "request_id", "config_sha256", "cutoff", "member", "image", "problem_sha256", "callees", "image_catalog_sha256", "overlay_mounts", "entry_observation"});
    else if (overlays && forms) fields(doc, {"schema", "operation", "request_id", "config_sha256", "cutoff", "member", "image", "problem_sha256", "callees", "image_catalog_sha256", "source_form", "overlay_mounts"});
    else if (overlays) fields(doc, {"schema", "operation", "request_id", "config_sha256", "cutoff", "member", "image", "problem_sha256", "callees", "image_catalog_sha256", "overlay_mounts"});
    else if (forms) fields(doc, {"schema", "operation", "request_id", "config_sha256", "cutoff", "member", "image", "problem_sha256", "callees", "image_catalog_sha256", "source_form"});
    else if (bindings) fields(doc, {"schema", "operation", "request_id", "config_sha256", "cutoff", "member", "image", "problem_sha256", "callees", "image_catalog_sha256"});
    else if (graph) fields(doc, {"schema", "operation", "request_id", "config_sha256", "cutoff", "member", "image", "problem_sha256", "callees"});
    else fields(doc, {"schema", "operation", "request_id", "config_sha256", "cutoff", "member", "image"});
    require(graph || schema == "retdec118.native-request/v1", "request schema rejected");
    digest(doc["request_id"]);
    require(digest(doc["config_sha256"]) == CONFIG_SHA, "configuration identity is not this release");
    require(doc["cutoff"].IsNumber() && !doc["cutoff"].IsBool(), "cutoff must be numeric");
    Request request;
    request.overlays = overlays;
    if (overlays) {
        require(doc["overlay_mounts"].IsArray() && !doc["overlay_mounts"].Empty()
            && doc["overlay_mounts"].Size() <= CATALOG_IMAGE_LIMIT, "overlay mount inventory rejected");
        std::set<std::string> mounted;
        for (const auto& id : doc["overlay_mounts"].GetArray()) {
            auto name = text(id);
            require(mounted.insert(name).second, "overlay mount inventory duplicates an image");
            request.overlayMounts.push_back(std::move(name));
        }
    }
    if (forms) request.sourceForm = common::parseOriginalSourceForm(text(doc["source_form"]));
    if (bindings) request.catalogHash = digest(doc["image_catalog_sha256"]);
    request.operation = text(doc["operation"]);
    request.cutoff = doc["cutoff"].GetDouble();
    checkCutoff(request.cutoff);
    if (observation) request.entryObservation = readEntryObservation(doc["entry_observation"], workspace, request.cutoff);
    if (request.operation == "self-check") {
        require(!graph && doc["member"].IsNull() && doc["image"].IsNull(), "self-check cannot consume original input");
        return request;
    }
    require(request.operation == "generate", "operation rejected");
    const auto& member = doc["member"];
    const auto& image = doc["image"];
    fields(member, {"key", "target", "image_id", "start", "end", "range_sha256"});
    fields(image, {"file_sha256", "file_bytes", "payload_sha256", "payload_offset", "payload_bytes", "load_address"});
    text(member["key"]); text(member["target"]); text(member["image_id"]);
    request.fileHash = digest(image["file_sha256"]);
    request.fileBytes = number(image["file_bytes"], (uint64_t(1) << 40));
    request.payloadOffset = number(image["payload_offset"], request.fileBytes);
    request.payloadBytes = number(image["payload_bytes"], PAYLOAD_LIMIT);
    require(request.payloadBytes > 0 && request.payloadBytes <= request.fileBytes - request.payloadOffset, "payload file extent invalid");
    request.load = number(image["load_address"], ADDRESS_END - 1);
    require(request.payloadBytes <= ADDRESS_END - request.load, "payload address overflow");
    request.start = number(member["start"], ADDRESS_END - 1);
    request.end = number(member["end"], ADDRESS_END);
    require(request.start % 4 == 0 && request.end % 4 == 0 && request.end > request.start, "member must be aligned and nonempty");
    require(request.end - request.start <= RANGE_LIMIT, "member range exceeds bound");
    require(request.start >= request.load && request.end <= request.load + request.payloadBytes, "member escapes payload");
    request.payloadHash = digest(image["payload_sha256"]);
    request.rangeHash = digest(member["range_sha256"]);
    if (graph) {
        common::OriginalCallScope scope;
        scope.problemHash = digest(doc["problem_sha256"]);
        scope.configurationHash = CONFIG_SHA; scope.payloadHash = request.payloadHash;
        auto readMember = [&](const auto& row) {
            fields(row, {"key", "target", "image_id", "start", "end", "range_sha256"});
            common::ReviewedOriginalFunction f;
            f.key = text(row["key"]); f.target = text(row["target"]); f.imageId = text(row["image_id"]);
            f.start = number(row["start"], ADDRESS_END - 1); f.end = number(row["end"], ADDRESS_END);
            f.rangeHash = digest(row["range_sha256"]);
            require(f.start % 4 == 0 && f.end % 4 == 0 && f.start < f.end && f.end - f.start <= RANGE_LIMIT
                && f.start >= request.load && f.end <= request.load + request.payloadBytes, "callee extent rejected");
            return f;
        };
        scope.root = readMember(member);
        require(doc["callees"].IsArray() && doc["callees"].Size() <= 117, "callee inventory rejected");
        for (const auto& row : doc["callees"].GetArray()) scope.callees.push_back(readMember(row));
        request.scope = std::move(scope);
    }
    return request;
}

config::Config cleanConfig(const rapidjson::Document& doc)
{
    fields(doc, {"schema", "architecture", "output_format", "selected_decode_only", "keep_all_functions", "deterministic", "detect_static_code", "max_memory_limit_half_ram", "support", "llvm_passes"});
    require(text(doc["schema"]) == "retdec118.native-config/v1", "config schema rejected");
    fields(doc["architecture"], {"name", "bits", "endian", "file_format"});
    require(text(doc["architecture"]["name"]) == "mips" && number(doc["architecture"]["bits"], 32) == 32, "architecture rejected");
    require(text(doc["architecture"]["endian"]) == "little" && text(doc["architecture"]["file_format"]) == "raw", "raw format rejected");
    require(text(doc["output_format"]) == "json-human", "output format rejected");
    for (auto key : {"selected_decode_only", "keep_all_functions", "deterministic"})
        require(doc[key].IsBool() && doc[key].GetBool(), "required fixed flag rejected");
    for (auto key : {"detect_static_code", "max_memory_limit_half_ram"})
        require(doc[key].IsBool() && !doc[key].GetBool(), "forbidden fixed flag rejected");
    const auto& support = doc["support"];
    fields(support, {"static_signatures", "user_static_signatures", "library_types", "crypto_patterns", "abi", "ordinal_directory"});
    for (auto key : {"static_signatures", "user_static_signatures", "library_types", "crypto_patterns", "abi"})
        require(support[key].IsArray() && support[key].Empty(), "support assets forbidden");
    require(support["ordinal_directory"].IsString() && support["ordinal_directory"].GetStringLength() == 0, "ordinal assets forbidden");
    require(doc["llvm_passes"].IsArray() && doc["llvm_passes"].Size() == 142, "fixed pass sequence rejected");
    auto config = config::Config::empty();
    config.architecture.setIsMips(); config.architecture.setBitSize(32); config.architecture.setIsEndianLittle();
    config.fileFormat.setIsRaw32(); config.fileType.setIsExecutable();
    config.parameters.setOutputFormat("json-human");
    config.parameters.setIsSelectedDecodeOnly(true); config.parameters.setIsKeepAllFunctions(true);
    config.parameters.setIsVerboseOutput(false); config.parameters.setIsDetectStaticCode(false);
    config.parameters.setIsBackendNoTimeVaryingInfo(true); config.parameters.setIsMaxMemoryLimitHalfRam(false);
    for (const auto& pass : doc["llvm_passes"].GetArray()) config.parameters.llvmPasses.push_back(text(pass));
    require(config.functions.empty() && config.globals.empty() && config.structures.empty()
        && config.registers.empty() && config.vtables.empty() && config.classes.empty()
        && config.patterns.empty() && config.tools.empty() && config.languages.empty(), "initial declarations forbidden");
    require(config.parameters.getMainAddress().isUndefined() && config.parameters.selectedFunctions.empty()
        && config.parameters.selectedNotFoundFunctions.empty(), "initial selection/context forbidden");
    require(config.parameters.staticSignaturePaths.empty() && config.parameters.userStaticSignaturePaths.empty()
        && config.parameters.libraryTypeInfoPaths.empty() && config.parameters.cryptoPatternPaths.empty()
        && config.parameters.abiPaths.empty() && config.parameters.getOrdinalNumbersDirectory().empty(), "initial support forbidden");
    require(config.parameters.getInputPdbFile().empty(), "initial debug context forbidden");
    config.parameters.setIsOriginalOnlyReturnRecovery(true);
    return config;
}

using Writer = rapidjson::Writer<rapidjson::StringBuffer>;

std::string compactInferredConfiguration(const std::string& generated)
{
    try {
        rapidjson::Document document;
        document.Parse<rapidjson::kParseFullPrecisionFlag | rapidjson::kParseIterativeFlag>(generated.data(), generated.size());
        if (document.HasParseError()) return generated;
        rapidjson::StringBuffer buffer;
        Writer writer(buffer);
        if (!document.Accept(writer) || !writer.IsComplete()) return generated;
        return std::string(buffer.GetString(), buffer.GetSize());
    } catch (const std::exception&) {
        return generated;
    }
}

void string(Writer& writer, const std::string& value)
{
    writer.String(value.data(), value.size());
}

void range(Writer& writer, uint64_t start, uint64_t end)
{
    writer.StartObject(); writer.Key("start"); writer.Uint64(start); writer.Key("end"); writer.Uint64(end); writer.EndObject();
}

struct BindingImage {
    std::string id, fileHash, payloadHash;
    uint64_t fileBytes, payloadOffset, payloadBytes, load;
    std::vector<size_t> members;
};

struct BindingTarget {
    std::string target;
    size_t image;
};

struct BindingCatalog {
    std::vector<BindingImage> images;
    std::vector<BindingTarget> targets;
    std::vector<common::ReviewedOriginalFunction> members;
};

bool sameMember(const common::ReviewedOriginalFunction& a, const common::ReviewedOriginalFunction& b)
{
    return std::tie(a.key, a.target, a.imageId, a.start, a.end, a.rangeHash)
        == std::tie(b.key, b.target, b.imageId, b.start, b.end, b.rangeHash);
}

BindingCatalog readBindingCatalog(const Request& request, const std::string& workspace)
{
    auto bytes = readFile((workspace + "/input/image-catalog.json").c_str(), CATALOG_LIMIT, request.cutoff);
    require(hash(bytes) == request.catalogHash, "original image catalog hash differs");
    auto doc = parse(bytes);
    fields(doc, {"schema", "problem_sha256", "images", "targets", "members"});
    require(text(doc["schema"]) == "retdec118.original-image-catalog/v1", "original image catalog schema rejected");
    require(request.scope && digest(doc["problem_sha256"]) == request.scope->problemHash, "catalog Problem identity differs");
    require(doc["images"].IsArray() && !doc["images"].Empty() && doc["images"].Size() <= CATALOG_IMAGE_LIMIT, "catalog image count rejected");
    require(doc["targets"].IsArray() && !doc["targets"].Empty() && doc["targets"].Size() <= CATALOG_IMAGE_LIMIT, "catalog target count rejected");
    require(doc["members"].IsArray() && doc["members"].Size() == 118, "catalog member count rejected");
    BindingCatalog catalog;
    std::map<std::string, size_t> images, targets, members;
    uint64_t totalBytes = 0;
    for (const auto& row : doc["images"].GetArray()) {
        checkCutoff(request.cutoff);
        fields(row, {"image_id", "file_sha256", "file_bytes", "payload_offset", "payload_sha256", "payload_bytes", "load_address", "payload_index"});
        BindingImage image;
        image.id = text(row["image_id"]); image.fileHash = digest(row["file_sha256"]); image.payloadHash = digest(row["payload_sha256"]);
        image.fileBytes = number(row["file_bytes"], PAYLOAD_LIMIT);
        image.payloadOffset = number(row["payload_offset"], image.fileBytes);
        image.payloadBytes = number(row["payload_bytes"], PAYLOAD_LIMIT);
        image.load = number(row["load_address"], ADDRESS_END - 1);
        require(image.payloadBytes > 0 && image.payloadBytes <= image.fileBytes - image.payloadOffset
            && image.payloadBytes <= ADDRESS_END - image.load, "catalog physical payload extent rejected");
        require(number(row["payload_index"], CATALOG_IMAGE_LIMIT - 1) == catalog.images.size(), "catalog payload index rejected");
        require(catalog.images.empty() || catalog.images.back().id < image.id, "catalog image order or identity rejected");
        auto available = CATALOG_TOTAL_LIMIT - totalBytes;
        require(image.fileBytes <= available && image.payloadBytes <= available - image.fileBytes, "catalog aggregate bytes rejected");
        totalBytes += image.fileBytes + image.payloadBytes;
        images.emplace(image.id, catalog.images.size());
        catalog.images.push_back(std::move(image));
    }
    for (const auto& row : doc["targets"].GetArray()) {
        fields(row, {"target", "kind", "image_id"});
        auto target = text(row["target"]), image = text(row["image_id"]);
        text(row["kind"]);
        auto found = images.find(image);
        require(found != images.end(), "catalog target image missing");
        require(catalog.targets.empty() || catalog.targets.back().target < target, "catalog target order or identity rejected");
        targets.emplace(target, catalog.targets.size());
        catalog.targets.push_back({std::move(target), found->second});
    }
    std::set<std::tuple<std::string, std::string, uint64_t>> starts;
    for (const auto& row : doc["members"].GetArray()) {
        checkCutoff(request.cutoff);
        fields(row, {"key", "target", "image_id", "start", "end", "range_sha256"});
        common::ReviewedOriginalFunction member;
        member.key = text(row["key"]); member.target = text(row["target"]); member.imageId = text(row["image_id"]);
        member.start = number(row["start"], ADDRESS_END - 1); member.end = number(row["end"], ADDRESS_END);
        member.rangeHash = digest(row["range_sha256"]);
        auto found = targets.find(member.target);
        require(found != targets.end(), "catalog member target missing");
        auto imageIndex = catalog.targets[found->second].image;
        auto& image = catalog.images[imageIndex];
        require(member.imageId == image.id && member.start % 4 == 0 && member.end % 4 == 0
            && member.start < member.end && member.end - member.start <= RANGE_LIMIT
            && member.start >= image.load && member.end <= image.load + image.payloadBytes, "catalog member physical extent rejected");
        require(catalog.members.empty() || catalog.members.back().key < member.key, "catalog member order or identity rejected");
        require(starts.emplace(member.target, member.imageId, member.start).second, "catalog reviewed entry ambiguous");
        members.emplace(member.key, catalog.members.size());
        image.members.push_back(catalog.members.size());
        catalog.members.push_back(std::move(member));
    }
    auto requireMember = [&](const auto& member) {
        auto found = members.find(member.key);
        require(found != members.end() && sameMember(catalog.members[found->second], member), "catalog reviewed scope identity differs");
    };
    requireMember(request.scope->root);
    for (const auto& member : request.scope->callees) requireMember(member);
    return catalog;
}

struct BindingAlternative {
    size_t target;
    uint64_t offset;
    std::optional<uint32_t> word;
    std::optional<size_t> member;
};

struct BindingCall {
    uint64_t pc;
    uint32_t word;
    unsigned link, source;
    std::optional<uint32_t> address;
    std::vector<BindingAlternative> alternatives;
};

struct BindingScan {
    uint64_t words;
    std::vector<BindingCall> calls;
    std::string remaining;
    void refuse(const char *reason) {
        if (remaining.empty()) remaining = reason;
        calls.clear();
    }
};

uint32_t fileWord(const char *bytes)
{
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) value |= uint32_t(static_cast<unsigned char>(bytes[i])) << (i * 8);
    return value;
}

BindingScan recoverBindingAlternatives(const BindingCatalog& catalog, const Request& request,
    const std::string& workspace, const std::string& payload)
{
    BindingScan scan{(request.end - request.start) / 4, {}, {}};
    for (uint64_t pc = request.start; pc < request.end; pc += 4) {
        if ((pc - request.start) % 512 == 0) checkCutoff(request.cutoff);
        auto word = fileWord(payload.data() + size_t(pc - request.load));
        bool direct = word >> 26 == 3;
        if (!direct && (word & 0xfc1f07ff) != 9) continue;
        if (!scan.remaining.empty()) continue;
        if (scan.calls.size() == BINDING_CALL_LIMIT) { scan.refuse("binding-call-count-bound"); continue; }
        BindingCall call{pc, word, direct ? 31u : (word >> 11) & 31u, (word >> 21) & 31u, {}, {}};
        if (direct) call.address = (uint32_t(pc + 4) & 0xf0000000u) | ((word & 0x03ffffffu) << 2);
        scan.calls.push_back(std::move(call));
    }
    size_t alternativeCount = 0;
    bool rootFound = false;
    for (size_t index = 0; index < catalog.images.size(); ++index) {
        checkCutoff(request.cutoff);
        const auto& image = catalog.images[index];
        auto digits = std::to_string(index);
        auto path = workspace + "/input/images/" + std::string(3 - digits.size(), '0') + digits + ".image";
        auto bytes = readFile(path.c_str(), PAYLOAD_LIMIT, request.cutoff);
        require(bytes.size() == image.fileBytes && hash(bytes) == image.fileHash, "catalog original file identity differs");
        const char *mapped = bytes.data() + size_t(image.payloadOffset);
        require(hash(mapped, size_t(image.payloadBytes)) == image.payloadHash, "catalog payload identity differs");
        if (image.id == request.scope->root.imageId) {
            require(image.fileHash == request.fileHash && image.fileBytes == request.fileBytes
                && image.payloadOffset == request.payloadOffset && image.payloadBytes == request.payloadBytes
                && image.payloadHash == request.payloadHash && image.load == request.load, "catalog root mapping differs");
            require(payload.size() == image.payloadBytes
                && std::equal(payload.begin(), payload.end(), mapped), "catalog root original bytes differ");
            rootFound = true;
        }
        for (auto memberIndex : image.members) {
            checkCutoff(request.cutoff);
            const auto& member = catalog.members[memberIndex];
            require(hash(mapped + size_t(member.start - image.load), size_t(member.end - member.start))
                == member.rangeHash, "catalog reviewed original range hash differs");
        }
        if (!scan.remaining.empty()) continue;
        for (size_t targetIndex = 0; targetIndex < catalog.targets.size(); ++targetIndex) {
            const auto& target = catalog.targets[targetIndex];
            if (target.image != index) continue;
            bool overflow = false;
            for (auto& call : scan.calls) {
                checkCutoff(request.cutoff);
                if (!call.address || *call.address < image.load || *call.address - image.load >= image.payloadBytes) continue;
                if (alternativeCount == BINDING_ALTERNATIVE_LIMIT) { overflow = true; break; }
                auto offset = uint64_t(*call.address) - image.load;
                BindingAlternative alternative{targetIndex, offset, {}, {}};
                if (image.payloadBytes - offset >= 4) alternative.word = fileWord(mapped + size_t(offset));
                for (auto memberIndex : image.members) {
                    const auto& member = catalog.members[memberIndex];
                    if (member.target == target.target && member.start == *call.address) alternative.member = memberIndex;
                }
                call.alternatives.push_back(std::move(alternative));
                ++alternativeCount;
            }
            if (overflow) scan.refuse("binding-alternative-count-bound");
            if (!scan.remaining.empty()) break;
        }
    }
    require(rootFound, "catalog root image missing");
    for (auto& call : scan.calls) std::sort(call.alternatives.begin(), call.alternatives.end(), [&](const auto& a, const auto& b) {
        const auto& at = catalog.targets[a.target]; const auto& bt = catalog.targets[b.target];
        return std::tie(at.target, catalog.images[at.image].id) < std::tie(bt.target, catalog.images[bt.image].id);
    });
    checkCutoff(request.cutoff);
    return scan;
}

void bindingFact(Writer& writer, const char *key, const char *reason)
{
    writer.Key(key); writer.StartObject(); writer.Key("kind"); writer.String(reason ? "partial" : "complete");
    writer.Key("remaining"); writer.StartArray(); if (reason) writer.String(reason); writer.EndArray(); writer.EndObject();
}

void bindingMember(Writer& writer, const common::ReviewedOriginalFunction& member)
{
    writer.StartObject(); writer.Key("key"); string(writer, member.key); writer.Key("target"); string(writer, member.target);
    writer.Key("image_id"); string(writer, member.imageId); writer.Key("start"); writer.Uint64(member.start);
    writer.Key("end"); writer.Uint64(member.end); writer.Key("range_sha256"); string(writer, member.rangeHash); writer.EndObject();
}

std::string serializeBindings(const BindingCatalog& catalog, const BindingScan& scan, const Request& request)
{
    rapidjson::StringBuffer buffer;
    Writer writer(buffer);
    writer.StartObject(); writer.Key("schema"); writer.String("retdec118.original-bindings/v1");
    writer.Key("request_sha256"); string(writer, request.scope->requestHash);
    writer.Key("problem_sha256"); string(writer, request.scope->problemHash);
    writer.Key("image_catalog_sha256"); string(writer, request.catalogHash);
    writer.Key("root"); bindingMember(writer, request.scope->root);
    writer.Key("scan"); writer.StartObject(); writer.Key("kind"); writer.String(scan.remaining.empty() ? "complete" : "partial");
    if (!scan.remaining.empty()) {
        writer.Key("remaining"); writer.StartArray(); string(writer, scan.remaining); writer.EndArray();
    } else {
        writer.Key("words"); writer.Uint64(scan.words); writer.Key("calls"); writer.StartArray();
        for (const auto& call : scan.calls) {
            checkCutoff(request.cutoff);
            writer.StartObject(); writer.Key("pc"); writer.Uint64(call.pc); writer.Key("word"); writer.Uint(call.word);
            writer.Key("link_register"); writer.Uint(call.link); writer.Key("target"); writer.StartObject();
            writer.Key("kind"); writer.String(call.address ? "direct" : "register");
            if (call.address) { writer.Key("address"); writer.Uint(*call.address); }
            else { writer.Key("register"); writer.Uint(call.source); bindingFact(writer, "value", "register-target-value-unresolved"); }
            writer.EndObject(); bindingFact(writer, "reachability", "original-call-execution-unresolved");
            writer.Key("alternatives"); writer.StartArray();
            for (const auto& alternative : call.alternatives) {
                checkCutoff(request.cutoff);
                const auto& target = catalog.targets[alternative.target]; const auto& image = catalog.images[target.image];
                writer.StartObject(); writer.Key("target"); string(writer, target.target); writer.Key("image_id"); string(writer, image.id);
                writer.Key("payload_sha256"); string(writer, image.payloadHash); writer.Key("address"); writer.Uint(*call.address);
                writer.Key("payload_offset"); writer.Uint64(alternative.offset); bindingFact(writer, "address_coverage", nullptr);
                if (alternative.word) {
                    writer.Key("entry_word"); writer.StartObject(); writer.Key("kind"); writer.String("four-file-bytes");
                    writer.Key("payload_offset"); writer.Uint64(alternative.offset); writer.Key("word"); writer.Uint(*alternative.word); writer.EndObject();
                } else bindingFact(writer, "entry_word", "destination-has-fewer-than-four-file-bytes");
                writer.Key("reviewed_entry");
                const common::ReviewedOriginalFunction *member = alternative.member ? &catalog.members[*alternative.member] : nullptr;
                if (member) bindingMember(writer, *member); else writer.Null();
                bool inScope = member && (sameMember(*member, request.scope->root)
                    || std::any_of(request.scope->callees.begin(), request.scope->callees.end(), [&](const auto& peer) { return sameMember(*member, peer); }));
                writer.Key("analysis_context"); writer.StartObject(); writer.Key("kind"); writer.String(inScope ? "same-image-reviewed-scope" : "not-analyzed");
                if (inScope) { writer.Key("member"); string(writer, member->key); }
                writer.EndObject(); bindingFact(writer, "residency", "resident-image-context-unresolved");
                bindingFact(writer, "callee_contract", "callee-contract-not-recovered-by-static-inventory");
                bindingFact(writer, "declaration", "callee-declaration-not-recovered-by-static-inventory"); writer.EndObject();
            }
            writer.EndArray(); bindingFact(writer, "active_target", "execution-target-unresolved");
            bindingFact(writer, "scoped_observation", "validated-runtime-observation-unavailable");
            bindingFact(writer, "universal_binding", "universal-call-binding-unresolved"); writer.EndObject();
        }
        writer.EndArray();
    }
    writer.EndObject(); writer.EndObject();
    return std::string(buffer.GetString(), buffer.GetSize()) + "\n";
}

std::string originalBindings(const Request& request, const std::string& workspace, const std::string& payload)
{
    {
        auto original = readFile((workspace + "/input/original.image").c_str(), PAYLOAD_LIMIT, request.cutoff);
        require(original.size() == request.fileBytes && hash(original) == request.fileHash, "root original file identity differs");
        require(payload.size() == request.payloadBytes
            && std::equal(payload.begin(), payload.end(), original.data() + size_t(request.payloadOffset)), "root original payload bytes differ");
    }
    auto catalog = readBindingCatalog(request, workspace);
    auto scan = recoverBindingAlternatives(catalog, request, workspace, payload);
    auto bytes = serializeBindings(catalog, scan, request);
    if (bytes.size() > BINDINGS_LIMIT) {
        scan.refuse("binding-artifact-byte-bound");
        bytes = serializeBindings(catalog, scan, request);
    }
    require(bytes.size() <= BINDINGS_LIMIT, "partial binding artifact exceeds bound");
    checkCutoff(request.cutoff);
    return bytes;
}

std::string status(const std::string& state, const std::string& reason, const std::string& requestBytes,
    const std::string& configBytes, const Request *request, const config::Config *config,
    bool invoked, bool backendReturned, bool backendFailed, const Artifacts& artifacts, bool bindingsProtocol, bool formsProtocol)
{
    rapidjson::StringBuffer buffer;
    Writer writer(buffer);
    writer.StartObject();
    writer.Key("schema"); writer.String(formsProtocol ? "retdec118.native-status/v4" : bindingsProtocol ? "retdec118.native-status/v3" : "retdec118.native-status/v2");
    if (formsProtocol) {
        writer.Key("source_form");
        if (request && request->sourceForm) writer.String(common::originalSourceFormName(*request->sourceForm));
        else writer.Null();
    }
    writer.Key("status"); string(writer, state);
    writer.Key("reason"); string(writer, reason.substr(0, 1024));
    writer.Key("request_bytes_hex"); string(writer, hexBytes(requestBytes));
    writer.Key("request_byte_count"); writer.Uint64(requestBytes.size());
    writer.Key("request_sha256"); string(writer, hash(requestBytes));
    writer.Key("configuration_bytes_hex"); string(writer, hexBytes(configBytes));
    writer.Key("configuration_byte_count"); writer.Uint64(configBytes.size());
    writer.Key("configuration_sha256"); string(writer, hash(configBytes));
    writer.Key("release_configuration_sha256"); writer.String(CONFIG_SHA);
    writer.Key("tokens_complete"); writer.Bool(artifacts.tokens.complete);
    writer.Key("tokens_bytes"); if (artifacts.tokens.complete) writer.Uint64(artifacts.tokens.bytes.size()); else writer.Null();
    writer.Key("tokens_sha256"); if (artifacts.tokens.complete) string(writer, hash(artifacts.tokens.bytes)); else writer.Null();
    writer.Key("inferred_configuration_complete"); writer.Bool(artifacts.inferred.complete);
    writer.Key("inferred_configuration_bytes"); if (artifacts.inferred.complete) writer.Uint64(artifacts.inferred.bytes.size()); else writer.Null();
    writer.Key("inferred_configuration_sha256"); if (artifacts.inferred.complete) string(writer, hash(artifacts.inferred.bytes)); else writer.Null();
    if (bindingsProtocol) {
        writer.Key("bindings_attempted"); writer.Bool(artifacts.bindings.attempted);
        writer.Key("bindings_complete"); writer.Bool(artifacts.bindings.complete);
        writer.Key("bindings_bytes"); if (artifacts.bindings.complete) writer.Uint64(artifacts.bindings.bytes.size()); else writer.Null();
        writer.Key("bindings_sha256"); if (artifacts.bindings.complete) string(writer, hash(artifacts.bindings.bytes)); else writer.Null();
    }
    writer.Key("partial_retention_attempted"); writer.Bool(artifacts.partialRetention);
    writer.Key("operation"); if (request) string(writer, request->operation); else writer.Null();
    writer.Key("cutoff"); if (request) writer.Double(request->cutoff); else writer.Null();
    writer.Key("requested_range");
    if (request && request->operation == "generate") range(writer, request->start, request->end); else writer.Null();
    writer.Key("invoked_range");
    if (invoked && request) range(writer, request->invokedStart, request->invokedEnd); else writer.Null();
    writer.Key("range_convention"); writer.String("requested/invoked/selected ranges are half-open; function ranges are backend observations");
    writer.Key("retdec_invoked"); writer.Bool(invoked);
    writer.Key("retdec_returned"); writer.Bool(backendReturned);
    writer.Key("retdec_failed"); if (backendReturned) writer.Bool(backendFailed); else writer.Null();
    writer.Key("backend_ranges"); writer.StartArray();
    if (invoked && config) for (const auto& function : config->functions) {
        writer.StartObject(); writer.Key("symbol"); string(writer, function.getName());
        writer.Key("start"); if (function.getStart().isDefined()) writer.Uint64(function.getStart().getValue()); else writer.Null();
        writer.Key("end"); if (function.getEnd().isDefined()) writer.Uint64(function.getEnd().getValue()); else writer.Null();
        writer.EndObject();
    }
    writer.EndArray();
    writer.Key("backend_selected_ranges"); writer.StartArray();
    if (invoked && config) for (const auto& selected : config->parameters.selectedRanges) {
        writer.StartObject();
        writer.Key("start"); if (selected.getStart().isDefined()) writer.Uint64(selected.getStart().getValue()); else writer.Null();
        writer.Key("end"); if (selected.getEnd().isDefined()) writer.Uint64(selected.getEnd().getValue()); else writer.Null();
        writer.EndObject();
    }
    writer.EndArray();
    writer.Key("initial_input_invariants"); writer.StartObject();
    writer.Key("checked"); writer.Bool(config != nullptr);
    for (auto key : {"imported_functions", "imported_globals", "imported_types", "static_signatures", "user_static_signatures", "library_types", "crypto_patterns", "abi_assets", "ordinal_assets"}) {
        writer.Key(key); if (config) writer.Uint(0); else writer.Null();
    }
    writer.Key("cache_used"); writer.Bool(false); writer.Key("rizin_database_used"); writer.Bool(false);
    writer.EndObject(); writer.EndObject();
    return std::string(buffer.GetString(), buffer.GetSize()) + "\n";
}

}

RzCmdStatus DataAnalysisConsole::recoverOriginalRange(RzCore *core, int argc, const char **argv)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    std::string workspace, requestBytes, configBytes, reason, state = "refused";
    Request request;
    config::Config config;
    bool requestReady = false, configReady = false, invoked = false, returned = false, failed = false, bindingsProtocol = false, formsProtocol = false;
    Artifacts artifacts;
    bool outputRootReady = false;
    try {
        require(argc == 1 || argc == 2, "pdzar accepts an optional absolute workspace");
        if (argc == 2) {
            require(argv && argv[1] && argv[1][0] == '/', "workspace must be absolute");
            workspace = argv[1];
            while (!workspace.empty() && workspace.back() == '/') workspace.pop_back();
        }
        outputRootReady = true;
        requestBytes = readFile((workspace + "/input/request.json").c_str(), REQUEST_LIMIT);
        auto doc = parse(requestBytes);
        formsProtocol = doc.IsObject() && doc.HasMember("schema") && doc["schema"].IsString()
            && (std::string(doc["schema"].GetString(), doc["schema"].GetStringLength()) == "retdec118.native-request/v4"
                || ((std::string(doc["schema"].GetString(), doc["schema"].GetStringLength()) == "retdec118.native-request/v5"
                    || std::string(doc["schema"].GetString(), doc["schema"].GetStringLength()) == "retdec118.native-request/v6") && doc.HasMember("source_form")));
        bindingsProtocol = formsProtocol || (doc.IsObject() && doc.HasMember("schema") && doc["schema"].IsString()
            && (std::string(doc["schema"].GetString(), doc["schema"].GetStringLength()) == "retdec118.native-request/v3"
                || std::string(doc["schema"].GetString(), doc["schema"].GetStringLength()) == "retdec118.native-request/v5"
                || std::string(doc["schema"].GetString(), doc["schema"].GetStringLength()) == "retdec118.native-request/v6"));
        request = readRequest(doc, workspace); requestReady = true;
        auto ambient = psxOverlaySnapshot(core);
        require(request.overlays || !ambient || ambient->mounts().empty(), "active overlays require an explicit v5 request");
        configBytes = readFile((workspace + "/native/fixed-config.json").c_str(), CONFIG_LIMIT);
        auto configuration = parse(configBytes);
        require(hash(configBytes) == CONFIG_SHA, "configuration bytes differ from release");
        config = cleanConfig(configuration); configReady = true;
        if (request.sourceForm) config.parameters.setOriginalSourceForm(*request.sourceForm);
        if (request.operation == "self-check") state = "self-check-complete";
        else {
            auto payload = readFile((workspace + "/input/image.raw").c_str(), PAYLOAD_LIMIT);
            require(payload.size() == request.payloadBytes && hash(payload) == request.payloadHash, "payload identity differs");
            auto slice = payload.substr(size_t(request.start - request.load), size_t(request.end - request.start));
            require(hash(slice) == request.rangeHash, "original range hash differs");
            if (request.scope) {
                request.scope->requestHash = hash(requestBytes);
                for (const auto& callee : request.scope->callees)
                    require(hash(payload.substr(size_t(callee.start - request.load), size_t(callee.end - callee.start)))
                        == callee.rangeHash, "callee original range hash differs");
                config.parameters.setOriginalCallScope(*request.scope);
            }
            if (request.overlays) {
                checkCutoff(request.cutoff);
                readBindingCatalog(request, workspace);
                auto images = loader::readPsxImageMetadata(workspace + "/input/image-catalog.json", request.catalogHash);
                std::vector<loader::PsxOverlayOperation> mounts;
                for (const auto& id : request.overlayMounts) {
                    auto found = std::find_if(images.begin(), images.end(), [&](const auto& image) { return image.id == id; });
                    require(found != images.end(), "declared overlay image missing from catalog");
                    mounts.push_back({loader::PsxOverlayOperation::Kind::Mount, id, *found});
                }
                loader::PsxOverlayManager manager;
                auto context = manager.apply(mounts);
                checkCutoff(request.cutoff);
                if (ambient && !ambient->mounts().empty()) require(ambient->identity() == context->identity(), "active overlay context differs from request");
                auto root = context->resolve(request.start, request.end - request.start);
                require(root && root->image->id == request.scope->root.imageId && root->image->payloadHash == request.payloadHash
                    && hash(reinterpret_cast<const char*>(root->bytes), root->size) == request.rangeHash, "active overlay root ownership differs");
                if (request.entryObservation) {
                    const auto& observation = *request.entryObservation;
                    auto source = context->resolve(observation.pc, 4);
                    require(source && source->image->id == observation.imageId && source->image->fileHash == observation.imageHash,
                        "observed entry original image ownership differs");
                    char address[9]; snprintf(address, sizeof(address), "%08x", observation.pc);
                    require(observation.function == source->image->target + "@" + address, "observed entry function identity differs");
                    config.parameters.setOriginalEntryObservation(observation);
                }
                config.parameters.setPsxMemoryContext(std::move(context));
            }
            config.parameters.setInputFile((workspace + "/input/image.raw").c_str());
            config.parameters.setSectionVMA(common::Address(request.load));
            config.parameters.setEntryPoint(common::Address(request.start));
            config.parameters.selectedRanges.insert(common::AddressRange(request.start, request.end));
            require(config.parameters.selectedRanges.size() == 1, "invocation range is not unique");
            const auto& selected = *config.parameters.selectedRanges.begin();
            require(selected.getStart().getValue() == request.start && selected.getEnd().getValue() == request.end, "invocation range differs");
            request.invokedStart = selected.getStart().getValue();
            request.invokedEnd = selected.getEnd().getValue();
            if (bindingsProtocol) {
                artifacts.bindings.bytes = originalBindings(request, workspace, payload);
                retain((workspace + "/work/bindings.json").c_str(), artifacts.bindings, BINDINGS_LIMIT);
            }
            checkCutoff(request.cutoff);
            invoked = true;
            failed = retdec::decompile(config, &artifacts.tokens.bytes);
            returned = true;
            artifacts.inferredComputed = true;
            artifacts.inferred.bytes = compactInferredConfiguration(config.generateJsonString());
            retain((workspace + "/work/tokens.json").c_str(), artifacts.tokens, TOKENS_LIMIT);
            retain((workspace + "/work/inferred-config.json").c_str(), artifacts.inferred, INFERRED_LIMIT);
            require(!failed, "RetDec reported failure");
            require(!artifacts.tokens.bytes.empty(), "RetDec emitted no token document");
            if (request.sourceForm) {
                auto tokens = parse(artifacts.tokens.bytes);
                fields(tokens, {"tokens", "language"});
                require(tokens["tokens"].IsArray() && !tokens["tokens"].Empty()
                    && text(tokens["language"]) == "C", "RetDec source-form token document incomplete");
                require(artifacts.tokens.complete && artifacts.inferred.complete && artifacts.bindings.complete,
                    "source-form artifact retention incomplete");
                require(config.parameters.getOriginalSourceForm() == request.sourceForm,
                    "source-form invocation choice changed");
            }
            checkCutoff(request.cutoff);
            state = "generation-complete";
        }
    } catch (const std::exception& error) {
        reason = error.what();
        state = invoked ? "generation-failed" : "refused";
    }
    if (invoked && state != "generation-complete") {
        artifacts.partialRetention = true;
        try {
            if (!artifacts.inferredComputed) {
                artifacts.inferredComputed = true;
                artifacts.inferred.bytes = compactInferredConfiguration(config.generateJsonString());
            }
        } catch (const std::exception& error) {
            reason += std::string("; partial configuration: ") + error.what();
        }
        try {
            retain((workspace + "/work/tokens.json").c_str(), artifacts.tokens, TOKENS_LIMIT);
        } catch (const std::exception& error) {
            reason += std::string("; partial tokens: ") + error.what();
        }
        try {
            retain((workspace + "/work/inferred-config.json").c_str(), artifacts.inferred, INFERRED_LIMIT);
        } catch (const std::exception& error) {
            reason += std::string("; partial configuration retention: ") + error.what();
        }
    }
    if (!outputRootReady) return RZ_CMD_STATUS_ERROR;
    try {
        writeFile((workspace + "/work/status.json").c_str(), status(state, reason, requestBytes, configBytes,
            requestReady ? &request : nullptr, configReady ? &config : nullptr, invoked, returned, failed, artifacts, bindingsProtocol, formsProtocol), STATUS_LIMIT);
    } catch (const std::exception&) {
        return RZ_CMD_STATUS_ERROR;
    }
    return state == "self-check-complete" || state == "generation-complete" ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

}
}
