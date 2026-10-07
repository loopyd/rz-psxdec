#include <array>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <retdec/config/config.h>
#include <retdec/retdec/retdec.h>

#include "rz-plugin/console/data_analysis.h"
#include "rz-plugin/rzretdec.h"

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

std::string hash(const std::string& bytes)
{
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest;
    SHA256(reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size(), digest.data());
    return hexBytes(std::string(reinterpret_cast<const char *>(digest.data()), digest.size()));
}

std::string readFile(const char *path, size_t limit)
{
    Descriptor file{::open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
    require(file.value >= 0, "fixed input cannot be opened");
    struct stat metadata;
    require(fstat(file.value, &metadata) == 0 && S_ISREG(metadata.st_mode), "fixed input is not regular");
    require(metadata.st_size >= 0 && uint64_t(metadata.st_size) <= limit, "fixed input exceeds bound");
    std::string bytes(size_t(metadata.st_size), '\0');
    size_t position = 0;
    while (position < bytes.size()) {
        auto count = ::read(file.value, &bytes[position], bytes.size() - position);
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "fixed input read is incomplete");
        position += size_t(count);
    }
    char extra;
    require(::read(file.value, &extra, 1) == 0, "fixed input grew during read");
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
    Artifact tokens, inferred;
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
    std::string payloadHash, rangeHash;
    std::optional<common::OriginalCallScope> scope;
};

Request readRequest(const rapidjson::Document& doc)
{
    require(doc.IsObject() && doc.HasMember("schema"), "request schema missing");
    auto schema = text(doc["schema"]);
    bool graph = schema == "retdec118.native-request/v2";
    if (graph) fields(doc, {"schema", "operation", "request_id", "config_sha256", "cutoff", "member", "image", "problem_sha256", "callees"});
    else fields(doc, {"schema", "operation", "request_id", "config_sha256", "cutoff", "member", "image"});
    require(graph || schema == "retdec118.native-request/v1", "request schema rejected");
    digest(doc["request_id"]);
    require(digest(doc["config_sha256"]) == CONFIG_SHA, "configuration identity is not this release");
    require(doc["cutoff"].IsNumber() && !doc["cutoff"].IsBool(), "cutoff must be numeric");
    Request request;
    request.operation = text(doc["operation"]);
    request.cutoff = doc["cutoff"].GetDouble();
    checkCutoff(request.cutoff);
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
    digest(image["file_sha256"]);
    auto fileBytes = number(image["file_bytes"], (uint64_t(1) << 40));
    auto payloadOffset = number(image["payload_offset"], fileBytes);
    request.payloadBytes = number(image["payload_bytes"], PAYLOAD_LIMIT);
    require(request.payloadBytes > 0 && request.payloadBytes <= fileBytes - payloadOffset, "payload file extent invalid");
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

void string(Writer& writer, const std::string& value)
{
    writer.String(value.data(), value.size());
}

void range(Writer& writer, uint64_t start, uint64_t end)
{
    writer.StartObject(); writer.Key("start"); writer.Uint64(start); writer.Key("end"); writer.Uint64(end); writer.EndObject();
}

std::string status(const std::string& state, const std::string& reason, const std::string& requestBytes,
    const std::string& configBytes, const Request *request, const config::Config *config,
    bool invoked, bool backendReturned, bool backendFailed, const Artifacts& artifacts)
{
    rapidjson::StringBuffer buffer;
    Writer writer(buffer);
    writer.StartObject();
    writer.Key("schema"); writer.String("retdec118.native-status/v2");
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

RzCmdStatus DataAnalysisConsole::recoverOriginalRange(RzCore *, int argc, const char **argv)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    std::string workspace, requestBytes, configBytes, reason, state = "refused";
    Request request;
    config::Config config;
    bool requestReady = false, configReady = false, invoked = false, returned = false, failed = false;
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
        request = readRequest(doc); requestReady = true;
        configBytes = readFile((workspace + "/native/fixed-config.json").c_str(), CONFIG_LIMIT);
        auto configuration = parse(configBytes);
        require(hash(configBytes) == CONFIG_SHA, "configuration bytes differ from release");
        config = cleanConfig(configuration); configReady = true;
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
            config.parameters.setInputFile((workspace + "/input/image.raw").c_str());
            config.parameters.setSectionVMA(common::Address(request.load));
            config.parameters.setEntryPoint(common::Address(request.start));
            config.parameters.selectedRanges.insert(common::AddressRange(request.start, request.end));
            require(config.parameters.selectedRanges.size() == 1, "invocation range is not unique");
            const auto& selected = *config.parameters.selectedRanges.begin();
            require(selected.getStart().getValue() == request.start && selected.getEnd().getValue() == request.end, "invocation range differs");
            request.invokedStart = selected.getStart().getValue();
            request.invokedEnd = selected.getEnd().getValue();
            checkCutoff(request.cutoff);
            invoked = true;
            failed = retdec::decompile(config, &artifacts.tokens.bytes);
            returned = true;
            artifacts.inferredComputed = true;
            artifacts.inferred.bytes = config.generateJsonString();
            retain((workspace + "/work/tokens.json").c_str(), artifacts.tokens, TOKENS_LIMIT);
            retain((workspace + "/work/inferred-config.json").c_str(), artifacts.inferred, INFERRED_LIMIT);
            require(!failed, "RetDec reported failure");
            require(!artifacts.tokens.bytes.empty(), "RetDec emitted no token document");
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
                artifacts.inferred.bytes = config.generateJsonString();
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
            requestReady ? &request : nullptr, configReady ? &config : nullptr, invoked, returned, failed, artifacts), STATUS_LIMIT);
    } catch (const std::exception&) {
        return RZ_CMD_STATUS_ERROR;
    }
    return state == "self-check-complete" || state == "generation-complete" ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

}
}
