#include "rz-plugin/console/data_analysis.h"
#include "rz-plugin/psx_overlays.h"
#include "rz-plugin/rzretdec.h"

#include <map>
#include <set>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

namespace retdec { namespace rzplugin {
namespace {

std::map<const RzCore*, loader::PsxOverlayManager> overlays;

void print(const common::PsxMemoryContext& context) {
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	context.serialize(writer);
	rz_cons_printf("%s\n", buffer.GetString());
}

}

std::shared_ptr<const common::PsxMemoryContext> psxOverlaySnapshot(const RzCore* core) {
	std::lock_guard<std::recursive_mutex> lock(mutex);
	auto found = overlays.find(core);
	return found == overlays.end() ? nullptr : found->second.snapshot();
}

void clearPsxOverlayState(RzCore* core) {
	std::lock_guard<std::recursive_mutex> lock(mutex);
	overlays.erase(core);
}

RzCmdStatus DataAnalysisConsole::showOverlays(RzCore* core, int argc, const char**) {
	std::lock_guard<std::recursive_mutex> lock(mutex);
	if (argc != 1) return RZ_CMD_STATUS_WRONG_ARGS;
	print(*overlays[core].snapshot());
	return RZ_CMD_STATUS_OK;
}

RzCmdStatus DataAnalysisConsole::mountOverlays(RzCore* core, int argc, const char** argv) {
	std::lock_guard<std::recursive_mutex> lock(mutex);
	try {
		if (argc < 3 || argc > 130) return RZ_CMD_STATUS_WRONG_ARGS;
		auto images = loader::readPsxImageMetadata(argv[1]);
		std::vector<loader::PsxOverlayOperation> operations;
		std::set<std::string> selected;
		for (int i = 2; i < argc; ++i) {
			if (!selected.insert(argv[i]).second) throw std::runtime_error("psx-overlay-duplicate-command-id");
			auto found = std::find_if(images.begin(), images.end(), [&](const auto& image) { return image.id == argv[i]; });
			if (found == images.end()) throw std::runtime_error("psx-overlay-image-id-not-in-metadata");
			operations.push_back({loader::PsxOverlayOperation::Kind::Mount, found->id, *found});
		}
		print(*overlays[core].apply(operations));
		return RZ_CMD_STATUS_OK;
	} catch (const std::exception& error) {
		rz_cons_printf("%s\n", error.what());
		return RZ_CMD_STATUS_ERROR;
	}
}

RzCmdStatus DataAnalysisConsole::dismountOverlays(RzCore* core, int argc, const char** argv) {
	std::lock_guard<std::recursive_mutex> lock(mutex);
	try {
		if (argc < 2 || argc > 129) return RZ_CMD_STATUS_WRONG_ARGS;
		std::vector<loader::PsxOverlayOperation> operations;
		for (int i = 1; i < argc; ++i)
			operations.push_back({loader::PsxOverlayOperation::Kind::Dismount, argv[i], {}});
		print(*overlays[core].apply(operations));
		return RZ_CMD_STATUS_OK;
	} catch (const std::exception& error) {
		rz_cons_printf("%s\n", error.what());
		return RZ_CMD_STATUS_ERROR;
	}
}

} }
